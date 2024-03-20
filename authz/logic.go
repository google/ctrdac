// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package authz includes the core implementation of the acjs application: policy evaluation.
package authz

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/golang/glog"
	"github.com/google/acjs/common"
	"github.com/google/acjs/slsa"
	"github.com/google/ctrdac/lookup"
	"github.com/dop251/goja"
	"https://github.com/mattbaird/jsonpatch"

	ctrdachttp "github.com/google/ctrdac/http"
	k8sac "k8s.io/api/admission/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type authDecision int

const (
	reject authDecision = 0
	allow  authDecision = 1
)

type compiledPolicy struct {
	name   string
	script *goja.Program
}

// CompiledPolicies is the type the authorization logic operates on.
type CompiledPolicies struct {
	config           *common.ConfigFile
	globalContext    map[string]any
	compiledPolicies []compiledPolicy
	defaultAction    authDecision
}

func consoleLog(v ...any) {
	log.Infoln(v...)
}

func convertDefaultAction(action string, def authDecision) authDecision {
	switch strings.ToLower(action) {
	case "reject":
		return reject
	case "allow":
		return allow
	default:
		return def
	}
}

func cosignVerify(ar *k8sac.AdmissionRequest, object any, publicKeyPath string) (any, error) {
	imagesRef, err := getImagesFromRequest(ar, object)
	if err != nil {
		return nil, err
	}

	// TODO(imrer): integrate this with the golang library instead, once it is released

	re := map[string]any{}

	for _, imageRef := range imagesRef {
		log.V(2).Infof("verifying cosign on image: %v", imageRef)
		stdout, err := callCosignVerify(imageRef, publicKeyPath)
		if err != nil {
			if strings.HasPrefix(err.Error(), "exit status 1") {
				// just no matching signatures, nothing "exceptional"
				return nil, nil
			}

			return nil, fmt.Errorf("invoking the cosign cli failed: %v", err)
		}
		var m []any
		if err := json.Unmarshal(stdout, &m); err != nil {
			return nil, fmt.Errorf("unable to parse Cosign response: %v", err)
		}

		re[imageRef] = m
	}

	return re, nil
}

// SlsaParams describes the arguments expected by the verifySlsa function in the context of an
// acjs policy.
type SlsaParams struct {
	BuilderID      string
	ProvenancePath string
	SourceURI      string
}

func slsaVerify(ar *k8sac.AdmissionRequest, object any, slsaParams SlsaParams) (bool, error) {
	imagesRef, err := getImagesFromRequest(ar, object)
	if err != nil {
		return false, err
	}

	log.V(2).Infof("slsaVerify, %v, params: %+v", imagesRef, slsaParams)

	for _, imageRef := range imagesRef {
		// TODO(imrer): refactor this to use the library behind
		output, err := callSlsaVerifier(imageRef, slsaParams.ProvenancePath, slsaParams.BuilderID, slsaParams.SourceURI)
		if err != nil {
			return false, fmt.Errorf("invoking the slsa-verifier cli failed: %v %v", string(output), err)
		}
	}

	return true, nil
}

func getImagesFromRequest(ar *k8sac.AdmissionRequest, object any) ([]string, error) {
	kind := lookup.Lookup(object, "kind", "")
	if kind != "Pod" {
		// it is not a k8s Pod, but may be a runc spec.
		image := lookup.Lookup(object, "container.image", "")
		if image != "" {
			return []string{image}, nil
		}

		return nil, fmt.Errorf("unable to extract image reference from object of kind: %s", kind)
	}
	var re []string
	var containers []any
	for _, path := range []string{"spec.containers", "spec.initContainers", "spec.ephemeralContainers"} {
		containers = append(containers, lookup.Lookup[[]any](object, path, nil)...)
	}
	for _, container := range containers {
		image := lookup.Lookup(container, "image", "")
		if image == "" {
			return nil, fmt.Errorf("image attribute is not present for container %v", lookup.Lookup(container, "name", ""))
		}

		re = append(re, image)
	}
	return re, nil
}

func slsaEnsureComingFromImage(imageRef string, slsaTrustedRepos []*slsa.Repo) (bool, error) {
	slsaTrustedRepoMatches := slsa.FindMatchingRepos(imageRef, slsaTrustedRepos)
	if len(slsaTrustedRepoMatches) == 0 {
		// makes no sense to fetch provenance, no idea which repo this image belongs to
		return false, nil
	}

	provenanceMeta, err := callSlsaObtainProvenance(imageRef)
	if err != nil {
		return false, err
	}
	file, err := ioutil.TempFile("/tmp", "slsa-provenance")
	if err != nil {
		return false, err
	}
	tmpProvenancePath := file.Name()
	defer os.Remove(tmpProvenancePath)
	permissions := 0644 // or whatever you need
	err = os.WriteFile(tmpProvenancePath, provenanceMeta, fs.FileMode(permissions))
	if err != nil {
		return false, err
	}

	for _, slsaTrustedRepo := range slsaTrustedRepoMatches {

		output, err := callSlsaVerifier(imageRef, tmpProvenancePath, slsaTrustedRepo.BuilderID, slsaTrustedRepo.Repo)

		if err != nil {
			// it just didn't match
			log.V(2).Infof("SLSA verification output: %s", string(output))
			continue
		}

		// match!
		return true, nil
	}

	// it didn't match any of the trusted repos
	return false, nil
}

func slsaEnsureComingFrom(ar *k8sac.AdmissionRequest, object any, trustedRepos []string) (bool, error) {
	imageRefs, err := getImagesFromRequest(ar, object)
	if err != nil {
		return false, err
	}

	log.V(2).Infof("slsaEnsureComingFrom: %v, params: %+v", imageRefs, trustedRepos)

	slsaTrustedRepos, err := callSlsaResolver(trustedRepos...)
	if err != nil {
		return false, err
	}
	for _, imageRef := range imageRefs {
		a, err := slsaEnsureComingFromImage(imageRef, slsaTrustedRepos)
		if err != nil {
			return false, err
		}
		if !a {
			return a, nil
		}
	}

	// all images matched
	return true, nil
}

// CompilePolicies processes the yaml parsed configuration file and does some preparation steps.
// Most importantly, it compiles the string policies present in the configuration file
// and turns them into a goja.Program so executing them later on will be faster
func CompilePolicies(config *common.ConfigFile) (*CompiledPolicies, error) {
	re := CompiledPolicies{}
	re.config = config
	re.defaultAction = convertDefaultAction(config.DefaultAction, reject)

	re.globalContext = make(map[string]any)
	seenAlready := map[string]bool{}
	for _, policy := range config.Policies {
		if seenAlready[policy.Name] {
			return nil, fmt.Errorf("duplicate policy name: %s", policy.Name)
		}
		seenAlready[policy.Name] = true
		var cp compiledPolicy

		cp.name = policy.Name
		code := config.Globals + "\n\nfunction policyHandler() {\n" + policy.Code + "\n}\npolicyHandler()\n"
		script, err := goja.Compile("", code, false)
		if err != nil {
			return nil, fmt.Errorf("unable to compile policy %s: %v", policy.Name, err)
		}
		cp.script = script
		re.compiledPolicies = append(re.compiledPolicies, cp)
	}
	return &re, nil
}

func jsWrapper(avm *goja.Runtime, callback func() (any, error)) any {
	cs, err := callback()
	if err != nil {
		panic(avm.ToValue(err.Error()))
	}
	return cs
}

// this will return either:
// - boolean true at successful validation
// - string message at policy violation
func forwardToAdmissionController(acURL string, ar *k8sac.AdmissionRequest) (any, error) {
	areq := k8sac.AdmissionReview{
		TypeMeta: k8smeta.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Request: ar,
	}
	ares, err := callValidatingWebhook(acURL, areq)
	if err != nil {
		return nil, err
	}
	if ares.Response.Allowed {
		return true, nil
	}

	// else it is not allowed
	return ares.Response.Result.Message, nil
}

func createPatch(orgObjBytes []byte, newObj any) ([]byte, error) {
	newObjBytes, err := json.Marshal(newObj)
	if err != nil {
		return nil, err
	}

	patches, err := jsonpatch.CreatePatch(orgObjBytes, newObjBytes)
	if err != nil {
		return nil, err
	}

	return json.Marshal(patches)
}

func (cp *CompiledPolicies) doEvaluate(rc *common.AdmissionControllerRequest, areq *k8sac.AdmissionRequest) *k8sac.AdmissionResponse {
	var re k8sac.AdmissionResponse
	re.UID = areq.UID
	re.Allowed = false

	rc.GlobalContext = cp.globalContext

	allowed := false
	reason := ""
	message := ""
	decided := false

	var patch []byte
	var object any
	err := json.Unmarshal(areq.Object.Raw, &object)
	if err == nil {
		avm := goja.New()

		avm.Set("console", map[string](func(...any)){
			"log": consoleLog,
		})
		avm.Set("atob", func(b64 string) string {
			return jsWrapper(avm, func() (any, error) {
				bytes, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					return nil, err
				}
				return string(bytes), nil
			}).(string)
		})
		avm.Set("btoa", func(in string) string {
			return base64.StdEncoding.EncodeToString([]byte(in))
		})
		avm.Set("cosignVerify", func(publicKeyPath string) any {
			return jsWrapper(avm, func() (any, error) {
				return cosignVerify(areq, object, publicKeyPath)
			})
		})
		avm.Set("slsaVerify", func(params SlsaParams) any {
			r, err := slsaVerify(areq, object, params)
			if err != nil {
				return err.Error()
			}
			return r
		})
		avm.Set("slsaEnsureComingFrom", func(repos []string) any {
			return jsWrapper(avm, func() (any, error) {
				return slsaEnsureComingFrom(areq, object, repos)
			})
		})
		avm.Set("forwardToAdmissionController", func(acUrl string) any {
			return jsWrapper(avm, func() (any, error) {
				return forwardToAdmissionController(acUrl, areq)
			})
		})

		avm.Set("ac", rc)
		avm.Set("req", areq)
		avm.Set("object", object)

		for _, p := range cp.compiledPolicies {

			value, err := avm.RunProgram(p.script)
			if err != nil {
				allowed = false
				reason = "INTERNAL_ERROR"
				message = p.name + ": unable to evaluate policy:" + err.Error()

				decided = true
				break

			} else if !goja.IsUndefined(value) {

				switch govalue := value.Export().(type) {
				case bool:
					if govalue {
						allowed = true
					} else {
						allowed = false
						reason = "VIOLATES_POLICY"
						message = p.name + ": request denied by policy"
					}
				case string:
					allowed = false
					reason = "VIOLATES_POLICY"
					message = p.name + ": " + govalue
				default:
					allowed = false
					reason = "INTERNAL_ERROR"
					message = p.name + fmt.Sprintf(": unknown return value from policy (%T: %v)", govalue, govalue)
				}

				decided = true
				break

			}

		}
	} else {
		allowed = false
		reason = "INTERNAL_ERROR"
		message = "unable to unmarshal object of the request:" + err.Error()
		decided = true
	}

	if !decided {
		// default decision
		allowed = cp.defaultAction == allow
	}

	if allowed {
		// need to compare the object
		patch, err = createPatch(areq.Object.Raw, object)

		if err != nil {
			allowed = false
			reason = "INTERNAL_ERROR"
			message = "unable to calculate the object diff:" + err.Error()
		} else if patch != nil && len(patch) != 2 { // 2 bytes patch is '[]'
			patchType := k8sac.PatchTypeJSONPatch
			re.PatchType = &patchType
			re.Patch = patch
		}
	}

	re.Allowed = allowed
	re.Result = &k8smeta.Status{
		Reason:  k8smeta.StatusReason(reason),
		Message: message,
	}

	if re.Result == nil {
		re.Result = &k8smeta.Status{}
		if !re.Allowed {
			re.Result.Reason = "VIOLATES_POLICY"
			re.Result.Message = "Default decision"
		}
	}
	if re.Allowed {
		re.Result.Status = "Success"
	} else {
		re.Result.Status = "Failure"
	}

	return &re
}

// LogEntry is the type that will be turned into a JSON string and will be emitted for each request
// to the standard output.
type LogEntry struct {
	Ts              string
	UserAuthNMethod string
	User            any
	Request         any
	Response        *k8sac.AdmissionResponse
}

// Evaluate iterates over the configured policies and evaluates the incoming admission review request.
func (cp *CompiledPolicies) Evaluate(rc *common.AdmissionControllerRequest, areq *k8sac.AdmissionRequest) *k8sac.AdmissionResponse {
	res := cp.doEvaluate(rc, areq)

	l := LogEntry{
		Ts:              rc.Timestamp,
		Request:         areq,
		Response:        res,
		UserAuthNMethod: rc.UserAuthNMethod,
		User:            rc.User,
	}

	logBytes, err := json.Marshal(l)
	if err == nil {
		fmt.Printf("%s\n", logBytes)
	}

	return res
}

var callValidatingWebhook = func(url string, ar k8sac.AdmissionReview) (*k8sac.AdmissionReview, error) {
	ar, err := ctrdachttp.Post[k8sac.AdmissionReview](url, ar, nil)
	if err != nil {
		return nil, err
	}
	return &ar, nil
}

var callCosignVerify = func(imageRef, publicKeyPath string) ([]byte, error) {
	return exec.Command("cosign", "verify", "--key", publicKeyPath, imageRef).Output()
}

var callSlsaResolver = func(trustedRepos ...string) ([]*slsa.Repo, error) {
	resolver := slsa.RepoResolver{}
	return resolver.Resolve(trustedRepos...)
}

var callSlsaObtainProvenance = func(imageRef string) ([]byte, error) {
	return slsa.ObtainProvenance(imageRef)
}

var callSlsaVerifier = func(imageRef, tmpProvenancePath, builderID, repo string) ([]byte, error) {
	// TODO(imrer): refactor this to use the library behind
	params := []string{"verify-image", imageRef, "--provenance-path", tmpProvenancePath, "--builder-id", builderID, "--source-uri", repo}
	log.V(2).Infof("executing command: slsa-verifier  %v", params)
	return exec.Command("slsa-verifier", params...).CombinedOutput()
}
