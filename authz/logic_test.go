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

package authz

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/acjs/common"
	"github.com/google/acjs/slsa"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	k8sac "k8s.io/api/admission/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFundamentals(t *testing.T) {
	config := &common.ConfigFile{
		Globals: `
		 function addNumbers(n1, n2) {
		    return n1 + n2
		 }
		`,
		Policies: []common.ConfigPolicy{
			{
				// this step does not return anything
				Name: "logging",
				Code: `
				console.log("hello!", ac.User.Username, "x", req.UID, "x", object)
				`,
			},
			{
				// this step returns a boolean false
				Name: "user restriction",
				Code: `
				if (ac.User.Username == "restricteduser")
					return false
				`,
			},
			{
				// returns a string
				Name: "access to the object",
				Code: `
				if (object.foo == "bar")
					return "you should not send "+object.foo
				`,
			},
			{
				// access to the AdmissionRequest
				Name: "admissionrequest",
				Code: `
				if (req.UID == "3")
					return "req.UID is 3"
				`,
			},
			{
				// base64 functions
				Name: "atob",
				Code: `
				if (object.atob == atob("aGVsbG8="))
					return "atob"
				`,
			},
			{
				// base64 functions
				Name: "btoa",
				Code: `
				if (object.btoa == btoa("hello"))
					return "btoa"
				`,
			},
			{
				Name: "true-terminates1",
				Code: `
				if (ac.User.Username == "trueuser")
					return true
				`,
			},
			{
				Name: "true-terminates2",
				Code: `
				if (ac.User.Username == "trueuser")
					return "should not get here"
				`,
			},
			{
				Name: "patch",
				Code: `
				if (ac.User.Username == "patchuser") {
				  object.attr = "modified"
					return true				
				}
				`,
			},
			{
				// this step relies on functions defined as globals
				Name: "global functions",
				Code: `
				if (ac.User.Username == "globalfunctions")
				   return "addNumbers(1,2)=" + addNumbers(1,2)
				`,
			},
			{
				// these two steps rely on the global context
				Name: "global context1",
				Code: `
				ac.GlobalContext[req.UID] = "value-set-in-previous-step"
				`,
			},
			{
				Name: "global context2",
				Code: `
				if (ac.User.Username == "globalcontext")
					return ac.GlobalContext[req.UID]
				`,
			},
			{
				Name: "http request path",
				Code: `
				if (ac.HTTPRequest.RequestURI + "/" + ac.User.Username == "/some/path/pathtest")
					return "i dont like this path"
				`,
			},
			{
				Name: "http request header",
				Code: `
				if (ac.User.Username == "headertest" && ac.HTTPRequest.Header.Get('X-Something-Cool') == "hello")
					return "i dont like cool headers"
				`,
			},
		},
		DefaultAction: "Allow",
	}

	cp, err := CompilePolicies(config)
	if err != nil {
		t.Fatal(err)
	}

	type testcase struct {
		user            string
		object          any
		expectedAllowed bool
		expectedMessage string
		expectedPatch   string
	}

	testcases := []testcase{
		{
			user:            "someone",
			object:          map[string]any{},
			expectedAllowed: true,
		},
		{
			user:            "restricteduser",
			object:          map[string]any{},
			expectedAllowed: false,
			expectedMessage: "user restriction: request denied by policy",
		},
		{
			user:            "someone",
			object:          map[string]any{"foo": "bar"},
			expectedAllowed: false,
			expectedMessage: "access to the object: you should not send bar",
		},
		{
			user:            "someone",
			object:          map[string]any{},
			expectedAllowed: false,
			expectedMessage: "admissionrequest: req.UID is 3",
		},
		{
			user:            "someone",
			object:          map[string]any{"atob": "hello"},
			expectedAllowed: false,
			expectedMessage: "atob: atob",
		},
		{
			user:            "someone",
			object:          map[string]any{"btoa": "aGVsbG8="},
			expectedAllowed: false,
			expectedMessage: "btoa: btoa",
		},
		{
			user:            "trueuser",
			object:          map[string]any{},
			expectedAllowed: true,
		},
		{
			user:            "patchuser",
			object:          map[string]any{"attr": "original"},
			expectedAllowed: true,
			expectedPatch:   `[{"op":"replace","path":"/attr","value":"modified"}]`,
		},
		{
			user:            "globalfunctions",
			object:          map[string]any{},
			expectedAllowed: false,
			expectedMessage: "global functions: addNumbers(1,2)=3",
		},
		{
			user:            "globalcontext",
			object:          map[string]any{},
			expectedAllowed: false,
			expectedMessage: "global context2: value-set-in-previous-step",
		},
		{
			user:            "pathtest",
			object:          map[string]any{},
			expectedAllowed: false,
			expectedMessage: "http request path: i dont like this path",
		},
		{
			user:            "headertest",
			object:          map[string]any{},
			expectedAllowed: false,
			expectedMessage: "http request header: i dont like cool headers",
		},
	}

	for i, tc := range testcases {
		objectBytes, err := json.Marshal(tc.object)
		if err != nil {
			t.Fatal(err)
		}
		rc := &common.AdmissionControllerRequest{
			User: map[string]any{"Username": tc.user},
			HTTPRequest: &http.Request{
				Method:     "POST",
				RequestURI: "/some/path",
				Header: http.Header{
					"X-Something-Cool": {"hello"},
				},
			},
		}
		areq := &k8sac.AdmissionRequest{
			UID: types.UID(strconv.Itoa(i)),
			Object: runtime.RawExtension{
				Raw: objectBytes,
			},
		}
		aresp := cp.Evaluate(rc, areq)

		if aresp.Allowed != tc.expectedAllowed {
			t.Errorf("subtest %d failed; allowed %v vs %v", i, aresp.Allowed, tc.expectedAllowed)
		}
		if aresp.Result.Message != tc.expectedMessage {
			t.Errorf("subtest %d failed; message %v vs %v", i, aresp.Result.Message, tc.expectedMessage)
		}
		if string(aresp.Patch) != tc.expectedPatch {
			t.Errorf("subtest %d failed; patch %v vs %v", i, string(aresp.Patch), tc.expectedPatch)
		}
	}
}

func TestConvertDefaultAction(t *testing.T) {
	if allow != convertDefaultAction("Allow", reject) {
		t.Errorf("convertDefaultAction(Allow) failed")
	}
	if reject != convertDefaultAction("Reject", allow) {
		t.Errorf("convertDefaultAction(Reject) failed")
	}
	if allow != convertDefaultAction("foobar", allow) {
		t.Errorf("convertDefaultAction(foobar) failed")
	}
}

func TestImageExtractionK8s(t *testing.T) {
	k8sobject := map[string]any{"kind": "Pod", "spec": map[string]any{
		"containers":          []any{map[string]any{"image": "image1"}},
		"initContainers":      []any{map[string]any{"image": "image2"}},
		"ephemeralContainers": []any{map[string]any{"image": "image3"}},
	}}
	is, err := getImagesFromRequest(nil, k8sobject)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(is, []string{"image1", "image2", "image3"}) {
		t.Errorf("getImagesFromRequest invalid response for k8s input: %+v", is)
	}
}

func TestImageExtractionRunc(t *testing.T) {
	runcobject := map[string]any{"container": map[string]any{"image": "imagename"}}
	is, err := getImagesFromRequest(nil, runcobject)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(is, []string{"imagename"}) {
		t.Errorf("getImagesFromRequest invalid response for runc input: %+v", is)
	}
}

func TestFowrardToAdmissionController(t *testing.T) {
	origCallValidatingWebhook := callValidatingWebhook
	defer func() { callValidatingWebhook = origCallValidatingWebhook }()
	callValidatingWebhook = func(url string, ar k8sac.AdmissionReview) (*k8sac.AdmissionReview, error) {
		if url != "https://some.tld/ac" {
			return nil, fmt.Errorf("unexpected ac url: %v", url)
		}
		if ar.Request.UID != "uid" {
			return nil, fmt.Errorf("unexpected ac payload: %v", url)
		}
		aresp := &k8sac.AdmissionReview{
			Response: &k8sac.AdmissionResponse{
				Allowed: false,
				Result: &k8smeta.Status{
					Message: "external rejection",
				},
			},
		}

		return aresp, nil
	}
	config := &common.ConfigFile{
		Policies: []common.ConfigPolicy{
			{
				Name: "forward",
				Code: `
				return forwardToAdmissionController("https://some.tld/ac")
				`,
			},
		},
		DefaultAction: "Allow",
	}

	cp, err := CompilePolicies(config)
	if err != nil {
		t.Fatal(err)
	}

	rc := &common.AdmissionControllerRequest{
		User: map[string]any{"Username": "whatever"},
	}
	areq := &k8sac.AdmissionRequest{
		UID: types.UID("uid"),
		Object: runtime.RawExtension{
			Raw: []byte(`{}`),
		},
	}
	aresp := cp.Evaluate(rc, areq)

	if aresp.Allowed != false {
		t.Errorf("should have been rejected")
	}
	if aresp.Result.Message != "forward: external rejection" {
		t.Errorf("unexpected rejection message: %v", aresp.Result.Message)
	}
}

func TestCosignVerify(t *testing.T) {
	origCallCosignVerify := callCosignVerify
	defer func() { callCosignVerify = origCallCosignVerify }()
	callCosignVerify = func(imageRef, publicKeyPath string) ([]byte, error) {

		if imageRef != "some/image" {
			return nil, fmt.Errorf("unexpected imageRef: %v", imageRef)
		}
		if publicKeyPath != "/path/to/key.pub" {
			return nil, fmt.Errorf("unexpected publicKeyPath: %v", publicKeyPath)
		}

		return []byte(`[{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":"cosign container image signature"},"Optional":null}]`), nil
	}
	config := &common.ConfigFile{
		Policies: []common.ConfigPolicy{
			{
				Name: "cosign",
				Code: `
				var x = cosignVerify("/path/to/key.pub")
				return x["some/image"][0].Critical.Type
				`,
			},
		},
		DefaultAction: "Allow",
	}

	cp, err := CompilePolicies(config)
	if err != nil {
		t.Fatal(err)
	}

	rc := &common.AdmissionControllerRequest{
		User: map[string]any{"Username": "whatever"},
	}
	areq := &k8sac.AdmissionRequest{
		UID: types.UID("uid"),
		Object: runtime.RawExtension{
			Raw: []byte(`{"container":{"image":"some/image"}}`),
		},
	}
	aresp := cp.Evaluate(rc, areq)

	if aresp.Allowed != false {
		t.Errorf("should have been rejected")
	}
	if aresp.Result.Message != "cosign: cosign container image signature" {
		t.Errorf("unexpected rejection message: %v", aresp.Result.Message)
	}
}

func TestSlsaEnsureComingFrom(t *testing.T) {
	origCallSlsaResolver := callSlsaResolver
	defer func() { callSlsaResolver = origCallSlsaResolver }()
	callSlsaResolver = func(trustedRepos ...string) ([]*slsa.Repo, error) {
		if len(trustedRepos) != 1 || trustedRepos[0] != "github.com/irsl/gcb-tests" {
			return nil, fmt.Errorf("unexpected trustedRepos: %v", trustedRepos)
		}
		return []*slsa.Repo{{
			BuilderID: "cloud-build",
			Images:    []string{"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image"},
			Repo:      trustedRepos[0],
		}}, nil
	}
	origCallSlsaObtainProvenance := callSlsaObtainProvenance
	defer func() { callSlsaObtainProvenance = origCallSlsaObtainProvenance }()
	callSlsaObtainProvenance = func(imageRef string) ([]byte, error) {
		if imageRef != "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529" {
			return nil, fmt.Errorf("unexpected imageRef for callSlsaObtainProvenance: %v", imageRef)
		}
		return []byte(`some-provenance-data`), nil
	}

	origCallSlsaVerifier := callSlsaVerifier
	defer func() { callSlsaVerifier = origCallSlsaVerifier }()
	callSlsaVerifier = func(imageRef, tmpProvenancePath, builderID, repo string) ([]byte, error) {
		if imageRef != "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529" {
			return nil, fmt.Errorf("unexpected imageRef for callSlsaVerifier: %v", imageRef)
		}
		if builderID != "cloud-build" {
			return nil, fmt.Errorf("unexpected builderID for callSlsaVerifier: %v", builderID)
		}
		if repo != "github.com/irsl/gcb-tests" {
			return nil, fmt.Errorf("unexpected repo for callSlsaVerifier: %v", repo)
		}
		f, err := os.Open(tmpProvenancePath)
		if err != nil {
			return nil, err
		}
		bytes, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		f.Close()
		if string(bytes) != "some-provenance-data" {
			return nil, fmt.Errorf("unexpected provenance data: %v", string(bytes))
		}
		return []byte("success"), nil
	}

	config := &common.ConfigFile{
		Policies: []common.ConfigPolicy{
			{
				Name: "slsaEnsureComingFrom",
				Code: `
				if (!slsaEnsureComingFrom(["github.com/irsl/gcb-tests"]))
					return "according to slsaEnsureComingFrom this image is not coming from one of the trusted repositories"
				`,
			},
		},
		DefaultAction: "Allow",
	}

	cp, err := CompilePolicies(config)
	if err != nil {
		t.Fatal(err)
	}

	rc := &common.AdmissionControllerRequest{
		User: map[string]any{"Username": "whatever"},
	}
	areq := &k8sac.AdmissionRequest{
		UID: types.UID("uid"),
		Object: runtime.RawExtension{
			Raw: []byte(`{"container":{"image":"some/image"}}`),
		},
	}
	aresp := cp.Evaluate(rc, areq)

	if aresp.Allowed != false {
		t.Errorf("should have been rejected")
	}
	if aresp.Result.Message != "slsaEnsureComingFrom: according to slsaEnsureComingFrom this image is not coming from one of the trusted repositories" {
		t.Errorf("unexpected rejection message: %v", aresp.Result.Message)
	}

	// and repeating with a successful verification
	areq = &k8sac.AdmissionRequest{
		UID: types.UID("uid"),
		Object: runtime.RawExtension{
			Raw: []byte(`{"container":{"image":"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529"}}`),
		},
	}
	aresp = cp.Evaluate(rc, areq)
	if aresp.Allowed != true {
		t.Errorf("should have been accepted")
	}
}

func TestSlsaVerify(t *testing.T) {
	origCallSlsaVerifier := callSlsaVerifier
	defer func() { callSlsaVerifier = origCallSlsaVerifier }()
	callSlsaVerifier = func(imageRef, tmpProvenancePath, builderID, repo string) ([]byte, error) {
		if imageRef != "some/image" {
			return nil, fmt.Errorf("unexpected imageRef for callSlsaVerifier: %v", imageRef)
		}
		if builderID != "https://cloudbuild.googleapis.com/GoogleHostedWorker" {
			return nil, fmt.Errorf("unexpected builderID for callSlsaVerifier: %v", builderID)
		}
		if repo != "github.com/irsl/gcb-tests" {
			return nil, fmt.Errorf("unexpected repo for callSlsaVerifier: %v", repo)
		}
		if tmpProvenancePath != "/home/imrer/provenance-github.json" {
			return nil, fmt.Errorf("unexpected provenance path for callSlsaVerifier: %v", tmpProvenancePath)
		}

		return []byte("stdout"), fmt.Errorf("slsa-verifier didn't like this image")
	}

	config := &common.ConfigFile{
		Policies: []common.ConfigPolicy{
			{
				Name: "slsaVerify",
				Code: `
				return slsaVerify({"SourceURI": "github.com/irsl/gcb-tests", "BuilderID": "https://cloudbuild.googleapis.com/GoogleHostedWorker", "ProvenancePath": "/home/imrer/provenance-github.json"})
				`,
			},
		},
		DefaultAction: "Reject",
	}

	cp, err := CompilePolicies(config)
	if err != nil {
		t.Fatal(err)
	}

	rc := &common.AdmissionControllerRequest{
		User: map[string]any{"Username": "whatever"},
	}
	areq := &k8sac.AdmissionRequest{
		UID: types.UID("uid"),
		Object: runtime.RawExtension{
			Raw: []byte(`{"container":{"image":"some/image"}}`),
		},
	}
	aresp := cp.Evaluate(rc, areq)

	if aresp.Allowed != false {
		t.Errorf("should have been rejected")
	}
	if aresp.Result.Message != "slsaVerify: invoking the slsa-verifier cli failed: stdout slsa-verifier didn't like this image" {
		t.Errorf("unexpected rejection message: %v", aresp.Result.Message)
	}

}
