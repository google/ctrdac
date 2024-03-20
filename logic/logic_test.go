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

package logic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/google/ctrdac/common"
	"github.com/mattbaird/jsonpatch"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sac "k8s.io/api/admission/v1"
)

type myK8sIn struct{ InParamK8s string }

type myIn struct{ InParam string }

type myOut struct{ OutParam string }

type mockedProxyServer struct {
	ProxyServerConfig common.ProxyServerConfig
}

func (m mockedProxyServer) PopulateUserInfo(ctx context.Context, authzReq *k8sac.AdmissionRequest) error {
	return nil
}
func (m mockedProxyServer) GetConfig() common.ProxyServerConfig {
	return m.ProxyServerConfig
}

func TestLogicSuccess(t *testing.T) {
	origCallAdmissionControllerWebhook := callAdmissionControllerWebhook
	defer func() { callAdmissionControllerWebhook = origCallAdmissionControllerWebhook }()
	admissionWebhookURLs := []string{"https://foobar1.tld/something", "https://foobar2.tld/something"}
	var actualAdmissionCalls []string
	callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {
		if headers["X-Ctrdac-RequestUri"] != "/some/uri" {
			return nil, fmt.Errorf("unexpected headers: %+v", headers)
		}
		acObjectPayload := string(ar.Request.Object.Raw)
		if acObjectPayload != `"k8s-version-of-input"` {
			return nil, fmt.Errorf("unexpected ac object payload: %v", acObjectPayload)
		}
		actualAdmissionCalls = append(actualAdmissionCalls, url)
		return &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
			Allowed: true,
		}}, nil
	}

	dMyIn := myIn{InParam: "inparam-value"}
	myProxyServer := mockedProxyServer{
		ProxyServerConfig: common.ProxyServerConfig{
			ValidatingWebhooks: admissionWebhookURLs,
		},
	}
	el := EvalLogic[myIn, myOut]{
		Upstream: func(ctx context.Context, in myIn, opts ...grpc.CallOption) (myOut, error) {
			if in.InParam != dMyIn.InParam {
				var re myOut
				return re, fmt.Errorf("unexpected input for the upstream")
			}
			return myOut{OutParam: "outparam-value"}, nil
		},
		TransformInput: func(s common.ProxyServer, in myIn) (any, error) {
			return "k8s-version-of-input", nil
		},
		PatchInput: func(s common.ProxyServer, in myIn, modifiedObjectBytes []byte) error {
			errmsg := "PatchInput should not be called"
			t.Fatalf(errmsg)
			return fmt.Errorf(errmsg)
		},
		ProxyServer: myProxyServer,
	}

	ctx := context.WithValue(context.Background(), common.RequestContext, &common.RequestWrapper{Request: &http.Request{RequestURI: "/some/uri"}})

	dMyOut, err := el.CallAdmissionControllers(ctx, dMyIn)
	if err != nil {
		t.Fatal(err)
	}
	if dMyOut.OutParam != "outparam-value" {
		t.Errorf("unexpected response: %+v", dMyOut)
	}
	if !reflect.DeepEqual(actualAdmissionCalls, admissionWebhookURLs) {
		t.Errorf("admission webhooks were not invoked, or not in the right order: %+v", actualAdmissionCalls)
	}
}

func TestLogicRejection(t *testing.T) {
	origCallAdmissionControllerWebhook := callAdmissionControllerWebhook
	defer func() { callAdmissionControllerWebhook = origCallAdmissionControllerWebhook }()
	admissionWebhookURLs := []string{"https://foobar1.tld/something", "https://foobar2.tld/something"}
	var actualAdmissionCalls []string
	callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {
		acObjectPayload := string(ar.Request.Object.Raw)
		if acObjectPayload != `"k8s-version-of-input"` {
			return nil, fmt.Errorf("unexpected ac object payload: %v", acObjectPayload)
		}
		actualAdmissionCalls = append(actualAdmissionCalls, url)
		if url == admissionWebhookURLs[len(admissionWebhookURLs)-1] {
			return &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
				Allowed: false,
				Result: &v1.Status{
					Message: "AC rejected the request",
				},
			}}, nil

		}
		return &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
			Allowed: true,
		}}, nil
	}

	dMyIn := myIn{InParam: "inparam-value"}
	myProxyServer := mockedProxyServer{
		ProxyServerConfig: common.ProxyServerConfig{
			ValidatingWebhooks: admissionWebhookURLs,
		},
	}
	el := EvalLogic[myIn, myOut]{
		Upstream: func(ctx context.Context, in myIn, opts ...grpc.CallOption) (myOut, error) {
			var re myOut
			return re, fmt.Errorf("upstream shouldn't have been called")
		},
		TransformInput: func(s common.ProxyServer, in myIn) (any, error) {
			return "k8s-version-of-input", nil
		},
		PatchInput: func(s common.ProxyServer, in myIn, modifiedObjectBytes []byte) error {
			errmsg := "PatchInput should not be called"
			t.Fatalf(errmsg)
			return fmt.Errorf(errmsg)
		},
		ProxyServer: myProxyServer,
	}

	ctx := context.TODO()
	dMyOut, err := el.CallAdmissionControllers(ctx, dMyIn)
	if dMyOut.OutParam != "" {
		t.Errorf("unexpected response: %+v", dMyOut)
	}
	if err == nil {
		t.Errorf("CallAdmissionControllers should have returned a GRPC error")
	}
	if err.Error() != "rpc error: code = InvalidArgument desc = : AC rejected the request" {
		t.Errorf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(actualAdmissionCalls, admissionWebhookURLs) {
		t.Errorf("admission webhooks were not invoked, or not in the right order: %+v", actualAdmissionCalls)
	}
}

func TestLogicError(t *testing.T) {
	origCallAdmissionControllerWebhook := callAdmissionControllerWebhook
	defer func() { callAdmissionControllerWebhook = origCallAdmissionControllerWebhook }()
	admissionWebhookURLs := []string{"https://foobar1.tld/something"}
	var actualAdmissionCalls []string
	callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {
		actualAdmissionCalls = append(actualAdmissionCalls, url)
		return nil, fmt.Errorf("testing-what-happend-when-callAdmissionControllerWebhook-returns-error")
	}

	dMyIn := myIn{InParam: "inparam-value"}
	myProxyServer := mockedProxyServer{
		ProxyServerConfig: common.ProxyServerConfig{
			ValidatingWebhooks: admissionWebhookURLs,
		},
	}
	el := EvalLogic[myIn, myOut]{
		Upstream: func(ctx context.Context, in myIn, opts ...grpc.CallOption) (myOut, error) {
			var re myOut
			return re, fmt.Errorf("upstream shouldn't have been called")
		},
		TransformInput: func(s common.ProxyServer, in myIn) (any, error) {
			return "k8s-version-of-input", nil
		},
		PatchInput: func(s common.ProxyServer, in myIn, modifiedObjectBytes []byte) error {
			errmsg := "PatchInput should not be called"
			t.Fatalf(errmsg)
			return fmt.Errorf(errmsg)
		},
		ProxyServer: myProxyServer,
	}

	ctx := context.TODO()
	dMyOut, err := el.CallAdmissionControllers(ctx, dMyIn)
	if dMyOut.OutParam != "" {
		t.Errorf("unexpected response: %+v", dMyOut)
	}
	if err == nil {
		t.Errorf("CallAdmissionControllers should have returned a GRPC error")
	}
	if err.Error() != "admission controller returned an error: testing-what-happend-when-callAdmissionControllerWebhook-returns-error" {
		t.Errorf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(actualAdmissionCalls, admissionWebhookURLs) {
		t.Errorf("admission webhooks were not invoked, or not in the right order: %+v", actualAdmissionCalls)
	}
}

func TestLogicNoK8sConversion(t *testing.T) {
	origCallAdmissionControllerWebhook := callAdmissionControllerWebhook
	defer func() { callAdmissionControllerWebhook = origCallAdmissionControllerWebhook }()
	admissionWebhookURLs := []string{"https://foobar1.tld/something"}
	var actualAdmissionCalls []string
	callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {
		acObjectPayload := string(ar.Request.Object.Raw)
		if acObjectPayload != `{"InParam":"inparam-value"}` {
			return nil, fmt.Errorf("unexpected ac object payload: %v", acObjectPayload)
		}
		actualAdmissionCalls = append(actualAdmissionCalls, url)
		return &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
			Allowed: true,
		}}, nil
	}

	dMyIn := myIn{InParam: "inparam-value"}
	myProxyServer := mockedProxyServer{
		ProxyServerConfig: common.ProxyServerConfig{
			ValidatingWebhooks: admissionWebhookURLs,
			NoK8sConversion:    true,
		},
	}
	el := EvalLogic[myIn, myOut]{
		Upstream: func(ctx context.Context, in myIn, opts ...grpc.CallOption) (myOut, error) {
			if in.InParam != dMyIn.InParam {
				var re myOut
				return re, fmt.Errorf("unexpected input for the upstream")
			}
			return myOut{OutParam: "outparam-value"}, nil
		},
		TransformInput: func(s common.ProxyServer, in myIn) (any, error) {
			errmsg := "TransformInput should not be called"
			t.Fatalf(errmsg)
			return nil, fmt.Errorf(errmsg)
		},
		PatchInput: func(s common.ProxyServer, in myIn, modifiedObjectBytes []byte) error {
			errmsg := "PatchInput should not be called"
			t.Fatalf(errmsg)
			return fmt.Errorf(errmsg)
		},
		ProxyServer: myProxyServer,
	}

	ctx := context.TODO()
	dMyOut, err := el.CallAdmissionControllers(ctx, dMyIn)
	if err != nil {
		t.Fatal(err)
	}
	if dMyOut.OutParam != "outparam-value" {
		t.Errorf("unexpected response: %+v", dMyOut)
	}
	if !reflect.DeepEqual(actualAdmissionCalls, admissionWebhookURLs) {
		t.Errorf("admission webhooks were not invoked, or not in the right order: %+v", actualAdmissionCalls)
	}
}

func TestLogicNoK8sPatching(t *testing.T) {
	origCallAdmissionControllerWebhook := callAdmissionControllerWebhook
	defer func() { callAdmissionControllerWebhook = origCallAdmissionControllerWebhook }()
	mutatingWebhookURLs := []string{"https://mutating1.tld/something", "https://mutating2.tld/something"}
	validatingWebhookURLs := []string{"https://validating1.tld/something"}
	var actualAcCalls []string
	expectedPayloads := []string{
		`{"InParam":"initial-value"}`,
		`{"InParam":"modified-value0"}`,
		`{"InParam":"modified-value1"}`,
		`{"InParam":"modified-value2"}`, // this is special, needed only for generating the patch
	}
	callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {
		acObjectPayload := string(ar.Request.Object.Raw)
		expectedObjectPayload := expectedPayloads[len(actualAcCalls)]
		if acObjectPayload != expectedObjectPayload {
			return nil, fmt.Errorf("unexpected ac object payload for %v: %v", url, acObjectPayload)
		}
		actualAcCalls = append(actualAcCalls, url)
		nextExpectedObjectPayload := expectedPayloads[len(actualAcCalls)]

		patches, err := jsonpatch.CreatePatch([]byte(expectedObjectPayload), []byte(nextExpectedObjectPayload))
		if err != nil {
			return nil, err
		}

		patchToReturn, err := json.Marshal(patches)
		if err != nil {
			return nil, err
		}

		patchType := k8sac.PatchTypeJSONPatch
		return &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
			Allowed:   true,
			Patch:     patchToReturn,
			PatchType: &patchType,
		}}, nil
	}

	dMyIn := myIn{InParam: "initial-value"}
	myProxyServer := mockedProxyServer{
		ProxyServerConfig: common.ProxyServerConfig{
			MutatingWebhooks:   mutatingWebhookURLs,
			ValidatingWebhooks: validatingWebhookURLs,
			NoK8sConversion:    true,
		},
	}
	el := EvalLogic[myIn, myOut]{
		Upstream: func(ctx context.Context, in myIn, opts ...grpc.CallOption) (myOut, error) {
			// note, this is not modified-value2 since the patch returned by the validating-webhook is
			// ignored!
			if in.InParam != "modified-value1" {
				var re myOut
				return re, fmt.Errorf("unexpected input for the upstream, upstream should get the latest modified one (modified-value1)")
			}
			return myOut{OutParam: "outparam-value"}, nil
		},
		TransformInput: func(s common.ProxyServer, in myIn) (any, error) {
			errmsg := "TransformInput should not be called"
			t.Fatalf(errmsg)
			return nil, fmt.Errorf(errmsg)
		},
		PatchInput: func(s common.ProxyServer, in myIn, modifiedObjectBytes []byte) error {
			errmsg := "PatchInput should not be called"
			t.Fatalf(errmsg)
			return fmt.Errorf(errmsg)
		},
		ProxyServer: myProxyServer,
	}

	ctx := context.TODO()
	dMyOut, err := el.CallAdmissionControllers(ctx, dMyIn)
	if err != nil {
		t.Fatal(err)
	}
	if dMyOut.OutParam != "outparam-value" {
		t.Errorf("unexpected response: %+v", dMyOut)
	}
	if !reflect.DeepEqual(actualAcCalls, append(mutatingWebhookURLs, validatingWebhookURLs...)) {
		t.Errorf("admission webhooks were not invoked, or not in the right order: %+v", actualAcCalls)
	}
}

func TestLogicPatching(t *testing.T) {
	origCallAdmissionControllerWebhook := callAdmissionControllerWebhook
	defer func() { callAdmissionControllerWebhook = origCallAdmissionControllerWebhook }()
	mutatingWebhookURLs := []string{"https://mutating1.tld/something", "https://mutating2.tld/something"}
	validatingWebhookURLs := []string{"https://validating1.tld/something"}
	var actualAcCalls []string
	expectedPayloads := []string{
		`{"InParamK8s":"original-k8s-transformed-version-of-input"}`,
		`{"InParamK8s":"modified-value0"}`,
		`{"InParamK8s":"modified-value1"}`,
		`{"InParamK8s":"modified-value2"}`, // this is special, needed only for generating the patch
	}
	callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {
		acObjectPayload := string(ar.Request.Object.Raw)
		expectedObjectPayload := expectedPayloads[len(actualAcCalls)]
		if acObjectPayload != expectedObjectPayload {
			return nil, fmt.Errorf("unexpected ac object payload for %v: %v", url, acObjectPayload)
		}
		actualAcCalls = append(actualAcCalls, url)
		nextExpectedObjectPayload := expectedPayloads[len(actualAcCalls)]

		patches, err := jsonpatch.CreatePatch([]byte(expectedObjectPayload), []byte(nextExpectedObjectPayload))
		if err != nil {
			return nil, err
		}

		patchToReturn, err := json.Marshal(patches)
		if err != nil {
			return nil, err
		}

		patchType := k8sac.PatchTypeJSONPatch
		return &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
			Allowed:   true,
			Patch:     patchToReturn,
			PatchType: &patchType,
		}}, nil
	}

	dMyIn := myIn{InParam: "initial-value"}
	myProxyServer := mockedProxyServer{
		ProxyServerConfig: common.ProxyServerConfig{
			MutatingWebhooks:   mutatingWebhookURLs,
			ValidatingWebhooks: validatingWebhookURLs,
		},
	}
	el := EvalLogic[*myIn, *myOut]{
		Upstream: func(ctx context.Context, in *myIn, opts ...grpc.CallOption) (*myOut, error) {
			// note, this is not modified-value2 since the patch returned by the validating-webhook is
			// ignored!
			if in.InParam != "modified-value1" {
				return nil, fmt.Errorf("unexpected input for the upstream, upstream should get the latest modified one (modified-value1)")
			}
			return &myOut{OutParam: "outparam-value"}, nil
		},
		TransformInput: func(s common.ProxyServer, in *myIn) (any, error) {
			return myK8sIn{InParamK8s: "original-k8s-transformed-version-of-input"}, nil
		},
		PatchInput: func(s common.ProxyServer, in *myIn, modifiedObjectBytes []byte) error {
			modifiedObjectStr := string(modifiedObjectBytes)
			if modifiedObjectStr != `{"InParamK8s":"modified-value1"}` {
				return fmt.Errorf("unexpected input for PatchInput: %v", modifiedObjectStr)
			}
			in.InParam = "modified-value1"
			return nil
		},
		ProxyServer: myProxyServer,
	}

	ctx := context.TODO()
	dMyOut, err := el.CallAdmissionControllers(ctx, &dMyIn)
	if err != nil {
		t.Fatal(err)
	}
	if dMyOut.OutParam != "outparam-value" {
		t.Errorf("unexpected response: %+v", dMyOut)
	}
	if !reflect.DeepEqual(actualAcCalls, append(mutatingWebhookURLs, validatingWebhookURLs...)) {
		t.Errorf("admission webhooks were not invoked, or not in the right order: %+v", actualAcCalls)
	}
}
