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

// Package logic features the main business logic: it forwards a containerd request to a Kubernetes
// admission controller.
package logic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/lookup"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"github.com/evanphx/json-patch"
	"k8s.io/apimachinery/pkg/runtime"

	ctrdachttp "github.com/google/ctrdac/http"
	k8sac "k8s.io/api/admission/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// EvalLogic is the type that encapsulates dependencies needed to delegate the authorization
// decision to k8s admission controllers
type EvalLogic[IN, OUT any] struct {
	// Upstream should send the gRPC method to real upstream (containerd)
	Upstream func(ctx context.Context, in IN, opts ...grpc.CallOption) (OUT, error)
	// TransformInput should transform the incoming containerd gRPC request into what Kubernetes
	// expects.
	TransformInput func(s common.ProxyServer, in IN) (any, error)
	PatchInput     func(s common.ProxyServer, in IN, modifiedObjectBytes []byte) error
	ProxyServer    common.ProxyServer
}

// Evaluator is an interface to facilitate unit testing of gRPC services implemented in ctrdac
type Evaluator[IN, OUT any] interface {
	CallAdmissionControllers(context.Context, IN) (OUT, error)
}

func populateHeaders(ctx context.Context) map[string]string {
	re := make(map[string]string)

	if rw, ok := ctx.Value(common.RequestContext).(*common.RequestWrapper); ok {
		var req *http.Request = rw.Request
		re["X-Ctrdac-RequestUri"] = req.RequestURI
	}

	return re
}

// CallAdmissionControllers is the main logic that takes a gRPC *Request message,
// repackages it into a K8s AdmissionReview request, forwards it to the configured
// validating/mutating webhooks. If the decision allows it, it is forwarded to the upstream
// containerd server and the *Response gRPC response is returned.
func (s EvalLogic[IN, OUT]) CallAdmissionControllers(ctx context.Context, in IN) (OUT, error) {
	var errout OUT

	var realObject any
	var err error

	noK8sConversion := s.ProxyServer.GetConfig().NoK8sConversion

	if noK8sConversion {
		realObject = in
	} else {
		realObject, err = s.TransformInput(s.ProxyServer, in)
	}

	if err != nil {
		return errout, err
	}
	realObjectBytes, err := json.Marshal(realObject)
	if err != nil {
		return errout, err
	}
	rawObject := runtime.RawExtension{
		Raw: realObjectBytes,
	}

	kind := lookup.Lookup(realObject, "kind", "unknown")
	name := lookup.Lookup(realObject, "metadata.name", "unknown")
	namespace := lookup.Lookup(realObject, "metadata.namespace", "unknown-ns")

	dryRun := false
	ar := k8sac.AdmissionReview{
		TypeMeta: k8smeta.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Request: &k8sac.AdmissionRequest{
			UID: k8stypes.UID(uuid.NewString()),
			Kind: k8smeta.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    kind,
			},
			Resource: k8smeta.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods", // TODO: where to infer this from? - is this needed at all?
			},
			RequestKind: &k8smeta.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    kind,
			},
			RequestResource: &k8smeta.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods", // TODO: where to infer this from? - is this needed at all?
			},
			Name:      name,
			Namespace: namespace,
			Operation: "CREATE",
			DryRun:    &dryRun,

			Object: rawObject,
		},
	}
	err = s.ProxyServer.PopulateUserInfo(ctx, ar.Request)
	if err != nil {
		return errout, err
	}

	headers := populateHeaders(ctx)

	config := s.ProxyServer.GetConfig()

	changes := false
	for i, webhooks := range [][]string{
		config.MutatingWebhooks,
		config.ValidatingWebhooks,
	} {
		for _, vw := range webhooks {
			resp, err := callAdmissionControllerWebhook(vw, ar, headers)
			if err != nil {
				return errout, fmt.Errorf("admission controller returned an error: %v", err)
			}
			if !resp.Response.Allowed {
				return errout, status.Error(codes.InvalidArgument, string(resp.Response.Result.Reason)+": "+strings.TrimSpace(resp.Response.Result.Message))
			}

			if i == 0 && resp.Response.Patch != nil {
				// this is a mutating webhook, need to apply the patch, if present
				if resp.Response.PatchType == nil || *resp.Response.PatchType != k8sac.PatchTypeJSONPatch {
					return errout, fmt.Errorf("unsupported patchtype returned by the admission controller")
				}

				p, err := jsonpatch.DecodePatch(resp.Response.Patch)
				if err != nil {
					return errout, err
				}

				nRealObjectBytes, err := p.Apply(realObjectBytes)
				if err != nil {
					return errout, err
				}

				realObjectBytes = nRealObjectBytes
				ar.Request.Object = runtime.RawExtension{
					Raw: realObjectBytes,
				}
				changes = true
			}

		}
	}

	if changes {
		// we need to rebuild the ctrd Create request.
		if noK8sConversion {
			in, err = s.patchCtrdType(in, realObjectBytes)
			if err != nil {
				return errout, err
			}
		} else {
			err = s.PatchInput(s.ProxyServer, in, realObjectBytes)
			if err != nil {
				return errout, err
			}
		}
	}

	// we delegate the HTTP request headers this way (the containerd namespace is among them)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	return s.Upstream(ctx, in)
}

func (s EvalLogic[IN, OUT]) patchCtrdType(in IN, modifiedCreateRequest []byte) (IN, error) {
	var re IN
	err := json.Unmarshal(modifiedCreateRequest, &re)
	return re, err
}

var callAdmissionControllerWebhook = func(url string, ar k8sac.AdmissionReview, headers map[string]string) (*k8sac.AdmissionReview, error) {

	ar, err := ctrdachttp.Post[k8sac.AdmissionReview](url, ar, headers)
	if err != nil {
		return nil, err
	}
	return &ar, nil

}
