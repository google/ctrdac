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

package common

import (
	"crypto/x509"
	"net/http"

	k8sac "k8s.io/api/admission/v1"
)

// CompiledPolicies is an interface to evaluate admission requests
type CompiledPolicies interface {
	Evaluate(rc *AdmissionControllerRequest, ar *k8sac.AdmissionRequest) *k8sac.AdmissionResponse
}

// AuthzServer type represents the acjs admission controller
type AuthzServer interface {
	Serve() error
	UsePolicies(CompiledPolicies)
}

// AdmissionControllerRequest holds data required for authZ plugins
type AdmissionControllerRequest struct {
	// timestamp of the operation (when the request or response was received by the plugin, before starting the policy evaluation)
	Timestamp string

	// User holds the user extracted by AuthN mechanism
	User any `json:"User,omitempty"`

	// UserAuthNMethod holds the mechanism used to extract user details (e.g., krb)
	UserAuthNMethod string `json:"UserAuthNMethod,omitempty"`

	// RequestPeerCertificates stores the request's TLS peer certificates in PEM format
	RequestPeerCertificates []*x509.Certificate `json:"RequestPeerCertificates,omitempty"`

	// HTTPRequest is the raw incoming HTTP request, allowing access to RequestURI or Headers
	HTTPRequest *http.Request `json:"HttpRequest,omitempty"`

	// a dictionary that is available through the whole lifecycle of tha authz configuration
	GlobalContext map[string]any
}
