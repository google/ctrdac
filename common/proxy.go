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
	"context"
	"net/http"

	k8sac "k8s.io/api/admission/v1"
)

// ProxyServer is an interface to the ctrdac proxy server; it is passed across the subpackages
// that need to interact with/fetch info from the proxy server.
type ProxyServer interface {
	PopulateUserInfo(ctx context.Context, authzReq *k8sac.AdmissionRequest) error
	GetConfig() ProxyServerConfig
}

// ProxyServerConfig holds the supported configuration options of the ctrdac proxy server
type ProxyServerConfig struct {
	ProxyListenerSocket      string
	ProxyListenerParams      string
	UpstreamContainerdSocket string
	DockerSocket             string
	ValidatingWebhooks       []string
	MutatingWebhooks         []string
	NoK8sConversion          bool
}

// ContextKey is the root type of info we attach to the context
type ContextKey struct {
	Name string
}

// RequestWrapper is a wrapper struct that exposes the underlying http.Request in gRPC context
type RequestWrapper struct {
	Request *http.Request
}

var (
	// RequestContext is the key in the context that exposes the original http.Request
	RequestContext = &ContextKey{Name: "req"}
)
