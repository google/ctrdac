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

// Package common contains a bunch of helper functions, interfaces and methods for the ctrdac
// application.
package common

import (
	"context"
	"net"
	"net/http"

	k8sac "k8s.io/api/admission/v1"
)

// Listener is the common interface of the mTLS and the UDS listeners.
type Listener interface {
	// GetListener returns the low level golang net.Listener for this path listener.
	GetListener() net.Listener

	// ConfigureHooks configured a http.Server so that information about the peers
	// is populated into the context.
	ConfigureHooks(server *http.Server) error

	// PopulateUserInfo sets the listener specific attributes on AuthzRequest, e.g.
	// the client certificates in the case of mTLS or the remote uid in the case of UDS
	PopulateUserInfo(ctx context.Context, ar *k8sac.AdmissionRequest) error
}
