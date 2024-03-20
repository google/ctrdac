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

// Package pathsocket is a helper library to facilitate dealing with unix domain sockets and
// named pipes
// (unix domain socket on *nix and pipes on windows). It provides a unified abstraction on top,
// so code would compile and work fine on both family of operating systems.
package pathsocket

import (
	"context"
	"net"
	"net/http"

	k8sac "k8s.io/api/admission/v1"
	k8sauth "k8s.io/api/authentication/v1"
)

// ContextKey is root type of info that is added into the context.
type ContextKey struct {
	Name string
}

var (
	// PathCred is a context key that is used when saving Ucred information into the context.
	PathCred = &ContextKey{"path-creds"}
)

type listenerImpl struct {
	listener net.Listener
}

// GetListener returns the golang net.Listener for this path listener.
func (ul *listenerImpl) GetListener() net.Listener {
	return ul.listener
}

// ConfigureHooks installs hooks for a http.Server so that peer info of the incoming
// connections can be retrieved.
func (ul *listenerImpl) ConfigureHooks(server *http.Server) error {
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		pc, err := RetrieveConnectionInfo(c)
		if err != nil {
			return ctx
		}

		return context.WithValue(ctx, PathCred, pc)
	}
	return nil
}

// PopulateUserInfo fills authentication related info into a k8s AdmissionRequest type
// based on the connected peer. Context must be coming from a http.Server configured by the
// ConfigureServer method.
func (ul *listenerImpl) PopulateUserInfo(ctx context.Context, ar *k8sac.AdmissionRequest) error {
	ui := k8sauth.UserInfo{}
	pc := ctx.Value(PathCred)
	if err := populateUserInfo(pc, &ui); err != nil {
		return err
	}
	ar.UserInfo = ui
	return nil
}

// RetrieveConnectionInfo retrieves info about the connection.
// On unix, this returns *ResolvedUcred - ucred information along with the Uid and Gid resolved
// into their textual representation.
// On other platforms currently, it returns nil.
func RetrieveConnectionInfo(conn net.Conn) (any, error) {
	return retrieveConnectionInfo(conn)
}
