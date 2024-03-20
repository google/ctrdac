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
	"crypto/tls"
	"net"
)

// Upstream is an interface for ctrdac to access the containerd listener.
// Currently only UDS is implemented.
type Upstream interface {
	Dial() (net.Conn, error)
}

// TLSDialer returns a dialer suitable to use for http.DialTLS
func TLSDialer(u Upstream) func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
	return func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
		return u.Dial()
	}
}

// TLSContextDialer returns a dialer suitable to use for http.DialTLSContext
func TLSContextDialer(u Upstream) func(ctx context.Context, netw, addr string, cfg *tls.Config) (net.Conn, error) {
	return func(ctx context.Context, netw, addr string, cfg *tls.Config) (net.Conn, error) {
		return u.Dial()
	}
}

// ContextDialer returns a dialer suitable to use for http.DialTLS
func ContextDialer(u Upstream) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return u.Dial()
	}
}
