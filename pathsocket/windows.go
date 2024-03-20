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

//go:build windows
// +build windows

package pathsocket

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/google/ctrdac/common"
	k8sauth "k8s.io/api/authentication/v1"
	"github.com/Microsoft/go-winio"
)

// NewListener creates a new named pipe listener.
// The following parameters are supported:
// - SecurityDescriptor in SDDL notation (by default, it is not specified)
func NewListener(socketPath string, params string) (common.Listener, error) {
	var pc *winio.PipeConfig
	if params != "" {
		pc = &winio.PipeConfig{SecurityDescriptor: params}
	}
	lsnr, err := winio.ListenPipe(socketPath, pc)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %v: %v", socketPath, err)
	}
	return &listenerImpl{lsnr}, nil
}

// TODO(imrer): Check whether Windows has any APIs for this.
func retrieveConnectionInfo(conn net.Conn) (any, error) {
	return nil, nil
}

func populateUserInfo(pc any, ui *k8sauth.UserInfo) error {
	return nil
}

// GetSocketPath is a helper function for unit tests so we can run them platform agnostic.
// On Windows, it combines dir and pipename, replacing special characters and
// use it as the pipe path
func GetSocketPath(dir string, pipeName string) string {
	s := filepath.Join(dir, pipeName)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, `\`, "_")
	return `\\.\pipe\` + s
}

// Dial establishes a connection to the unix domain socket of containerd.
func (us *PathUpstream) Dial() (net.Conn, error) {
	conn, err := winio.DialPipe(us.socketPath, nil)
	if err != nil {
		return nil, err
	}
	if us.grpcHack {
		// Note: we read here to workaround a net/http client issue on Windows via named channels against
		// gRPC http servers
		buf := make([]byte, 15)
		_, _ = conn.Read(buf)
	}
	return conn, nil
}
