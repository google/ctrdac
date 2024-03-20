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

package pathsocket

import (
	"github.com/google/ctrdac/common"
)

// PathUpstream implements the Upstream interface to access the containerd listener.
type PathUpstream struct {
	socketPath string
	grpcHack   bool
}

// DialFlag allows customizing the dialing behaviour.
type DialFlag int

const (
	// Grpc indicates that the upstream is a Grpc listener
	Grpc DialFlag = 1
)

// NewDialer creates a new Upstream interface to a path listener.
func NewDialer(socketPath string, flags ...DialFlag) common.Upstream {
	grpcHack := false
	if len(flags) == 1 && flags[0] == Grpc {
		grpcHack = true
	}
	return &PathUpstream{socketPath, grpcHack}
}
