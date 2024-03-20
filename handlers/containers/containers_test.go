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

package containers

import (
	"context"
	"testing"

	"github.com/google/ctrdac/logic"

	cpb "github.com/containerd/containerd/v2/api/services/containers/v1"
)

type mockedEval struct{}

func (mockedEval) CallAdmissionControllers(ctx context.Context, in *cpb.CreateContainerRequest) (*cpb.CreateContainerResponse, error) {
	return &cpb.CreateContainerResponse{
		Container: &cpb.Container{ID: "hellothere"},
	}, nil
}

func TestContainersEval(t *testing.T) {
	cs := NewContainersServer(nil, nil)
	in := &cpb.CreateContainerRequest{}
	origCreateEval := createEvaluator
	defer func() {
		createEvaluator = origCreateEval
	}()
	createEvaluator = func(s *CreateContainersServer) logic.Evaluator[*cpb.CreateContainerRequest, *cpb.CreateContainerResponse] {
		return mockedEval{}
	}
	resp, err := cs.Create(context.TODO(), in)
	if err != nil {
		t.Fatal(err)
	}
	expectedContainerID := "hellothere"
	if resp.GetContainer().GetID() != expectedContainerID {
		t.Errorf("expected container ID: %v, actual response: %v", expectedContainerID, resp.GetContainer().GetID())
	}
}
