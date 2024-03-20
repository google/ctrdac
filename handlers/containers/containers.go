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

// Package containers implements a gRPC service that can handle containerd's
// `/containerd.services.containers.v1.Containers/Create` method invocation.
package containers

import (
	"context"

	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/logic"
	"google.golang.org/grpc"

	cgrpcpb "github.com/containerd/containerd/v2/api/services/containers/v1"
	cpb "github.com/containerd/containerd/v2/api/services/containers/v1"
)

// CreateContainersServer is the gRPC service that can deal with the containerd Create container
// gRPC method calls.
type CreateContainersServer struct {
	cgrpcpb.UnimplementedContainersServer

	server common.ProxyServer
	client cgrpcpb.ContainersClient
}

// NewContainersServer creates a new CreateContainersServer for the ctrdac proxy.
func NewContainersServer(server common.ProxyServer, conn *grpc.ClientConn) *CreateContainersServer {
	client := cgrpcpb.NewContainersClient(conn)
	re := CreateContainersServer{client: client, server: server}
	return &re
}

// Register registers the current gRPC service into the supplied grpc server
// It returns the list of supported gRPC method names to assist the reverse proxy logic.
func Register(grpcServer *grpc.Server, proxyServer common.ProxyServer, grpcUpstreamConn *grpc.ClientConn) []string {
	cgrpcpb.RegisterContainersServer(grpcServer, NewContainersServer(proxyServer, grpcUpstreamConn))
	return []string{"/containerd.services.containers.v1.Containers/Create"}
}

// Create is a gRPC exported API invoked by containerd clients to create containers.
func (s *CreateContainersServer) Create(ctx context.Context, in *cpb.CreateContainerRequest) (*cpb.CreateContainerResponse, error) {
	// log.Printf("in.Container.Spec: %v, %+v", in.Container.Spec.TypeUrl, string(in.Container.Spec.Value))
	// log.Printf("in.Container.Runtime.Options: %v, %+v", in.Container.Runtime.Options.TypeUrl, in.Container.Runtime.Options.Value)

	eval := createEvaluator(s)

	return eval.CallAdmissionControllers(ctx, in)
}

var createEvaluator = func(s *CreateContainersServer) logic.Evaluator[*cpb.CreateContainerRequest, *cpb.CreateContainerResponse] {
	eval := logic.EvalLogic[*cpb.CreateContainerRequest, *cpb.CreateContainerResponse]{
		Upstream:       s.client.Create,
		TransformInput: ConvertCreateContainerToPod,
		PatchInput:     PatchCreateContainer,
		ProxyServer:    s.server,
	}
	return eval
}
