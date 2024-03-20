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

package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/pathsocket"
	"google.golang.org/grpc"

	anypb "github.com/golang/protobuf/ptypes/any"
	emptypb "github.com/golang/protobuf/ptypes/empty"
	cgrpcpb "github.com/containerd/containerd/v2/api/services/containers/v1"
	cpb "github.com/containerd/containerd/v2/api/services/containers/v1"
	k8sac "k8s.io/api/admission/v1"
)

type myAcHandler struct {
	calls int
}

func (h *myAcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls++
	re := &k8sac.AdmissionReview{Response: &k8sac.AdmissionResponse{
		Allowed: true,
	}}
	bytes, err := json.Marshal(re)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}

// CreateContainersServer is the gRPC service that can deal with the containerd Create container
// gRPC method calls.
type upstreamCreateContainersServer struct {
	cgrpcpb.UnimplementedContainersServer
}

// Create is a gRPC exported API invoked by containerd clients to create containers.
func (s *upstreamCreateContainersServer) Create(ctx context.Context, in *cpb.CreateContainerRequest) (*cpb.CreateContainerResponse, error) {
	return &cpb.CreateContainerResponse{Container: &cpb.Container{ID: "hello-from-the-upstream"}}, nil
}

func (s *upstreamCreateContainersServer) List(ctx context.Context, req *cpb.ListContainersRequest) (*cpb.ListContainersResponse, error) {
	return &cpb.ListContainersResponse{Containers: []*cpb.Container{&cpb.Container{ID: "list-response-from-the-upstream"}}}, nil
}

func (s *upstreamCreateContainersServer) Delete(ctx context.Context, req *cpb.DeleteContainerRequest) (*emptypb.Empty, error) {
	return nil, errors.New("not implemented")
}

func (s *upstreamCreateContainersServer) Get(context.Context, *cpb.GetContainerRequest) (*cpb.GetContainerResponse, error) {
	return nil, errors.New("not implemented")
}

func (s *upstreamCreateContainersServer) ListStream(*cpb.ListContainersRequest, cgrpcpb.Containers_ListStreamServer) error {
	return errors.New("not implemented")
}

func TestEnd2End(t *testing.T) {
	testdir := t.TempDir()
	containerdSockPath := pathsocket.GetSocketPath(testdir, "containerd.sock")
	acSockPath := pathsocket.GetSocketPath(testdir, "ac.sock")
	ctrdacSockPath := pathsocket.GetSocketPath(testdir, "ctrdac.sock")

	// dummy ac listener
	acListener, err := pathsocket.NewListener(acSockPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer acListener.GetListener().Close()
	acHandler := myAcHandler{}
	acServer := http.Server{
		Handler: &acHandler,
	}
	go acServer.Serve(acListener.GetListener())

	// dummy containerd listener
	containerdListener, err := pathsocket.NewListener(containerdSockPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer containerdListener.GetListener().Close()

	grpcServer := grpc.NewServer()
	containerUpstream := upstreamCreateContainersServer{}
	cgrpcpb.RegisterContainersServer(grpcServer, &containerUpstream)

	go grpcServer.Serve(containerdListener.GetListener())

	// the proxy server
	config := common.ProxyServerConfig{
		ProxyListenerSocket:      ctrdacSockPath,
		ProxyListenerParams:      "",
		UpstreamContainerdSocket: containerdSockPath,
		ValidatingWebhooks:       []string{acSockPath},
	}
	ps := NewProxyServer(config)
	go ps.Serve()

	// and now some real gRPC calls

	upstream := pathsocket.NewDialer(ctrdacSockPath)

	options := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials),
		grpc.WithBlock(),
		grpc.WithContextDialer(common.ContextDialer(upstream)),
	}

	grpcCtrdacConn, err := grpc.Dial("upstream", options...)
	if err != nil {
		t.Fatal(err)
	}
	defer grpcCtrdacConn.Close()

	grpcCtrdacContainersClient := cgrpcpb.NewContainersClient(grpcCtrdacConn)
	lr, err := grpcCtrdacContainersClient.List(context.Background(), &cpb.ListContainersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lr.Containers) != 1 {
		t.Errorf("unexpected number of containers in the list containers response: %+v", lr)
	}
	if lr.GetContainers()[0].GetID() != "list-response-from-the-upstream" {
		t.Errorf("unexpected response for list containers request: %+v", lr)
	}
	if acHandler.calls != 0 {
		t.Error("ac shouldn't have been called")
	}
	cr, err := grpcCtrdacContainersClient.Create(context.Background(), &cpb.CreateContainerRequest{
		Container: &cpb.Container{
			Image: "some/image",
			Spec: &anypb.Any{
				Value: []byte("{}"),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cr.GetContainer().GetID() != "hello-from-the-upstream" {
		t.Errorf("unexpected response for create container request: %+v", cr)
	}
	if acHandler.calls != 1 {
		t.Errorf("ac should have been called: %d", acHandler.calls)
	}
}
