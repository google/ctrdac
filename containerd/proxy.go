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

// Package containerd is the core proxy logic for ctrdac.
package containerd

import (
	"context"
	"fmt"

	"net/http"
	"net/http/httputil"
	"time"

	log "github.com/golang/glog"
	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/handlers/containers"
	"github.com/google/ctrdac/pathsocket"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	k8sac "k8s.io/api/admission/v1"
)

// ProxyServer is the type of the main proxy server code
type ProxyServer struct {
	config common.ProxyServerConfig

	listener common.Listener
}

var (
	credentials = local.NewCredentials() // No SSL/TLS
	kacp        = keepalive.ClientParameters{
		Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
		Timeout:             time.Second,      // wait 1 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // send pings even without active streams
	}
)

// NewProxyServer creates a new ctrdac proxy server with the given configuration
func NewProxyServer(config common.ProxyServerConfig) ProxyServer {
	return ProxyServer{config: config, listener: nil}
}

func registerAll(grpcServer *grpc.Server, proxyServer common.ProxyServer, grpcUpstreamConn *grpc.ClientConn) map[string]bool {
	var supportedMethods []string
	supportedMethods = append(supportedMethods, containers.Register(grpcServer, proxyServer, grpcUpstreamConn)...)

	re := map[string]bool{}
	for _, m := range supportedMethods {
		re[m] = true
	}
	return re
}

// Serve starts serving or returns an error
func (pl *ProxyServer) Serve() error {
	aListener, err := pathsocket.NewListener(pl.config.ProxyListenerSocket, pl.config.ProxyListenerParams)
	if err != nil {
		return fmt.Errorf("proxy listener failed: %v", err)
	}

	pl.listener = aListener

	upstream := pathsocket.NewDialer(pl.config.UpstreamContainerdSocket, pathsocket.Grpc)

	l := pl.listener.GetListener()

	options := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials),
		grpc.FailOnNonTempDialError(true),
		grpc.WithContextDialer(common.ContextDialer(upstream)),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithReturnConnectionError(),
	}

	grpcUpstreamConn, err := grpc.Dial("upstream", options...)
	if err != nil {
		return err
	}
	defer grpcUpstreamConn.Close()

	log.Infof("Connection to the upstream Containerd has been established")

	grpcServer := grpc.NewServer()

	supportedMethods := registerAll(grpcServer, *pl, grpcUpstreamConn)

	proxy := &httputil.ReverseProxy{
		Transport: &http2.Transport{
			AllowHTTP:      true,
			DialTLSContext: common.TLSContextDialer(upstream),
		},
		Director: func(req *http.Request) {
			// we need to fix these, otherwise httputil.ReverseProxy would complain, e.g.:
			// http: proxy error: http: no Host in request URL
			// or
			// http2: invalid Host header

			req.URL.Scheme = "http"
			req.URL.Host = "localhost"
			req.Host = "localhost"
		},
		FlushInterval: 50 * time.Millisecond,
	}

	log.Infof("Containerd proxy listener started on %v", pl.config.ProxyListenerSocket)
	server := http2.Server{}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		rCred, err := pathsocket.RetrieveConnectionInfo(conn)
		if err != nil {
			return err
		}

		ctx := context.Background()
		rw := common.RequestWrapper{}
		ctx = context.WithValue(ctx, pathsocket.PathCred, rCred)
		ctx = context.WithValue(ctx, common.RequestContext, &rw)

		// ServeConn is blocking
		go server.ServeConn(conn, &http2.ServeConnOpts{
			Context: ctx,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.Infof("%v", r.RequestURI)

				if supportedMethods[r.RequestURI] {
					if rw, ok := r.Context().Value(common.RequestContext).(*common.RequestWrapper); ok {
						rw.Request = r
					}

					grpcServer.ServeHTTP(w, r)
					return
				}

				// otherwise blind relay
				proxy.ServeHTTP(w, r)
			}),
		})
	}
}

// PopulateUserInfo calls the same method on the underlying listener to get the UserInfo structure
// of the AdmissionRequest filled
func (pl ProxyServer) PopulateUserInfo(ctx context.Context, authzReq *k8sac.AdmissionRequest) error {
	return pl.listener.PopulateUserInfo(ctx, authzReq)
}

// GetConfig returns the full configuration of the ctrdac proxy server
func (pl ProxyServer) GetConfig() common.ProxyServerConfig {
	return pl.config
}
