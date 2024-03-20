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

// Package common provides a bunch of common types and functions for the acjs project
package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/pathsocket"
)

// ContextKey is the root type we use for populating context
type ContextKey struct {
	Name string
}

var (
	// MtlsConn is the ContextKey that can be used to retrieve mTLS related info from an
	// http.Requests's context
	MtlsConn = &ContextKey{Name: "mtls-conn"}
)

// Listener is the common interface of the unix domain socket, named pipes and the mTLS listeners
type Listener interface {
	GetListener() net.Listener
	ConfigureHooks(server *http.Server) error

	// this is to set the listener specific attributes on authzReq, e.g.
	// the client certificates in the case of mTLS or the remote uid in the case of UDS
	PopulateRequest(authzReq *AdmissionControllerRequest, dReq *http.Request) error
}

// NewPathListener creates a new Listener for unix domain socket / named pipe connections
func NewPathListener(config *ConfigPathListener) (*PathListener, error) {

	ulsnr, err := pathsocket.NewListener(config.SocketPath, config.Params)
	if err != nil {
		return nil, err
	}

	return &PathListener{ulsnr}, nil
}

// PathListener implements the Listener interface for connections over unix domain socket
type PathListener struct {
	listener common.Listener
}

// GetListener returns the raw golang net.Listener
func (ul *PathListener) GetListener() net.Listener {
	return ul.listener.GetListener()
}

// ConfigureHooks configures an http.Server so that authentication related info can be retrieved
// in the business logic via the context
func (ul *PathListener) ConfigureHooks(server *http.Server) error {
	return ul.listener.ConfigureHooks(server)
}

// PopulateRequest fills the authentication related fields of AdmissionControllerRequest based on
// the incoming dReq
func (ul *PathListener) PopulateRequest(authzReq *AdmissionControllerRequest, dReq *http.Request) error {
	authzReq.User = dReq.Context().Value(pathsocket.PathCred)
	authzReq.UserAuthNMethod = "path-listener"
	return nil
}

// MtlsListener implements the Listener interface for mTLS connections
type MtlsListener struct {
	listener net.Listener
}

// NewMtlsListener returns a new mTLS listener implementing the Listener interface
func NewMtlsListener(config *ConfigMtlsListener) (*MtlsListener, error) {

	cer, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	clientCaBytes, err := ioutil.ReadFile(config.ClientCAsPath)
	if err != nil {
		return nil, err
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCaBytes) {
		return nil, fmt.Errorf("unable to parse %s as PEM certificate(s)", config.ClientCAsPath)
	}

	tlsConfig := &tls.Config{
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cer},
	}
	listener, err := tls.Listen("tcp", config.ListenOn, tlsConfig)
	if err != nil {
		return nil, err
	}

	return &MtlsListener{listener}, nil
}

// PopulateRequest fills the authentication related fields of AdmissionControllerRequest based on
// the incoming dReq
func (ml *MtlsListener) PopulateRequest(authzReq *AdmissionControllerRequest, dReq *http.Request) error {
	var conn *tls.Conn
	var ok bool
	if conn, ok = dReq.Context().Value(MtlsConn).(*tls.Conn); !ok {
		return errors.New("unable to extract caller process'es tls connection")
	}

	state := conn.ConnectionState()

	var peercerts []*x509.Certificate

	for _, cert := range state.PeerCertificates {
		if authzReq.User == nil {
			authzReq.User = cert.Subject
		}

		peercerts = append(peercerts, cert)
	}

	authzReq.UserAuthNMethod = "mTLS"
	authzReq.RequestPeerCertificates = peercerts

	return nil
}

// GetListener returns the raw golang net.Listener
func (ml *MtlsListener) GetListener() net.Listener {
	return ml.listener
}

// ConfigureHooks configures an http.Server so that authentication related info can be retrieved
// in the business logic via the context
func (ml *MtlsListener) ConfigureHooks(server *http.Server) error {
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		conn, ok := c.(*tls.Conn)
		if !ok {
			return ctx
		}

		// we are saving the connection handle here,
		// as handshake was not yet processed and we can't return an error in this callback
		return context.WithValue(ctx, MtlsConn, conn)
	}
	return nil
}

// TLSListener implements the Listener interface for TLS connections
type TLSListener struct {
	listener net.Listener
}

// NewTLSListener returns a new mTLS listener implementing the Listener interface
func NewTLSListener(config *ConfigTLSListener) (*TLSListener, error) {

	cer, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
	}
	listener, err := tls.Listen("tcp", config.ListenOn, tlsConfig)
	if err != nil {
		return nil, err
	}

	return &TLSListener{listener}, nil
}

// PopulateRequest fills the authentication related fields of AdmissionControllerRequest
func (ml *TLSListener) PopulateRequest(authzReq *AdmissionControllerRequest, dReq *http.Request) error {
	return nil
}

// GetListener returns the raw golang net.Listener
func (ml *TLSListener) GetListener() net.Listener {
	return ml.listener
}

// ConfigureHooks configures an http.Server so that authentication related info can be retrieved
// in the business logic via the context
func (ml *TLSListener) ConfigureHooks(server *http.Server) error {
	return nil
}
