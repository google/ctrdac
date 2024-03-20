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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/google/ctrdac/lookup"
)

type myHandler struct {
	listener Listener
}

func (h myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	re := AdmissionControllerRequest{}
	h.listener.PopulateRequest(&re, r)
	re.RequestPeerCertificates = nil
	bytes, err := json.Marshal(re)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}

func TestUdsListener(t *testing.T) {
	testdir := t.TempDir()
	udsPath := path.Join(testdir, "uds")
	cus := ConfigPathListener{
		SocketPath: udsPath,
	}
	listener, err := NewPathListener(&cus)
	if err != nil {
		t.Fatal(err)
	}

	server := http.Server{
		Handler: myHandler{listener},
	}
	err = listener.ConfigureHooks(&server)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener.GetListener())

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", udsPath)
			},
		},
	}
	resp, err := client.Get("http://unix/")
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var rc AdmissionControllerRequest
	err = json.Unmarshal(bytes, &rc)
	if err != nil {
		t.Fatal(err)
	}

	aUID := lookup.Lookup[float64](rc.User, "Uid", 0)
	eUID := os.Getuid()
	if eUID != int(aUID) {
		t.Errorf("User was not populated correctly. %v vs %v (in %v)", eUID, aUID, rc.User)
	}
}

func generateSelfSignedCert(certPath, privKeyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "hello:)",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	ip := net.ParseIP("127.0.0.1")
	template.IPAddresses = []net.IP{ip}
	template.DNSNames = []string{"localhost"}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	f, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	f.Close()

	f, err = os.OpenFile(privKeyPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	f.Close()
	return nil
}

func TestMtlsListener(t *testing.T) {
	testdir := t.TempDir()
	privKeyPath := path.Join(testdir, "privkey.pem")
	certPath := path.Join(testdir, "cert.pem")

	err := generateSelfSignedCert(certPath, privKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	cus := ConfigMtlsListener{
		PrivateKeyPath:  privKeyPath,
		CertificatePath: certPath,
		ClientCAsPath:   certPath,
		ListenOn:        ":0", // random free port
	}
	listener, err := NewMtlsListener(&cus)
	if err != nil {
		t.Fatal(err)
	}

	server := http.Server{
		Handler: myHandler{listener},
	}
	err = listener.ConfigureHooks(&server)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener.GetListener())

	caCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cer, err := tls.LoadX509KeyPair(certPath, privKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cer},
			},
		},
	}
	upstreamAddress := strings.Replace(listener.GetListener().Addr().String(), "[::]", "localhost", -1)
	url := "https://" + upstreamAddress + "/"

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var rc AdmissionControllerRequest
	err = json.Unmarshal(bytes, &rc)
	if err != nil {
		t.Fatal(err)
	}

	commonName := lookup.Lookup(rc.User, "CommonName", "")
	if commonName != "hello:)" {
		t.Errorf("User was not populated correctly. %v", rc.User)
	}
}

func TestTlsListener(t *testing.T) {
	testdir := t.TempDir()
	privKeyPath := path.Join(testdir, "privkey.pem")
	certPath := path.Join(testdir, "cert.pem")

	err := generateSelfSignedCert(certPath, privKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	cus := ConfigTLSListener{
		PrivateKeyPath:  privKeyPath,
		CertificatePath: certPath,
		ListenOn:        ":0", // random free port
	}
	listener, err := NewTLSListener(&cus)
	if err != nil {
		t.Fatal(err)
	}

	server := http.Server{
		Handler: myHandler{listener},
	}
	err = listener.ConfigureHooks(&server)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener.GetListener())

	caCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	upstreamAddress := strings.Replace(listener.GetListener().Addr().String(), "[::]", "localhost", -1)
	url := "https://" + upstreamAddress + "/"

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var rc AdmissionControllerRequest
	err = json.Unmarshal(bytes, &rc)
	if err != nil {
		t.Fatal(err)
	}

	// note: User is not populated here as no authentication happens
	if rc.UserAuthNMethod != "" || rc.User != nil {
		t.Errorf("User was not populated correctly. %v - %v", rc.UserAuthNMethod, rc.User)
	}
}
