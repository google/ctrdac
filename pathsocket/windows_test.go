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
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

type myHandler struct{}

func (h myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello: " + r.RequestURI))
}

func TestPipeHttpListener(t *testing.T) {
	pipePath := GetSocketPath(t.TempDir(), "uds")
	listener, err := NewListener(pipePath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.GetListener().Close()

	server := http.Server{
		Handler: myHandler{},
	}
	err = listener.ConfigureHooks(&server)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener.GetListener())

	dialer := NewDialer(pipePath)

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return dialer.Dial()
			},
		},
	}
	resp, err := client.Get("http://unix/foobar")
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	response := string(bytes)
	if response != "Hello: /foobar" {
		t.Error("unexpected response: %v", response)
	}
}

func TestGetSocketPath(t *testing.T) {
	tmpdir := t.TempDir()
	pipePath := GetSocketPath(tmpdir, "uds")
	expectedPrefix := `\\.\pipe\`
	if !strings.HasPrefix(pipePath, expectedPrefix) {
		t.Error("unexpected pipe path %v", pipePath)
	}
	rest := pipePath[len(expectedPrefix):]
	if strings.ContainsAny(rest, `:\/`) {
		t.Error("unexpected characters in pipe path: %v", pipePath)
	}
}
