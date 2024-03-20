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

package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/ctrdac/pathsocket"
)

type someInputData struct {
	Foo string
	Bar int
}

type someOutputData struct {
	Baz               someInputData
	InterestingHeader string
}

type myHandler struct {
	expectedAuthorization string
}

func (h myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// it should be present for real googleapis.com requests only
	if r.Header.Get("Authorization") != h.expectedAuthorization {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var sid someInputData
	err = json.Unmarshal(bytes, &sid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// just echoing it back in a repackaged way
	re := someOutputData{Baz: sid, InterestingHeader: r.Header.Get("X-Interesting")}
	bytes, err = json.Marshal(re)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(bytes)
}

func TestHttpCallOverUds(t *testing.T) {
	testdir := t.TempDir()
	udsPath := pathsocket.GetSocketPath(testdir, "uds")
	listener, err := pathsocket.NewListener(udsPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.GetListener().Close()

	server := http.Server{
		Handler: myHandler{
			expectedAuthorization: "",
		},
	}
	go server.Serve(listener.GetListener())

	sid := someInputData{Foo: "FooValue", Bar: 42}
	eod := someOutputData{Baz: sid, InterestingHeader: "hello"}

	sod, err := Post[someOutputData](udsPath, sid, map[string]string{"X-Interesting": "hello"})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(eod, sod) {
		t.Errorf("unexpected response by the server. Expected: %+v, Actual: %+v", eod, sod)
	}
}

type mockedHTTPDoer struct {
	expectedURL           string
	expectedAuthorization string
}

func (h mockedHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	if req.URL.String() != h.expectedURL {
		return nil, fmt.Errorf("unexpected url: %v (wanted: %v)", req.URL, h.expectedURL)
	}

	// it should be present for real googleapis.com requests only
	if req.Header.Get("Authorization") != h.expectedAuthorization {
		return nil, fmt.Errorf("unexpected authorization header: %v", req.Header.Get("Authorization"))
	}

	aBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	var sid someInputData
	err = json.Unmarshal(aBytes, &sid)
	if err != nil {
		return nil, err
	}

	// just echoing it back in a repackaged way
	re := someOutputData{Baz: sid}
	aBytes, err = json.Marshal(re)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(aBytes)),
	}, nil
}

func TestHttpCallOverTcp(t *testing.T) {
	var origGetGoogleAuthToken = getGoogleAuthToken
	defer func() { getGoogleAuthToken = origGetGoogleAuthToken }()
	getGoogleAuthToken = func() (string, error) { return "token", nil }

	sid := someInputData{Foo: "FooValue", Bar: 42}
	eod := someOutputData{Baz: sid}

	mockedClient := mockedHTTPDoer{
		expectedURL:           "https://www.googleapis.com/something",
		expectedAuthorization: "Bearer token",
	}

	sod, err := postImpl[someOutputData](mockedClient, mockedClient.expectedURL, sid, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(eod, sod) {
		t.Errorf("unexpected response by the server. Expected: %+v, Actual: %+v", eod, sod)
	}
}

func TestHttpCallOverUdsFailure(t *testing.T) {
	testdir := t.TempDir()
	udsPath := pathsocket.GetSocketPath(testdir, "uds")
	listener, err := pathsocket.NewListener(udsPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.GetListener().Close()

	server := http.Server{
		Handler: myHandler{
			expectedAuthorization: "",
		},
	}
	go server.Serve(listener.GetListener())

	sid := someInputData{Foo: "FooValue", Bar: 42}

	a, err := Post[[]string](udsPath, sid, nil)
	if a != nil {
		t.Error("we expected no return value")
	}
	if err == nil {
		t.Error("we expected an error, but got none")
	}
	eError := "cannot unmarshal object into Go value of type []string"
	if !strings.Contains(err.Error(), eError) {
		t.Errorf("unexpected error message: %v (wanted: %v)", err.Error(), eError)
	}

}
