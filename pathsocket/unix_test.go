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

//go:build unix
// +build unix

package pathsocket

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/google/ctrdac/common"
	k8sac "k8s.io/api/admission/v1"
)

func doPermissionTest(t *testing.T, udsPath string, iPerm, ePerm string) {
	listener, err := NewListener(udsPath, iPerm+":-:-")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.GetListener().Close()
	fi, err := os.Stat(udsPath)
	if err != nil {
		t.Fatal(err)
	}
	aPerm := fi.Mode().String()
	if aPerm != ePerm {
		t.Errorf("unexpected file permission: %v vs %v", aPerm, ePerm)
	}

}

func TestPermissions(t *testing.T) {
	tempdir := t.TempDir()
	udsPath := path.Join(tempdir, "uds")

	doPermissionTest(t, udsPath, "0111", "S--x--x--x")
	// listening on the same path again, as the previous file should be removed automatically
	doPermissionTest(t, udsPath, "0600", "Srw-------")
}

func assessMe(t *testing.T, rc *ResolvedUcred) {
	ePid := os.Getpid()
	if int(rc.Pid) != ePid {
		t.Errorf("ExtractUcred didn't return the correct pid %v vs %v", rc.Pid, ePid)
	}

	eUID := os.Getuid()
	if int(rc.Uid) != eUID {
		t.Errorf("ExtractUcred didn't return the correct uid %v vs %v", rc.Uid, eUID)
	}

	eGid := os.Getgid()
	if int(rc.Gid) != eGid {
		t.Errorf("ExtractUcred didn't return the correct gid %v vs %v", rc.Gid, eGid)
	}
}

func TestRetrieveConnectionInfo(t *testing.T) {
	tempdir := t.TempDir()
	udsPath := path.Join(tempdir, "uds")
	listener, err := NewListener(udsPath, "0600:-:-")
	if err != nil {
		t.Fatal(err)
	}

	rcChan := make(chan *ResolvedUcred)
	go func() {
		c, err := listener.GetListener().Accept()
		if err != nil {
			t.Log(err)
			return
		}
		rc, err := RetrieveConnectionInfo(c)
		if err != nil {
			t.Log(err)
			return
		}
		rcu, ok := rc.(*ResolvedUcred)
		if !ok {
			t.Errorf("invalid return type: %T", rc)
			return
		}

		rcChan <- rcu
	}()

	go func() {
		attempts := 0
		for {
			c, err := net.Dial("unix", udsPath)
			if err == nil {
				// success! giving some time to the other thread to access the peer info
				time.Sleep(1 * time.Second)
				c.Close()
				return
			}

			attempts++
			if attempts > 3 {
				t.Log("uds connection didn't succeed")
				return
			}
			time.Sleep(1 * time.Second)
		}

	}()

	select {
	case rc := <-rcChan:
		listener.GetListener().Close()

		assessMe(t, rc)

	case <-time.After(5 * time.Second):
		listener.GetListener().Close()

		t.Fatal("no unix domain connections were received")
	}

}

type myHandler struct{}

func (h myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := r.Context().Value(PathCred).(*ResolvedUcred)
	bytes, err := json.Marshal(rc)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}

func TestUdsHttpListener(t *testing.T) {
	testdir := t.TempDir()
	udsPath := path.Join(testdir, "uds")
	listener, err := NewListener(udsPath, "0600:-:-")
	if err != nil {
		t.Fatal(err)
	}

	server := http.Server{
		Handler: myHandler{},
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
	var rc ResolvedUcred
	err = json.Unmarshal(bytes, &rc)
	if err != nil {
		t.Fatal(err)
	}

	assessMe(t, &rc)
}

type myK8sHandler struct {
	listener common.Listener
}

func (h myK8sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	re := k8sac.AdmissionRequest{}
	h.listener.PopulateUserInfo(r.Context(), &re)
	bytes, err := json.Marshal(re)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}

func TestK8sUdsHttpListener(t *testing.T) {
	testdir := t.TempDir()
	udsPath := GetSocketPath(testdir, "uds")
	listener, err := NewListener(udsPath, "0600:-:-")
	if err != nil {
		t.Fatal(err)
	}

	server := http.Server{
		Handler: myK8sHandler{listener},
	}
	err = listener.ConfigureHooks(&server)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener.GetListener())

	dialer := NewDialer(udsPath)

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return dialer.Dial()
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
	var rc k8sac.AdmissionRequest
	err = json.Unmarshal(bytes, &rc)
	if err != nil {
		t.Fatal(err)
	}

	eUID := os.Getuid()
	eUIDstr := strconv.Itoa(eUID)
	if rc.UserInfo.UID != eUIDstr {
		t.Errorf("UserInfo was not populated correctly. %v vs %v", eUIDstr, rc.UserInfo.UID)
	}
}
