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
	"io"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReadConfigFile(t *testing.T) {
	tempdir := t.TempDir()
	configFilePath := path.Join(tempdir, "config.yaml")
	f, err := os.Create(configFilePath)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(f, `
listener:
  path:
    socketPath: /tmp/acjs.sock
    params: 0660:-:-
  mtls:
    privateKeyPath: /priv
    certificatePath: /cert
    clientCAsPath: /cas
    listenOn: ":8080"

globals: |
  hello

policies:
- name: some name of the policy
  code: |
    console.log("hello!", ac.User.Username, "x", req.UID, "x", object)

defaultAction: Allow
  `)
	f.Close()

	c, err := ReadConfigFile(configFilePath)
	if err != nil {
		t.Fatal(err)
	}

	e := &ConfigFile{
		Listener: &ConfigListener{
			Path: &ConfigPathListener{
				SocketPath: "/tmp/acjs.sock",
				Params:     "0660:-:-",
			},
			Mtls: &ConfigMtlsListener{
				PrivateKeyPath:  "/priv",
				CertificatePath: "/cert",
				ClientCAsPath:   "/cas",
				ListenOn:        ":8080",
			},
		},
		Globals: "hello\n",
		Policies: []ConfigPolicy{
			{Name: "some name of the policy", Code: `console.log("hello!", ac.User.Username, "x", req.UID, "x", object)` + "\n"},
		},
		DefaultAction: "Allow",
	}

	diff := cmp.Diff(c, e)
	if diff != "" {
		t.Errorf("config file was not parsed as expected: %v", diff)
	}

}
