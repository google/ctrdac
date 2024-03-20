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

package authz

import (
	"path"
	"testing"

	"github.com/google/acjs/common"
	"github.com/google/ctrdac/http"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	k8sac "k8s.io/api/admission/v1"
)

func TestEnd2End(t *testing.T) {
	tempdir := t.TempDir()
	udsPath := path.Join(tempdir, "acjs.sock")
	config := &common.ConfigFile{
		Listener: &common.ConfigListener{
			Path: &common.ConfigPathListener{
				SocketPath: udsPath,
			},
		},
		Policies: []common.ConfigPolicy{
			{
				Name: "logging",
				Code: `
				console.log("hello!", ac.User.Username, "x", req.UID, "x", object)
				`,
			},
			{
				Name: "some name of the policy",
				Code: `
				return "rejection: "+req.UID+" "+object.foo+" "+ac.HTTPRequest.Header.Get("Accept-Encoding")
				`,
			},
		},
		DefaultAction: "Allow",
	}
	cp, err := CompilePolicies(config)
	if err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	server.UsePolicies(cp)
	go server.Serve()

	uid := "deadbeef"
	areview := k8sac.AdmissionReview{
		Request: &k8sac.AdmissionRequest{
			UID: types.UID(uid),
			Object: runtime.RawExtension{
				Raw: []byte(`{"foo":"bar"}`),
			},
		},
	}
	re, err := http.Post[k8sac.AdmissionReview](udsPath, areview, nil)
	if err != nil {
		t.Fatal(err)
	}
	if re.Response.Allowed {
		t.Errorf("should have been rejected")
	}
	eMessage := "some name of the policy: rejection: " + uid + " bar gzip"
	if re.Response.Result.Message != eMessage {
		t.Errorf("unexpeceted rejection message: %v vs %v", re.Response.Result.Message, eMessage)
	}
}
