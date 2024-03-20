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

package resolver

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type mockedGetter struct{}

var dockerResponses = map[string]string{
	"http://unix/v1.41/containers/json?all=1": `[  {
    "Id": "deadbeef",
    "Names": [
      "/sweet_jemison"
    ],
    "Image": "alpine",
    "ImageID": "sha256:b2aa39c304c27b96c1fef0c06bee651ac9241d49c4fe34381cab8453f9a89c7d",
    "Command": "echo done",
    "Created": 1676895246,
    "Ports": [],
    "Labels": {},
    "State": "created",
    "Status": "Created",
    "HostConfig": {
      "NetworkMode": "default"
    },
    "NetworkSettings": {
      "Networks": {"bridge": {
          "IPAMConfig": null,
          "Links": null,
          "Aliases": null,
          "NetworkID": "",
          "EndpointID": "",
          "Gateway": "",
          "IPAddress": "",
          "IPPrefixLen": 0,
          "IPv6Gateway": "",
          "GlobalIPv6Address": "",
          "GlobalIPv6PrefixLen": 0,
          "MacAddress": "",
          "DriverOpts": null
        }
      }
    },
    "Mounts": []
  }
]`,
	"http://unix/v1.41/images/alpine/json": `{"Id":"sha256:042a816809aac8d0f7d7cacac7965782ee2ecac3f21bcf9f24b1de1a7387b769","RepoTags":["alpine:latest"],"RepoDigests":["alpine@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"],"Parent":"","Comment":"","Created":"2023-01-09T17:05:20.656498283Z","Container":"d4d39cab50d7e505e946044f9131e99602e21f02d0137599e85a70c0b2b7cd15","ContainerConfig":{"Hostname":"d4d39cab50d7","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"Image":"sha256:7fdd9d695f58803dd6ee7b1b8135122acedeb3817964d644b65995698b438002","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"DockerVersion":"20.10.12","Author":"","Config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"Image":"sha256:7fdd9d695f58803dd6ee7b1b8135122acedeb3817964d644b65995698b438002","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"Architecture":"amd64","Os":"linux","Size":7049701,"VirtualSize":7049701,"GraphDriver":{"Data":{"MergedDir":"/usr/local/google/docker/overlay2/c01d8f2efac13ee747c44841b2fb627baf76e691d5aa443b70382be6b195cf9f/merged","UpperDir":"/usr/local/google/docker/overlay2/c01d8f2efac13ee747c44841b2fb627baf76e691d5aa443b70382be6b195cf9f/diff","WorkDir":"/usr/local/google/docker/overlay2/c01d8f2efac13ee747c44841b2fb627baf76e691d5aa443b70382be6b195cf9f/work"},"Name":"overlay2"},"RootFS":{"Type":"layers","Layers":["sha256:8e012198eea15b2554b07014081c85fec4967a1b9cc4b65bd9a4bce3ae1c0c88"]},"Metadata":{"LastTagTime":"0001-01-01T00:00:00Z"}}`,
}

func (m mockedGetter) Get(url string) (*http.Response, error) {
	resp := dockerResponses[url]

	if resp == "" {
		return nil, fmt.Errorf("unknown url: %v", url)
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(resp))}, nil
}

func TestResolver(t *testing.T) {
	mockedGetter := mockedGetter{}
	expectedImageID := "alpine@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"
	containerID := "deadbeef"
	resolver := Resolver{client: mockedGetter}
	id, err := resolver.Resolve(containerID)
	if err != nil {
		t.Fatal(err)
	}
	if id != expectedImageID {
		t.Errorf("expected image ID: %v, got instead: %v", expectedImageID, id)
	}
}
