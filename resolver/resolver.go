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

// Package resolver is a lightweight tool that allows fetching info about docker containers and
// images.
package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
)

const (
	// DefaultDockerUnixSocket is a helper constant pointing to the default path of the docker socket
	DefaultDockerUnixSocket = "/run/docker.sock"
	dockerAPIVersion        = "v1.41"
)

type httpGetter interface {
	Get(string) (*http.Response, error)
}

// Resolver is a lightweight tool that allows fetching info about docker containers and images
type Resolver struct {
	client httpGetter
}

// New creates a new resolver
func New(dockerSocket string) Resolver {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", dockerSocket)
			},
		},
	}
	return Resolver{&client}
}

// Resolve resolves a docker container ID into its RepoDigest or RepoTag.
// Shortcut to calling ResolveContainer + ResolveImage along with some fallback logic.
func (r Resolver) Resolve(containerID string) (string, error) {
	a, e := r.ResolveContainer(containerID)
	if e != nil {
		return "", e
	}
	as, e := r.ResolveImage(a)
	if e != nil {
		return "", e
	}
	if len(as) < 1 {
		// We were unable to obtain more info about the image, let's fall back to the Image reference
		// coming from the container info.
		return a, nil
	}
	return as[0], nil
}

// ResolveContainer resolves a docker container ID that is just being created by docker
// into the corresponding image name.
// It returns an empty string without error if cannot be found
func (r Resolver) ResolveContainer(containerID string) (string, error) {

	resp, err := r.client.Get("http://unix/" + dockerAPIVersion + "/containers/json?all=1")
	if err != nil {
		return "", fmt.Errorf("listing containers failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read the response body: %v", err)
	}

	var entries []map[string]any
	err = json.Unmarshal(body, &entries)
	if err != nil {
		return "", fmt.Errorf("unable to unmarhsal the response of container resolution: %v", err)
	}

	for _, e := range entries {
		aID, ok := e["Id"].(string)
		if !ok || aID != containerID {
			continue
		}

		aImage, ok := e["Image"].(string)
		if !ok {
			return "", errors.New("field Image is not a string")
		}

		return aImage, nil
	}

	return "", nil
}

// ResolveImage resolves a docker image name (e.g. "alpine:latest") into its
// RepoDigest(s)/RepoTag(s).
func (r Resolver) ResolveImage(imageName string) ([]string, error) {

	uri := fmt.Sprintf("http://unix/"+dockerAPIVersion+"/images/%s/json", url.QueryEscape(imageName))
	resp, err := r.client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("inspecting image failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read the response body: %v", err)
	}

	var props map[string]any
	err = json.Unmarshal(body, &props)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarhsal the response of image lookup: %v", err)
	}

	rd := props["RepoDigests"]
	repoDigests, ok := rd.([]any)
	if !ok {
		return nil, fmt.Errorf("field RepoDigests has invalid Type: %T", rd)
	}
	rt := props["RepoTags"]
	repoTags, ok := rt.([]any)
	if !ok {
		return nil, fmt.Errorf("field RepoTags has invalid Type: %T", rd)
	}

	var re []string

	for _, rde := range append(repoDigests, repoTags...) {
		rdv, ok := rde.(string)
		if !ok {
			return nil, fmt.Errorf("entry %+v has invalid Type: %T", rde, rde)
		}
		re = append(re, rdv)
	}

	return re, nil
}
