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

package slsa

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
)

var cloudbuildYaml = []byte(`
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: [ 'build', '-t', 'us-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image:v41', '.' ]
images: [ 'us-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image:v41' ]
options:
  requestedVerifyOption: VERIFIED
`)

func TestGetImageRefWithoutTags(t *testing.T) {
	testCases := map[string]string{
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529": "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529":         "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag":                                                                         "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image",
	}
	for input, expected := range testCases {
		actual := GetImageRefWithoutTags(input)
		if actual != expected {
			t.Errorf("GetImageRefWithoutTags(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestIsImageMatch(t *testing.T) {
	matchingPairs := map[string]string{
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529": "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag":                                                                         "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag2":                                                                        "us-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image",
	}
	for v1, v2 := range matchingPairs {
		if !IsImageMatch(v1, v2) {
			t.Errorf("IsImageMatch(%q, %q) did not match", v1, v2)
		}
	}
}

func TestIsImageMismatch(t *testing.T) {
	mismatchingPairs := map[string]string{
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag1": "us-west2-docker.pkg.dev/xxximre-test/quickstart-docker-repo/quickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag2": "us-west2-docker.pkg.dev/imre-test/xxxquickstart-docker-repo/quickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag3": "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/xxxquickstart-image",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag4": "xx-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image",
	}
	for v1, v2 := range mismatchingPairs {
		if IsImageMatch(v1, v2) {
			t.Errorf("IsImageMatch(%q, %q) should not match", v1, v2)
		}
	}
}

func TestFindMatchingRepos(t *testing.T) {
	repos := []*Repo{
		{Images: []string{"xx-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image"}},
		{Images: []string{"us-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image"}},
	}
	frepos := FindMatchingRepos("us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag", repos)
	if len(frepos) != 1 {
		t.Fatalf("unexpected number of FindMatchingRepos matches: %d", len(frepos))
	}
	if frepos[0].Images[0] != "us-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image" {
		t.Errorf("FindMatchingRepos did not return the expected repo")
	}
}

func TestGithubUrl(t *testing.T) {
	eURL := "https://raw.githubusercontent.com/imre/test/main/cloudbuild.yaml"
	aURL := githubURLProducer("imre/test", "cloudbuild.yaml")
	if aURL != eURL {
		t.Errorf("githubURLProducer: got %v wanted %v", aURL, eURL)
	}
}

type mockedClient struct{}

func (m mockedClient) Get(url string) (*http.Response, error) {
	switch url {
	case "https://raw.githubusercontent.com/irsl/gcb-tests/main/cloudbuild.yaml":
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(cloudbuildYaml))}, nil
	default:
		return nil, fmt.Errorf("unexpected url: %v", url)
	}
}

func TestResolver(t *testing.T) {

	inputRepo := "github.com/irsl/gcb-tests"

	rr := RepoResolver{}
	rr.client = mockedClient{}
	repos, err := rr.Resolve(inputRepo)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 {
		t.Fatalf("unexpected number of repos: %d", len(repos))
	}
	if repos[0].BuilderID != BuilderIDGoogleCloudBuild {
		t.Errorf("should be cloud build: %v vs %v", repos[0].BuilderID, BuilderIDGoogleCloudBuild)
	}
	expectedImages := []string{"us-west2-docker.pkg.dev/$PROJECT_ID/quickstart-docker-repo/quickstart-image"}
	if !reflect.DeepEqual(repos[0].Images, expectedImages) {
		t.Errorf("images incorrect: %v vs %v", repos[0].Images, expectedImages)
	}
	if repos[0].Repo != inputRepo {
		t.Errorf("repo invalid: %v vs %v", repos[0].Repo, inputRepo)
	}
}
