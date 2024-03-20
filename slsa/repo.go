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
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/ctrdac/lookup"
	"gopkg.in/yaml.v2"
)

const (
	// BuilderIDGoogleCloudBuild is the ID slsa-verifier expects for the Cloud Build builder
	BuilderIDGoogleCloudBuild = "https://cloudbuild.googleapis.com/GoogleHostedWorker"

	maxBytesToRead = 100 * 1024 // 100kbyte
)

type httpGetter interface {
	Get(string) (*http.Response, error)
}

// RepoResolver is the type that features resolving SLSA info for a repository
type RepoResolver struct {
	client httpGetter
}

// Repo contains SLSA related info about a code repository
type Repo struct {
	BuilderID string
	Images    []string
	Repo      string
}

// fetchURL is a helper function to slurp a url to bytes. Read is limited to maxBytesToRead.
func (s RepoResolver) fetchURL(url string) ([]byte, error) {
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	limitedReader := &io.LimitedReader{R: resp.Body, N: maxBytesToRead}
	return io.ReadAll(limitedReader)
}

func githubURLProducer(repo string, file string) string {
	// https://raw.githubusercontent.com/irsl/gcb-tests/main/cloudbuild.yaml
	// repo is just the repo under github.com, like irsl/something
	return "https://raw.githubusercontent.com/" + repo + "/main/" + file
}

func (s RepoResolver) doResolveHTTPCloudBuild(cloudbuild []byte) (*Repo, error) {
	// Unmarshal our input YAML file into empty Car (var c)
	var c map[string]any
	if err := yaml.Unmarshal(cloudbuild, &c); err != nil {
		return nil, fmt.Errorf("unable to parse cloudbuild.yaml: %v", err)
	}
	// fmt.Printf("%+v", c.Proxy.Listener.UDS)

	repoImages, err := lookup.ToStrSlice(lookup.Lookup[[]any](c, "images", nil))
	if err != nil || len(repoImages) == 0 {
		return nil, errors.New("images field not present in cloudbuild.yaml")
	}
	var sImages []string
	for _, image := range repoImages {
		sImages = append(sImages, GetImageRefWithoutTags(image))
	}

	return &Repo{Images: sImages, BuilderID: BuilderIDGoogleCloudBuild}, nil
}

func (s RepoResolver) doResolveHTTP(repo string, urlProducer func(repo string, file string) string) (*Repo, error) {

	type HTTPResolver struct {
		logic func([]byte) (*Repo, error)
		files []string
	}

	for _, resolver := range []HTTPResolver{
		{
			logic: s.doResolveHTTPCloudBuild,
			files: []string{"cloudbuild.yaml", "cloudbuild.yml"},
		},
	} {
		for _, file := range resolver.files {
			url := urlProducer(repo, file)
			body, err := s.fetchURL(url)
			if err != nil {
				continue
			}

			return resolver.logic(body)
		}
	}

	return nil, errors.New("unable to parse repo")
}

func (s RepoResolver) doResolvePartially(repo string) (*Repo, error) {

	if strings.HasPrefix(repo, "github.com/") {
		cs := strings.SplitN(repo, "/", 2)

		return s.doResolveHTTP(cs[1], githubURLProducer)
	}

	return nil, errors.New("the specified repo is not supported")
}

func (s RepoResolver) doResolve(repo string) (*Repo, error) {

	as, err := s.doResolvePartially(repo)
	if err != nil {
		return nil, err
	}
	as.Repo = repo
	return as, nil
}

// ResolveRepo attempts to obtain SLSA related info about the specified code repository
func (s RepoResolver) ResolveRepo(repo string) (*Repo, error) {
	// TODO(imrer): add some caching
	r, e := s.doResolve(repo)
	if e != nil {
		return nil, fmt.Errorf("error while resolving %s: %v", repo, s)
	}
	return r, nil
}

// Resolve attempts to obtain SLSA related info about the specified code repositories
func (s RepoResolver) Resolve(repos ...string) ([]*Repo, error) {
	// TODO(imrer): add some caching
	var re []*Repo
	for _, repo := range repos {
		s, err := s.ResolveRepo(repo)
		if err != nil {
			return nil, err
		}
		re = append(re, s)
	}
	return re, nil
}

// GetImageRefWithoutTags returns the name of a container image reference without tags and hash
func GetImageRefWithoutTags(imageRef string) string {
	// an imageref may look like this:
	// us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529
	// or
	// us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529
	// or
	// us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag
	imageRefSplit := strings.SplitN(imageRef, "@", 2)
	imageRef = imageRefSplit[0]
	imageRefSplit = strings.SplitN(imageRef, ":", 2)
	return imageRefSplit[0]
}

// IsImageMatch is a helper function to compare a container image reference to a reference present
// in a code repo - this latter may have $PROJECT_ID reference inside.
func IsImageMatch(imageRef string, imageFromRepo string) bool {
	imageRef = GetImageRefWithoutTags(imageRef)

	// TODO(imrer): some nicer simple wildcard based solution
	repoPattern := strings.ReplaceAll(imageFromRepo, ".", "\\.")
	repoPattern = strings.ReplaceAll(repoPattern, "$PROJECT_ID", ".*")
	repoPattern = "^" + repoPattern + "$"
	matched, err := regexp.MatchString(repoPattern, imageRef)
	if err != nil {
		return false
	}
	return matched
}

// FindMatchingRepos filters the provided code repo slice based on the image reference.
func FindMatchingRepos(imageRef string, repos []*Repo) []*Repo {
	var re []*Repo
	for _, repo := range repos {
		for _, image := range repo.Images {
			if IsImageMatch(imageRef, image) {
				re = append(re, repo)
			}
		}
	}
	return re
}
