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
	"encoding/json"
	"io"

	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/ctrdac/auth/google"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func extractGcpProjectFromImageRef(imageRef string) string {
	cs := strings.SplitN(imageRef, "/", 3)
	return cs[1]
}

func getImageHash(fullyQualifiedDigest string) string {
	cs := strings.SplitN(fullyQualifiedDigest, "@", 2)
	if len(cs) == 1 {
		// it was not fully qualified after all...
		return ""
	}
	return cs[1]
}

// GcpImageSummary contains info about a container image
type GcpImageSummary struct {
	Digest               string `json:"digest"`
	FullyQualifiedDigest string `json:"fully_qualified_digest"`
}

// GcpProvenanceOccourence contains info about a container image
type GcpProvenanceOccourence map[string]any

// GcpProvenanceSummary is the main type with provenance info about a container image
type GcpProvenanceSummary struct {
	Provenance []GcpProvenanceOccourence `json:"provenance"`
}

// GcpProvenance contains info about the container image along with provenance summary
type GcpProvenance struct {
	ImageSummary      GcpImageSummary      `json:"image_summary"`
	ProvenanceSummary GcpProvenanceSummary `json:"provenance_summary"`
}

// GcpRawProvenanceOccourencesResponse is the type that holds the response of the containeranalysis API
type GcpRawProvenanceOccourencesResponse struct {
	Occourances []GcpProvenanceOccourence `json:"occurrences"`
}

// ObtainGoogleCloudProvenance obtains SLSA provenance info about a container image that was built
// on Google Cloud.
func ObtainGoogleCloudProvenance(fullyQualifiedDigest string) ([]byte, error) {
	hashOnly := getImageHash(fullyQualifiedDigest)
	if hashOnly == "" {
		return nil, fmt.Errorf("immutable image specification is expected, %s is not", fullyQualifiedDigest)
	}

	imageWithoutTagsAndHash := GetImageRefWithoutTags(fullyQualifiedDigest)
	rebuiltFullyQualifiedDigest := imageWithoutTagsAndHash + "@" + hashOnly

	token, err := getGoogleAccessToken()
	if err != nil {
		return nil, err
	}

	projectID := extractGcpProjectFromImageRef(fullyQualifiedDigest)
	filter := `((kind = "BUILD") OR (kind = "DSSE_ATTESTATION")) AND (resourceUrl = "https://` + rebuiltFullyQualifiedDigest + `")`

	requestURL := fmt.Sprintf("https://containeranalysis.googleapis.com/v1/projects/%s/occurrences?alt=json&filter=%s&pageSize=10", url.QueryEscape(projectID), url.QueryEscape(filter))
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("client: could not create request: %v", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	httpDoer := getHTTPDoer()
	res, err := httpDoer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: error making http request: %v", err)
	}
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read the response: %v", err)
	}

	var ocs GcpRawProvenanceOccourencesResponse
	err = json.Unmarshal(bytes, &ocs)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the response: %v", err)
	}

	hTime := ""
	var prov *GcpProvenanceOccourence
	for _, o := range ocs.Occourances {
		ct, ok := o["createTime"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid response, creationTime not present")
		}
		if hTime == "" || hTime < ct {
			hTime = ct
			prov = &o
		}
	}

	if prov == nil {
		return nil, errors.New("no provenance occourances")
	}

	re := GcpProvenance{
		ImageSummary: GcpImageSummary{
			Digest:               hashOnly,
			FullyQualifiedDigest: rebuiltFullyQualifiedDigest,
		},
		ProvenanceSummary: GcpProvenanceSummary{
			Provenance: []GcpProvenanceOccourence{
				*prov,
			},
		},
	}

	bytes, err = json.Marshal(re)
	if err != nil {
		return nil, err
	}
	// log.Printf("latest prov: %s", string(bytes))

	return bytes, nil
}

var getGoogleAccessToken = func() (string, error) { return google.GetAccessToken() }
var getHTTPDoer = func() httpDoer { return http.DefaultClient }
