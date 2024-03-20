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

// Package slsa provides functions to resolve SLSA related info about code repositories and to
// obtain SLSA provenance information about images.
package slsa

import (
	"fmt"
	"regexp"
)

type platformResolver func(string) ([]byte, error)

// registry about the supported platforms where we can automatically obtain provenance info from.
var platformLookupMap = map[string]platformResolver{
	"^([a-z0-9-]+-)?docker.pkg.dev/": ObtainGoogleCloudProvenance,
}

func findPlatform(fullyQualifiedDigest string) platformResolver {
	for platformRegexp, resolver := range platformLookupMap {
		match, err := regexp.MatchString(platformRegexp, fullyQualifiedDigest)
		if err != nil {
			// the regexes are always hard coded above, so no errors are ever expected
			continue
		}

		if match {
			return resolver
		}
	}
	return nil
}

func obtainProvenance(fullyQualifiedDigest string) ([]byte, error) {
	resolver := findPlatform(fullyQualifiedDigest)
	if resolver == nil {
		return nil, fmt.Errorf("automatically obtaining provenance for image %s is not supported", fullyQualifiedDigest)
	}

	return resolver(fullyQualifiedDigest)
}

// ObtainProvenance obtains SLSA provenance info about the specified container image.
// The image reference is expected to be fully qualified (along with the sha hash).
func ObtainProvenance(fullyQualifiedDigest string) ([]byte, error) {
	// TODO(imrer): add caching
	return obtainProvenance(fullyQualifiedDigest)
}
