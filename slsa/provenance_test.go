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
	"fmt"
	"testing"
)

func TestObtainProvenance(t *testing.T) {
	inputImage := "mocked-unit-tests.tld/some/image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529"

	mockedPlatformObtainProvenance := func(fullyQalifiedImage string) ([]byte, error) {
		if fullyQalifiedImage != inputImage {
			return nil, fmt.Errorf("unexpected image ref: %v vs %v", fullyQalifiedImage, inputImage)
		}
		return []byte("hello:)"), nil
	}

	regexp := "^mocked-unit-tests\\.tld/"
	platformLookupMap[regexp] = mockedPlatformObtainProvenance
	defer delete(platformLookupMap, regexp)
	re, err := ObtainProvenance(inputImage)
	if err != nil {
		t.Fatal(err)
	}
	sre := string(re)
	ere := "hello:)"
	if sre != ere {
		t.Errorf("unexpected response from ObtainProvenance: %v vs %v", sre, ere)
	}
}
