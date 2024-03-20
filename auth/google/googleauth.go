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

// Package google provides authentication related helper methods for ctrdac/acjs.
package google

import (
	"context"

	auth "golang.org/x/oauth2/google"
)

// GetAccessToken obtains an access token using the standard Google Oauth SDK.
func GetAccessToken() (string, error) {
	ctx := context.Background()
	scopes := []string{
		"https://www.googleapis.com/auth/cloud-platform",
	}
	credentials, err := findDefaultCredentials(ctx, scopes...)
	if err != nil {
		return "", err
	}

	token, err := credentials.TokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

var findDefaultCredentials = auth.FindDefaultCredentials
