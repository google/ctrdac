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

package google

import (
	"context"
	"errors"
	"testing"

	auth "golang.org/x/oauth2/google"
	"golang.org/x/oauth2"
)

func TestGetAccessTokenSuccess(t *testing.T) {
	want := "ya.hello"

	origFindDefaultCredentials := findDefaultCredentials
	findDefaultCredentials = func(ctx context.Context, scopes ...string) (*auth.Credentials, error) {
		return &auth.Credentials{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: want}),
		}, nil
	}
	defer func() {
		findDefaultCredentials = origFindDefaultCredentials
	}()

	at, err := GetAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if at != want {
		t.Errorf("GetAccessToken() = %v, want: %v", at, want)
	}
}

func TestGetAccessTokenFailure(t *testing.T) {
	want := "it wont work"
	origFindDefaultCredentials := findDefaultCredentials
	findDefaultCredentials = func(ctx context.Context, scopes ...string) (*auth.Credentials, error) {
		return nil, errors.New(want)
	}
	defer func() {
		findDefaultCredentials = origFindDefaultCredentials
	}()

	at, err := GetAccessToken()
	if at != "" || err == nil {
		t.Fatalf("GetAccessToken() = %v, want: \"\"", at)
	}
	if err.Error() != want {
		t.Errorf("GetAccessToken() threw %v, want: %v", err, want)
	}
}
