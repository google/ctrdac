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

// Package http provides helper functions to send JSON POST requests to either some HTTPS apis
// or to a unix domain socket.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/ctrdac/auth/google"
	"github.com/google/ctrdac/pathsocket"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Post sends a json POST request to the url specified. It supports both the standard TCP channel
// (when the url begins with https://...) and local unix domain sockets as well (when url is a
// file path - beginning with a slash).
func Post[RE any](url string, body any, headers map[string]string) (RE, error) {

	client := http.Client{
		Timeout: 30 * time.Second,
	}
	if strings.HasPrefix(url, "/") || strings.HasPrefix(url, `\`) {
		socketPath := url
		dialer := pathsocket.NewDialer(socketPath)
		client.Transport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return dialer.Dial()
			},
		}

		url = "http://unix/"
	}
	return postImpl[RE](&client, url, body, headers)
}

func postImpl[RE any](httpClient httpDoer, targetURL string, body any, headers map[string]string) (RE, error) {
	var errout RE
	requestBody, err := json.Marshal(body)
	if err != nil {
		return errout, err
	}

	bodyReader := bytes.NewReader(requestBody)
	req, err := http.NewRequest(http.MethodPost, targetURL, bodyReader)
	if err != nil {
		return errout, err
	}
	req.Header.Set("Content-Type", "application/json")
	u, err := url.Parse(targetURL)
	if err != nil {
		return errout, err
	}
	if strings.HasSuffix(u.Host, ".googleapis.com") {
		token, err := getGoogleAuthToken()
		if err != nil {
			return errout, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return errout, err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errout, err
	}

	if resp.StatusCode/100 != 2 {
		return errout, fmt.Errorf("statuscode of the response indicates failure: %d: %s", resp.StatusCode, string(respBody))
	}

	var re RE
	err = json.Unmarshal(respBody, &re)
	if err != nil {
		return errout, err
	}

	return re, nil
}

var getGoogleAuthToken = func() (string, error) {
	return google.GetAccessToken()
}
