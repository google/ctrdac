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

package authz

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/acjs/common"

	k8sac "k8s.io/api/admission/v1"
)

// AdmissionControllerServer is the root type of an acjs server instance
type AdmissionControllerServer struct {
	policies common.CompiledPolicies
	listener common.Listener
}

// UsePolicies can swap the policies on the fly for a running acjs instance. This can be useful
// e.g. at SIGHUP.
func (pl *AdmissionControllerServer) UsePolicies(cp common.CompiledPolicies) {
	pl.policies = cp
}

func (pl *AdmissionControllerServer) handleRequest(w http.ResponseWriter, r *http.Request) error {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var areq k8sac.AdmissionReview
	err = json.Unmarshal(bodyBytes, &areq)
	if err != nil {
		return err
	}

	az := common.AdmissionControllerRequest{}
	az.HTTPRequest = r
	az.Timestamp = time.Now().Format(time.RFC3339)
	err = pl.listener.PopulateRequest(&az, r)
	if err != nil {
		return err
	}

	aresp := pl.policies.Evaluate(&az, areq.Request)

	ar := k8sac.AdmissionReview{
		TypeMeta: areq.TypeMeta,
		Response: aresp,
	}

	respBytes, err := json.Marshal(&ar)
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)

	return nil
}

// Serve starts accepting and serving requests. It returns an error immediately if it is unable to.
func (pl *AdmissionControllerServer) Serve() error {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := pl.handleRequest(w, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

	})
	s := http.Server{}
	s.Handler = handler
	if err := pl.listener.ConfigureHooks(&s); err != nil {
		return err
	}
	return s.Serve(pl.listener.GetListener())
}

// NewServer creates a new acjs server instance based on the configuration provided.
// It returns a common.AuthzServer interface.
func NewServer(c *common.ConfigFile) (common.AuthzServer, error) {

	listeners := 0
	if c.Listener != nil {
		if c.Listener.Mtls != nil {
			listeners++
		}
		if c.Listener.TLS != nil {
			listeners++
		}
		if c.Listener.Path != nil {
			listeners++
		}
	}
	if listeners > 1 {
		return nil, errors.New("only one listener can be configured")
	}

	var err error
	var listener common.Listener
	switch {
	case c.Listener.TLS != nil:
		listener, err = common.NewTLSListener(c.Listener.TLS)
	case c.Listener.Mtls != nil:
		listener, err = common.NewMtlsListener(c.Listener.Mtls)
	case c.Listener.Path != nil:
		listener, err = common.NewPathListener(c.Listener.Path)
	}

	if err != nil {
		return nil, err
	}

	return &AdmissionControllerServer{
		listener: listener,
	}, nil
}
