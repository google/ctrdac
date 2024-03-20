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

package main

import (
	"strings"

	"flag"
)

type arrayFlags []string

var (
	validatingWebhooks  arrayFlags
	mutatingWebhooks    arrayFlags
	noK8sConversion     = flag.Bool("no-k8s-conversion", false, "By default, ctrdac converts the containerd payload to the closest compatible K8s resource definition (e.g. to a Pod/PodSpec). When no-k8s-conversion is activated, the raw containerd request will be assigned as the Object of the AdmissionRequest.")
	proxyListenerParams = flag.String("proxy-listener-params", "", "Parameters of the path listener.")
	dockerSocket        = flag.String("docker-socket", "/run/docker.sock", "UDS socket of docker (may be needed for image digest lookups)")
)

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Get() any {
	return i
}
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func init() {
	flag.Var(&validatingWebhooks, "validating-webhook", "Validating webhook Admission controller(s) to inspect the requests")
	flag.Var(&mutatingWebhooks, "mutating-webhook", "Mutating webhook Admission controller(s) to inspect/modify the requests")
	flag.Set("alsologtostderr", "true")
}
