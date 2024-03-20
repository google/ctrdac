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

// Package main is the cli of the ctrdac application.
package main

import (
	"os"

	"flag"
	log "github.com/golang/glog"
	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/containerd"
)

func main() {
	if !flag.Parsed() {
		flag.Parse()
	}
	if len(validatingWebhooks) == 0 && len(mutatingWebhooks) == 0 {
		log.Infof("You must specify at least one webhook.")
		flag.Usage()
		os.Exit(1)
		return
	}

	proxyServerConfig := common.ProxyServerConfig{
		*proxyListenerSocket, *proxyListenerParams, *upstreamContainerdSocket, *dockerSocket, validatingWebhooks, mutatingWebhooks, *noK8sConversion,
	}
	proxy := containerd.NewProxyServer(proxyServerConfig)

	err := proxy.Serve()
	if err != nil {
		log.Infof("proxy server returned an error: %v", err)
	}
}
