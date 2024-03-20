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

// Package main is the cli of the acjs application.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"flag"
	log "github.com/golang/glog"
	"github.com/google/acjs/authz"
	"github.com/google/acjs/common"
)

var (
	server common.AuthzServer
)

func reReadConfigFile(configFilePath string) (*common.ConfigFile, *authz.CompiledPolicies, error) {
	config, err := common.ReadConfigFile(configFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the config file failed: %v", err)
	}
	cp, err := authz.CompilePolicies(config)
	if err != nil {
		return nil, nil, fmt.Errorf("compiling policies failed: %v", err)
	}

	return config, cp, nil
}

func main() {
	if !flag.Parsed() {
		flag.Parse()
	}

	config, policies, err := reReadConfigFile(*configFilePath)
	if err != nil {
		log.Info(err)
		return
	}

	server, err = authz.NewServer(config)
	if err != nil {
		log.Infof("Unable to start the server: %v", err)
		return
	}
	server.UsePolicies(policies)

	/*
		signal handler for HUP
	*/
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		<-c
		_, policies, err := reReadConfigFile(*configFilePath)
		if err != nil {
			log.Errorf("Unable to reread configuration: %v", err)
			server.UsePolicies(policies)
		}
	}()

	err = server.Serve()
	if err != nil {
		log.Errorf("Failed serving on server: %v", err)
	}
}
