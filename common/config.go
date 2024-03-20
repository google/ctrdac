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

package common

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// ConfigPathListener holds the settings for an UDS listener
type ConfigPathListener struct {
	SocketPath string `yaml:"socketPath"`
	Params     string // according to pathListener's documentation
}

// ConfigMtlsListener holds the settings for an mTLS listener
type ConfigMtlsListener struct {
	PrivateKeyPath  string `yaml:"privateKeyPath"`
	CertificatePath string `yaml:"certificatePath"`
	ClientCAsPath   string `yaml:"clientCAsPath"`
	ListenOn        string `yaml:"listenOn"` // e.g. ":8080"
}

// ConfigTLSListener holds the settings for a TLS listener
// If acjs is meant to be used in a cluster-local setup, you can generate a CA cert and load it with
// this listener, like this:
// ```
// openssl req -x509 -sha256 -new -nodes -newkey rsa:2048 -keyout ca_acjs.key -days 14600 -out ca_acjs.pem -subj "/C=NL/ST=Zuid Holland/L=Rotterdam/O=ACME Corp/OU=IT Dept/CN=Acjs" -addext "subjectAltName = DNS:acjs-svc.my-namespace.svc.cluster.local"
// ```
type ConfigTLSListener struct {
	PrivateKeyPath  string `yaml:"privateKeyPath"`
	CertificatePath string `yaml:"certificatePath"`
	ListenOn        string `yaml:"listenOn"` // e.g. ":8080"
}

// ConfigPolicy represents a policy to be evaluated and make authz decisions based on
type ConfigPolicy struct {
	Name string
	Code string
}

// ConfigListener represents the listener options for acjs
type ConfigListener struct {
	Path *ConfigPathListener
	Mtls *ConfigMtlsListener
	TLS  *ConfigTLSListener `yaml:"tls"`
}

// ConfigFile type represents the configuration for acjs
type ConfigFile struct {
	Listener *ConfigListener

	Globals  string
	Policies []ConfigPolicy

	DefaultAction string `yaml:"defaultAction"`
}

// ReadConfigFile parses the specified file into a ConfigFile structure
func ReadConfigFile(filename string) (*ConfigFile, error) {
	f, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %v", err)
	}

	var c ConfigFile

	// Unmarshal our input YAML file into empty Car (var c)
	if err := yaml.Unmarshal(f, &c); err != nil {
		return nil, fmt.Errorf("unable to parse config file %s: %v", filename, err)
	}
	// fmt.Printf("%+v", c.Proxy.Listener.UDS)

	return &c, nil
}
