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

package containers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/lookup"
	"github.com/google/ctrdac/resolver"
	"golang.org/x/exp/slices"

	cpb "github.com/containerd/containerd/v2/api/services/containers/v1"
	k8score "k8s.io/api/core/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*
capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
*/
var kubernetesDefaultCapabilities = strings.Split("cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap", ",")

func ctrdCapsToK8sCaps(ctrdCaps []string) k8score.Capabilities {
	re := k8score.Capabilities{}
	for _, ctrdCap := range ctrdCaps {

		ctrdCapLc := strings.ToLower(ctrdCap)
		presentAmongDefaults := slices.Contains(kubernetesDefaultCapabilities, ctrdCapLc)
		if !presentAmongDefaults {
			// a capability granted by ctrd is not present among the k8s default
			re.Add = append(re.Add, k8score.Capability(ctrdCapLc))
		}

	}
	for _, k8sDefCap := range kubernetesDefaultCapabilities {
		k8sDefCapUc := strings.ToUpper(k8sDefCap)
		presentAmongCtrdCaps := slices.Contains(ctrdCaps, k8sDefCapUc)
		if !presentAmongCtrdCaps {
			// a capability that k8s grants by default, is missing
			re.Drop = append(re.Drop, k8score.Capability(k8sDefCap))
		}
	}
	return re
}

// ConvertCreateContainerToPod converts a CreateContainerRequest gRPC request meant for Containerd
// into a Pod object for a K8S admission controller
func ConvertCreateContainerToPod(s common.ProxyServer, in *cpb.CreateContainerRequest) (any, error) {
	var runcSpec map[string]any
	if in == nil || in.Container.Spec == nil {
		return nil, fmt.Errorf("CreateContainerRequest is empty")
	}
	err := json.Unmarshal(in.Container.Spec.Value, &runcSpec)
	if err != nil {
		return nil, err
	}

	image := in.Container.Image
	if image == "" {
		image, err = resolveImageFromDocker(s, in.GetContainer().GetID())
		if err != nil {
			return nil, err
		}
	}

	if image == "" {
		return nil, errors.New("image is missing in the CreateContainerRequest")
	}

	command, err := lookup.ToStrSlice(lookup.Lookup[[]any](runcSpec, "process.args", nil))
	if err != nil {
		return nil, err
	}

	envStrs, err := lookup.ToStrSlice(lookup.Lookup[[]any](runcSpec, "process.env", nil))
	if err != nil {
		return nil, err
	}

	var envVars []k8score.EnvVar
	for _, p := range envStrs {
		ss := strings.SplitN(p, "=", 2)
		ev := k8score.EnvVar{
			Name:  ss[0],
			Value: ss[1],
		}
		envVars = append(envVars, ev)
	}

	var volumes []k8score.Volume
	var volumeMounts []k8score.VolumeMount
	ctrdVolumes := lookup.Lookup[[]any](runcSpec, "mounts", nil)
	for i, ctrdVolume := range ctrdVolumes {
		ctrdVolumeEntry, ok := ctrdVolume.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unable to process volumes: %v", ctrdVolume)
		}
		ctrdVolumeType := lookup.Lookup(ctrdVolumeEntry, "type", "")
		dest := lookup.Lookup(ctrdVolumeEntry, "destination", "")
		if dest == "" {
			return nil, fmt.Errorf("destination missing: %v", ctrdVolumeEntry)
		}

		var volumeSource *k8score.VolumeSource
		switch ctrdVolumeType {
		case "":
			return nil, fmt.Errorf("invalid mount, no type: %v", ctrdVolumeEntry)
		case "tmpfs":
			volumeSource = &k8score.VolumeSource{
				EmptyDir: &k8score.EmptyDirVolumeSource{},
			}
		case "bind":
			isNameResolutionEntry := false
			switch dest {
			case "/etc/resolv.conf", "/etc/hostname", "/etc/hosts":
				// kubernetes does not include these entries
				isNameResolutionEntry = true
			}
			if isNameResolutionEntry {
				continue
			}

			src := lookup.Lookup(ctrdVolumeEntry, "source", "")
			if src == "" {
				return nil, fmt.Errorf("source attribute missing from bind mount: %v", ctrdVolumeEntry)
			}
			volumeSource = &k8score.VolumeSource{
				HostPath: &k8score.HostPathVolumeSource{
					Path: src,
				},
			}
		case "proc", "devpts", "sysfs", "cgroup", "mqueue":
			continue
		default:
			return nil, fmt.Errorf("unsupported mount type: %v", ctrdVolumeType)
		}

		/*
			// the linter claims this is never met
			if volumeSource == nil {
				continue
			}
		*/

		volname := fmt.Sprintf("vol%d", i)
		volumes = append(volumes, k8score.Volume{
			Name:         volname,
			VolumeSource: *volumeSource,
		})
		volumeMounts = append(volumeMounts, k8score.VolumeMount{
			Name: volname,
			// TODO: infer ReadOnly
			MountPath: dest,
			// TODO: infer MountPropagation (options may contain rbind or rprivate)
		})
	}

	hostNsNetwork := false
	hostNsPid := false
	hostNsIPC := false
	for _, ns := range lookup.Lookup[[]any](runcSpec, "linux.namespaces", nil) {
		nsMap, ok := ns.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid namespaces entry: %+v", ns)
		}
		path := lookup.Lookup(nsMap, "path", "")
		// TODO: this is probably not enough to distinguish between host namespace usage vs shared namespace usage among containers.
		if path == "" {
			// dedicated
			continue
		}
		nsType := lookup.Lookup(nsMap, "type", "")
		switch nsType {
		case "network":
			hostNsNetwork = true
		case "pid":
			hostNsPid = true
		case "ipc":
			hostNsIPC = true
		}
	}

	ctrdCaps, err := lookup.ToStrSlice(lookup.Lookup[[]any](runcSpec, "process.capabilities.effective", nil))
	if err != nil {
		return nil, err
	}

	k8sCaps := ctrdCapsToK8sCaps(ctrdCaps)

	runAsUser := int64(lookup.Lookup(runcSpec, "process.user.uid", float64(0)))
	runAsGroup := int64(lookup.Lookup(runcSpec, "process.user.gid", float64(0)))
	runAsNonRoot := runAsUser != 0
	privileged := slices.Contains(ctrdCaps, "CAP_SYS_ADMIN") // may be not the most accurate way to detect this

	respec := k8score.PodSpec{
		Volumes: volumes,
		Containers: []k8score.Container{
			k8score.Container{
				Name:         in.GetContainer().GetID(),
				Image:        image,
				Command:      command,
				Args:         []string{},
				WorkingDir:   lookup.Lookup(runcSpec, "process.cwd", "/"),
				TTY:          lookup.Lookup(runcSpec, "process.terminal", false),
				Env:          envVars,
				VolumeMounts: volumeMounts,

				// further todo
				// Ports may not be possible as that is handled at docker level - we may need to call back if it is important
				// SecurityContext
				SecurityContext: &k8score.SecurityContext{
					RunAsUser:    &runAsUser,
					RunAsGroup:   &runAsGroup,
					RunAsNonRoot: &runAsNonRoot,
					Privileged:   &privileged,
					Capabilities: &k8sCaps,
				},
			},
		},
		HostNetwork: hostNsNetwork,
		HostPID:     hostNsPid,
		HostIPC:     hostNsIPC,
	}
	re := k8score.Pod{
		TypeMeta: k8smeta.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Spec: respec,
	}
	return re, nil
}

// PatchCreateContainer patches the original ctrd Create request based on the modified Pod specification
// this is limited for now to the following:
// - image of the container
// - command/args of the container
// TODO: decide to rather return an error instead
func PatchCreateContainer(s common.ProxyServer, in *cpb.CreateContainerRequest, modifiedPod []byte) error {
	var pod k8score.Pod
	err := json.Unmarshal(modifiedPod, &pod)
	if err != nil {
		return err
	}

	if len(pod.Spec.Containers) != 1 {
		return fmt.Errorf("invalid number of containers in the patched pod specification")
	}

	in.Container.Image = pod.Spec.Containers[0].Image

	var runcSpec map[string]any
	err = json.Unmarshal(in.Container.Spec.Value, &runcSpec)
	if err != nil {
		return err
	}

	newArgs := append(pod.Spec.Containers[0].Command, pod.Spec.Containers[0].Args...)
	err = lookup.Patch(runcSpec, "process.args", newArgs)
	if err != nil {
		return nil
	}

	rebuiltRuncSpec, err := json.Marshal(runcSpec)
	if err != nil {
		return err
	}
	in.Container.Spec.Value = rebuiltRuncSpec

	return nil
}

var resolveImageFromDocker = func(s common.ProxyServer, containerID string) (string, error) {
	// now trying to look it up from docker
	dsocket := s.GetConfig().DockerSocket
	if dsocket != "" {
		r := resolver.New(dsocket)
		aImage, err := r.Resolve(containerID)
		if err != nil {
			return "", fmt.Errorf("unable to resolve image from docker: %v", err)
		}

		return aImage, nil
	}
	return "", fmt.Errorf("image not present in create container request: %v", containerID)
}
