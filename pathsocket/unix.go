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

//go:build unix
// +build unix

package pathsocket

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/ctrdac/common"

	"golang.org/x/sys/unix"

	k8sauth "k8s.io/api/authentication/v1"
)

// ResolvedUcred is the expanded version of Ucred that features the resolved Username/Group names
// as well.
// Initialism: style is aligned with the upstream struct unix.Ucred
type ResolvedUcred struct {
	Pid      int32
	Uid      uint32
	Gid      uint32
	Username string
	Group    string
}

// NewListener creates a new unix domain socket listener
// Params is platform specific and optional (empty string is ok).
// On unix, the following parameters are supported (separated by `:`):
// - permission (filemode e.g. 0660)
// - userName (e.g. root)
// - groupName (e.g. sudoers)
// The default permission is 0600. The default userName and groupName is "-" which
// means chown is not executed (the listener inode is owned by the current process).
func NewListener(socketPath string, params string) (common.Listener, error) {
	if params == "" {
		return newUDSListener(socketPath, "0600", "-", "-")
	}
	arg := strings.Split(params, ":")
	if len(arg) == 1 {
		return newUDSListener(socketPath, arg[0], "-", "-")
	}
	if len(arg) == 3 {
		return newUDSListener(socketPath, arg[0], arg[1], arg[2])
	}
	return nil, fmt.Errorf("invalid number of parameters: %d", len(arg))
}

func newUDSListener(socketPath, permission, userName, groupName string) (*listenerImpl, error) {
	if socketPath == "" {
		return nil, errors.New("unix socket is not configured for proxy listener")
	}
	if permission == "" {
		return nil, errors.New("permission of the UDS listener is not configured")
	}
	if userName == "" {
		return nil, errors.New("user of the UDS listener is not configured")
	}
	if groupName == "" {
		return nil, errors.New("group of the UDS listener is not configured")
	}
	if _, err := os.Stat(socketPath); err == nil {
		err = os.Remove(socketPath)
		if err != nil {
			return nil, err
		}
	}

	lsnr, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	permissions, err := strconv.ParseInt(permission, 8, 64)
	if err != nil {
		return nil, err
	}
	if userName != "-" && groupName != "-" {
		u, err := user.Lookup(userName)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return nil, err
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			return nil, err
		}

		err = os.Chown(socketPath, uid, gid)
		if err != nil {
			return nil, err
		}
	}

	err = os.Chmod(socketPath, fs.FileMode(permissions))
	if err != nil {
		return nil, err
	}
	return &listenerImpl{lsnr}, nil
}

func retrieveConnectionInfo(conn net.Conn) (*ResolvedUcred, error) {
	f, err := conn.(*net.UnixConn).File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	var connectionFd int
	err = rc.Control(func(fd uintptr) { connectionFd = int(fd) })
	if err != nil {
		return nil, err
	}

	ucred, err := unix.GetsockoptUcred(connectionFd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, err
	}

	resolved := ResolvedUcred{Uid: ucred.Uid, Gid: ucred.Gid, Pid: ucred.Pid}
	userResolved, err := user.LookupId(strconv.FormatInt(int64(resolved.Uid), 10))
	if err != nil {
		return nil, fmt.Errorf("unable to lookup uid %d: %v", resolved.Uid, err)
	}
	resolved.Username = userResolved.Username

	groupResolved, err := user.LookupGroupId(strconv.FormatInt(int64(resolved.Gid), 10))
	groupName := "<unknown>"
	if err != nil {
		// unable to lookup gid 89939: user: lookup groupid 89939: internal buffer exceeds 1048576 bytes
		// this error was encountered on some google internal systems, and it is ok to ignore it.
		if !strings.Contains(err.Error(), "internal buffer exceeds") {
			return nil, fmt.Errorf("unable to lookup gid %d: %v", resolved.Gid, err)
		}
	} else {
		groupName = groupResolved.Name
	}

	resolved.Group = groupName

	return &resolved, nil
}

func populateUserInfo(pc any, ui *k8sauth.UserInfo) error {
	var resolved *ResolvedUcred
	var ok bool
	if resolved, ok = pc.(*ResolvedUcred); !ok {
		return errors.New("unable to extract caller process'es ucred structure")
	}

	ui.Username = resolved.Username
	ui.Groups = []string{resolved.Group}
	ui.UID = fmt.Sprintf("%d", resolved.Uid)

	return nil
}

// GetSocketPath is a helper function for unit tests so we can run them platform agnostic
func GetSocketPath(dir string, pipeName string) string {
	return filepath.Join(dir, pipeName)
}

// Dial establishes a connection to the unix domain socket of containerd.
func (us *PathUpstream) Dial() (net.Conn, error) {
	return net.Dial("unix", us.socketPath)
}
