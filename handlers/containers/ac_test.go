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
	"reflect"
	"testing"

	"github.com/google/ctrdac/common"
	"github.com/google/ctrdac/lookup"
	"github.com/google/go-cmp/cmp"

	anypb "github.com/golang/protobuf/ptypes/any"
	cpb "github.com/containerd/containerd/v2/api/services/containers/v1"
	k8score "k8s.io/api/core/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func bp(b bool) *bool {
	return &b
}

func i64p(u int) *int64 {
	re := int64(u)
	return &re
}

func buildCreateContainerRequest() *cpb.CreateContainerRequest {
	runcSpec := []byte(`{"ociVersion":"1.0.2-dev","process":{"terminal":true,"consoleSize":{"height":24,"width":323},"user":{"uid":1000,"gid":1001,"additionalGids":[0,0,1,2,3,4,6,10,11,20,26,27]},"args":["/bin/echo", "hello world"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOSTNAME=a813a1480e2c","TERM=xterm"],"cwd":"/foo","capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_SYS_ADMIN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"apparmorProfile":"docker-default","oomScoreAdj":0},"root":{"path":"/var/lib/docker/overlay2/438c45435c1be66309ee41fa29ad1f7da06251a1dd7a9e3a6be9d9cedf423672/merged"},"hostname":"a813a1480e2c","mounts":[{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},{"destination":"/sys/fs/cgroup","type":"cgroup","source":"cgroup","options":["ro","nosuid","noexec","nodev"]},{"destination":"/dev/mqueue","type":"mqueue","source":"mqueue","options":["nosuid","noexec","nodev"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"]},{"destination":"/etc/resolv.conf","type":"bind","source":"/var/lib/docker/containers/a813a1480e2cd00fb9788de58073183e1703b7fae1901b59914452e6566b895a/resolv.conf","options":["rbind","rprivate"]},{"destination":"/etc/hostname","type":"bind","source":"/var/lib/docker/containers/a813a1480e2cd00fb9788de58073183e1703b7fae1901b59914452e6566b895a/hostname","options":["rbind","rprivate"]},{"destination":"/etc/hosts","type":"bind","source":"/var/lib/docker/containers/a813a1480e2cd00fb9788de58073183e1703b7fae1901b59914452e6566b895a/hosts","options":["rbind","rprivate"]},{"destination": "/something","type": "bind","source": "/etc","options": ["rbind","rprivate"]}],"hooks":{"prestart":[{"path":"/proc/1474/exe","args":["libnetwork-setkey","-exec-root=/var/run/docker","a813a1480e2cd00fb9788de58073183e1703b7fae1901b59914452e6566b895a","b8455c2ee388"]}]},"linux":{"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"},"resources":{"devices":[{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"}],"memory":{},"cpu":{"shares":0},"blockIO":{"weight":0}},"cgroupsPath":"/docker/a813a1480e2cd00fb9788de58073183e1703b7fae1901b59914452e6566b895a","namespaces":[{"type":"mount"},{"type":"network", "path": "/var/run/docker/netns/default"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["accept","accept4","access","adjtimex","alarm","bind","brk","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_time64","futex_waitv","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","io_uring_enter","io_uring_register","io_uring_setup","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listxattr","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","rename","renameat","renameat2","restart_syscall","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"],"action":"SCMP_ACT_ALLOW"},{"names":["process_vm_readv","process_vm_writev","ptrace"],"action":"SCMP_ACT_ALLOW"},{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":40,"op":"SCMP_CMP_NE"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":0,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":8,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131072,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131080,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":4294967295,"op":"SCMP_CMP_EQ"}]},{"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW"},{"names":["modify_ldt"],"action":"SCMP_ACT_ALLOW"},{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},{"names":["chroot"],"action":"SCMP_ACT_ALLOW"}]},"maskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}}`)
	return &cpb.CreateContainerRequest{
		Container: &cpb.Container{
			/*Container*/ ID: "containerid",
			Image:            "some/image",
			Runtime: &cpb.Container_Runtime{
				Name: "types.containerd.io/opencontainers/runtime-spec/1/Spec",
			},
			Spec: &anypb.Any{
				Value: runcSpec,
			},
		},
	}
}

func getExpectedPod() k8score.Pod {
	return k8score.Pod{
		TypeMeta: k8smeta.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Spec: k8score.PodSpec{
			Volumes: []k8score.Volume{
				k8score.Volume{
					Name: "vol1",
					VolumeSource: k8score.VolumeSource{
						EmptyDir: &k8score.EmptyDirVolumeSource{},
					},
				},
				k8score.Volume{
					Name: "vol6",
					VolumeSource: k8score.VolumeSource{
						EmptyDir: &k8score.EmptyDirVolumeSource{},
					},
				},
				k8score.Volume{
					Name: "vol10",
					VolumeSource: k8score.VolumeSource{
						HostPath: &k8score.HostPathVolumeSource{
							Path: "/etc",
						},
					},
				},
			},
			Containers: []k8score.Container{
				k8score.Container{
					Name:       "containerid",
					Image:      "some/image",
					Command:    []string{"/bin/echo", "hello world"},
					Args:       []string{},
					WorkingDir: "/foo",
					TTY:        true,
					Env: []k8score.EnvVar{
						{
							Name:  "PATH",
							Value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
						},
						{
							Name:  "HOSTNAME",
							Value: "a813a1480e2c",
						},
						{
							Name:  "TERM",
							Value: "xterm",
						},
					},
					VolumeMounts: []k8score.VolumeMount{
						k8score.VolumeMount{
							Name:      "vol1",
							MountPath: "/dev",
						},
						k8score.VolumeMount{
							Name:      "vol6",
							MountPath: "/dev/shm",
						},
						k8score.VolumeMount{
							Name:      "vol10",
							MountPath: "/something",
						},
					},
					SecurityContext: &k8score.SecurityContext{
						RunAsUser:    i64p(1000),
						RunAsGroup:   i64p(1001),
						RunAsNonRoot: bp(true),
						Privileged:   bp(true),
						Capabilities: &k8score.Capabilities{
							Add:  []k8score.Capability{"cap_sys_admin"},
							Drop: []k8score.Capability{"cap_chown"},
						},
					},
				},
			},
			HostNetwork: true,
			HostPID:     false,
			HostIPC:     false,
		},
	}
}

func TestConversionWithDockerResolution(t *testing.T) {
	origResolveImageFromDocker := resolveImageFromDocker
	defer func() { resolveImageFromDocker = origResolveImageFromDocker }()

	resolveImageFromDocker = func(s common.ProxyServer, containerID string) (string, error) {
		return "some/different/image", nil
	}

	c := buildCreateContainerRequest()
	c.Container.Image = "" // missing!

	a, err := ConvertCreateContainerToPod(nil, c)
	if err != nil {
		t.Fatalf("no error expected, got %v", err)
	}
	e := getExpectedPod()
	e.Spec.Containers[0].Image = "some/different/image"
	diff := cmp.Diff(a, e)
	if diff != "" {
		t.Errorf("compare failed: %v", diff)
	}
}

func TestConversion(t *testing.T) {
	c := buildCreateContainerRequest()
	a, err := ConvertCreateContainerToPod(nil, c)
	if err != nil {
		t.Fatalf("no error expected, got %v", err)
	}
	e := getExpectedPod()
	diff := cmp.Diff(a, e)
	if diff != "" {
		t.Errorf("compare failed: %v", diff)
	}
}

func TestPatch(t *testing.T) {
	c := buildCreateContainerRequest()
	podAny, err := ConvertCreateContainerToPod(nil, c)
	if err != nil {
		t.Fatalf("no error expected, got %v", err)
	}
	pod, ok := podAny.(k8score.Pod)
	if !ok {
		t.Fatalf("no pod was returned")
	}
	pod.Spec.Containers[0].Image = "some/other/image"
	pod.Spec.Containers[0].Command = []string{"/bin/reboot"}
	pod.Spec.Containers[0].Args = []string{"now"}

	podBytes, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}

	err = PatchCreateContainer(nil, c, podBytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.Container.Image != "some/other/image" {
		t.Errorf("image was not modified: %s", c.Container.Image)
	}

	var runcSpec map[string]any
	err = json.Unmarshal(c.Container.Spec.Value, &runcSpec)
	if err != nil {
		t.Fatal(err)
	}

	args, err := lookup.ToStrSlice(lookup.Lookup[[]any](runcSpec, "process.args", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{"/bin/reboot", "now"}) {
		t.Errorf("process.args in the runtime spec was unexpected: %+v", args)
	}

}
