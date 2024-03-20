# Admission control for Containerd/Docker

**This is not an officially supported Google product.**

Kubernetes supports the concept of admission control - which is effectively a
webhook that is triggered upon certain action (e.g. pod creation). The admission
controller can then inspect the request and decide whether the action is to be
allowed or rejected.

The ctrdac and acjs projects try to adopt this technology for workloads that
rely on container images but are not hosted in Kubernetes. The primary
motivation with these projects is to provide a way to verify image signatures
and provenance where having a full Kubernetes deployment is not an option.

## ctrdac

The ctrdac project is a super lightweight proxy in front of Containerd that
intercepts the `/containerd.services.containers.v1.Containers/Create` gRPC
method invocation, repackages it into a Kubernetes AdmissionReview and forwards
it to the specified Admission controller.

### ctrdac setup

Stop docker (that kills containerd with the same shot):

```
pkill -f dockerd
```

Restart containerd yourself:

```
containerd --config /var/run/docker/containerd/containerd.toml --log-level info
```

Start `ctrdac`:

```
./ctrdac -proxy-listener-socket /tmp/ctrdac.sock -validating-webhook https://some.tld/to/an/admission/controller
```

And restart dockerd pointing to `ctrdac`:

```
dockerd --containerd /tmp/ctrdac.sock
```


### ctrdac and Container Optimized OS (COS)

You can use the following recipe to configure COS to verify images at container
creation. This can be done by adding a `user-data` key of the GCE instance
metadata with the following content:

```
#cloud-config

write_files:
- path: /etc/systemd/system/ctrdac.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=ctrdac forwards container creation requests to K8s admission controllers

    [Service]
    ExecStart=/var/lib/containerd/ctrdac/ctrdac -containerd-socket /var/run/containerd/containerd.vanilla.sock -proxy-listener-params 0660:root:docker -proxy-listener-socket /var/run/containerd/containerd.sock -validating-webhook 'https://my-awesome-ac.com/v1/projects/user-test/policy/locations/europe-west4-b/clusters/cluster-1:admissionReview?timeout=10s'
    ExecStop=pkill ctrdac

runcmd:
- systemctl daemon-reload
- systemctl start ctrdac.service

bootcmd:
- |
  set -e
  mkdir /etc/containerd
  containerd config default | sed 's#/run/containerd/containerd.sock#/run/containerd/containerd.vanilla.sock#' > /etc/containerd/config.toml
  systemctl restart containerd

  dir=/var/lib/containerd/ctrdac
  mkdir -p "$dir"
  access_token="$(curl -H "Metadata-Flavor: Google"  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token)"
  curl -H "Authorization: Bearer $access_token" "https://storage.googleapis.com/storage/v1/b/ctrdac-dropzone/o/ctrdac?alt=media" -o "$dir/ctrdac"
  echo "1a167ebd30dcab4502fc3954265391f43baefd4189aaef178ecf684f60f7ec1d $dir/ctrdac" > "$dir/ctrdac.sum"
  if ! sha256sum --check "$dir/ctrdac.sum"; then
    echo "Integrity check of ctrdac has failed"
    rm "$dir/ctrdac"
    exit 1
  fi

  chmod 755 "$dir/ctrdac"

```

Note: you'll need to customize:

-   the URL of the admission controller

-   the source URL of the `ctrdac` executable

-   the SHA checksum of `ctrdac`

### ctrdac and raw runc payloads

If you don't plan to integrate with any "real" Kubernetes services, you may flip
the `-no-k8s-conversion` command line flag of `ctrdac`. The gateway will then
simply forward the complete Containerd requests to the specified Admission
Controller intact. The Containerd request will be available as the `object`
(just like the Pod is when conversion is in use). This allows inspecting and
modifying the full runc specification without any compromise: the K8s pod
definition is not 100% compatible with K8s - e.g. kubernetes lacks the concept
of effective/permitted/bounding capabilities, the fine grained list of seccomp
syscalls, etc.
