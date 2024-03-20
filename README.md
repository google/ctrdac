# Admission control with Javascript policies

**This is not an officially supported Google product.**

Kubernetes supports the concept of admission control - which is effectively a
webhook that is triggered upon certain action (e.g. pod creation). The admission
controller can then inspect the request and decide whether the action is to be
allowed or rejected.

## acjs

The project `acjs` is a Kubernetes admission controller that allows inspecting
the requests with policies written in JavaScript, making it flexible enough to
cover both typical any atypical needs. It was developed to support the [ctrdac](https://github.com/google/ctrdac)
project in non-Kubernetes context, but it can be used in standard Kubernetes
clusters as well. `ctrdac` can be connected to `acjs`; to facilitate the
process, `acjs` can be listening on a unix domain socket and `ctrdac` can
forward the requests to that UDS. This setup allows enforcing policies and
verifying images "offline" (on the same host).

Acjs can be used both as "validating webhook" and "mutating webhook".

### acjs setup in a Kubernetes cluster

It should be as easy as running:

```
$ git clone https://github.com/google/acjs.git
$ helm install --create-namespace --namespace acjs-namespace -f /path/to/policies.yaml acjs-installation acjs/charts/acjs-k8s-local
```

Where policies.yaml contains your acjs policies to enforce:

```
policies:
- name: some policy
...
```

### acjs setup with ctrdac

Create a `yaml` configuration file for `acjs`. Setup the listener and the
policies. You can refer to the sample config `simple-ac.yaml`. Start `acjs`:

```
./acjs -config-file ./simple-ac.yaml
```

You may execute `ctrdac` with these options:

```
./ctrdac -containerd-socket /tmp/ctrdac.sock -validating-webhook '/tmp/acjs.sock'
```

### acjs policies

A policy is a piece of javascript code. The admission decision is made based on
the return value:

-   boolean true: evaluating the policies is terminated and the admission
    request is accepted
-   boolean false: evaluating the policies is terminated and the admission
    request is rejected
-   string: evaluating the policies is terminated and the admission request is
    rejected with the returned string as the admission response message
-   exception was thrown: evaluating the policies is terminated and the
    admission request is rejected with the exception message as the admission
    response message
-   undef (or no explicit return), the engine proceeds to evaluating the next
    policy. If there are no more policies, the decision is made based on the
    `defaultAction` config option (it defaults to reject).

The following global variables are available in the context of a policy:

-   `ac.Timestamp`: The timestamp when `acjs` received the current admission
    request

-   `ac.User`: Information about the entity that sent the current admission
    request. In the case of the UDS listener, this will be a dictionary about
    the process that connected to the `acjs` socket, e.g. `ctrdac`. Subfields:
    `Pid`, `Uid`, `Gid`, `Username`, `Group` In the case of the mTLS listener,
    this will be a dictionary with subject of the client certificate presented
    during the handshake. You may access it like this: `ac.User.CommonName`

-   `ac.UserAuthNMethod`: A string indicating the type of authentication (e.g.
    `mTLS` or `unix-domain-socket`)

-   `ac.RequestPeerCertificates` a slice of x509.Certificates; this is the peer
    certificate when mTLS is used

-   `ac.HTTPRequest` this is the raw, incoming net/http.Request. You can use it
    in advanced rules to inspect the request path (`ac.HTTPRequest.RequestURI`)
    or the headers (e.g. ac.HTTPRequest.Header.Get("X-Something")`)). In a
    ctrdac setup, you can also use it to check which containerd interface the
    request was originally submitted to:
    ```
    ac.HTTPRequest.Header.Get("X-Ctrdac-RequestUri") == "/containerd.services.containers.v1.Container/Create"
    ```

    In a Kubernetes context, you can use the RequestUri to serve multiple 
    webhookconfigurations with the same acjs process. Example:

    ```
    if (ac.HTTPRequest.RequestUri == "/ac1") {
      // ... some logic here
    }
    if (ac.HTTPRequest.RequestUri == "/ac2") {
      // ... some logic here
    }
    ```

-   `ac.GlobalContext` a dictionary that is available through the whole
    lifecycle of tha authz configuration. You can use it to save some kind of
    state information, if needed.

-   `req`: this is the incoming
    [AdmissionRequest](https://pkg.go.dev/k8s.io/api/admission/v1#AdmissionRequest).
    As such, you may access info like this (in line with the `json=""`):
    `req.namespace` or `req.name`

-   `object`: this is the json parsed `req.Object` (which is just raw bytes).
    This is typically a [Pod](https://pkg.go.dev/k8s.io/api/core/v1#Pod) As
    such, you may access info like this (in line with the `json=""`):
    `object.spec.containers[0].name` or `object.spec.containers[0].image`

-   `console`: this is the Javascript standard console object that you may use
    for logging.

-   `cosignVerify(keyPath)`: built-in function to verify cosign signatures on
    the images present in the request This function relies on the `cosign`
    binary in the PATH. It returns a map indexed by the image references where
    the value is the JSON output of cosign for further processing or throws an
    error when the verification was unsuccessful. Example:

```
  {"some/image":[{"Critical":{...}}]}
```

-   `slsaVerify({"SourceURI": "github.com/irsl/gcb-tests", "BuilderID":
    "https://cloudbuild.googleapis.com/GoogleHostedWorker", "ProvenancePath":
    "/home/user/provenance-github.json"})`: built-in function to verify SLSA
    provenance. It returns a boolean. This function relies on the
    `slsa-verifier` binary in the PATH. It returns boolean true or an error
    string.

-   `slsaEnsureComingFrom(repos)`: built-in helper function to verify SLSA
    provenance, it supports looking up image provenance on the fly. This
    function relies on the `slsa-verifier` binary in the PATH. It returns a
    boolean indicating whether the image was built at one of the provided
    repositories.

-   `forwardToAdmissionController(acUrl)`: built-in function to forward the
    current admission review request to another admission controller.

-   `atob` helper function to decode a base64 string

-   `btoa` helper function to encode something into base64

`acjs` can work as a mutating webhook: if the policy makes changes on the
`object` and returns true, then a JSON Patch is calculated and included in the
admission review response.

### An example policy

```
policies:
- name: some name of the policy
  code: |
    console.log("hello!", ac.User.Username, "x", req.UID, "x", object.spec.containers[0].name, "x", object.spec.containers[0].image)

    if (object.spec.containers[0].name.includes("apple"))
      return "please choose a different fruit"
```

The corresponding response may look like this:

```
$ curl --unix-socket /tmp/acjs.sock http:/images/ -d @/home/user/ac1-apple.json
{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","response":{"uid":"2bb7b8e5-3cd4-47ea-9b4e-ee8c98dc00ed","allowed":false,"status":{"metadata":{},"status":"Failure","message":"some name of the policy: please choose a different fruit","reason":"VIOLATES_POLICY"}}
```

### Example to mutate a Pod - default k8s conversion

```
policies:
- name: replace the parameters
  code: |
    object.spec.containers[0].command = ["/bin/echo", "hello :) sorry, this is probably not what you expected."]
    object.spec.containers[0].args = []
    return true
```

### Example to mutate the runc spec - k8s conversion is disabled

```
policies:
- name: replace the parameters
  code: |
    runcSpec = JSON.parse(atob(object.container.spec.value))
    runcSpec.process.env.push("SOMETHING=debug")
    object.container.spec.value = btoa(JSON.stringify(runcSpec))
```

### Example to forward the request

```
policies:
- name: example-forward
  code: |
    if (object.spec.containers[0].name.includes("apple"))
      // apple containers are to be evaluated by this another admission controller:
      return forwardToAdmissionController('https://my-awesome-ac.com/v1/projects/user-test/policy/locations/europe-west4-b/clusters/cluster-1:admissionReview?timeout=10s')
```

### Example to verify SLSA:

```
policies:
- name: example-slsa
  code: |
    var trustedSourceRepos = ["github.com/irsl/gcb-tests"]
    if (!slsaEnsureComingFrom(trustedSourceRepos))
       return "SLSA verification of the image failed. Trusted repos are: "+(trustedSourceRepos.join(", "))
```

Example rejection:

```
$ docker run --rm -it us-west2-docker.pkg.dev/user-test/quickstart-docker-repo/quickstart-image:tag3
docker: Error response from daemon: VIOLATES_POLICY: some name of the policy: SLSA verification of the image failed. Trusted repos are: github.com/irsl/gcb-tests: invalid argument.
```

Example success:

```
$ docker run --rm -it us-west2-docker.pkg.dev/user-test/quickstart-docker-repo/quickstart-image:v41
user: Hello! The time is Thu Mar 23 10:47:47 UTC 2023.
```

### Example to secure deprecated gitRepo volumes:

Kubernetes's gitRepo volume type is vulnerable to privilege escalation attacks
(code execution in the context of `kubelet`).
The following mutating webhook policy secures the configuration on the fly by
offloading the git operation into init containers:

```
policies:
- name: securing gitrepo volumes
  code: |
    for(var i = 0; i < object.spec.volumes.length; i++) {
       var volume = object.spec.volumes[i]
       if(!volume.gitRepo) continue
       var gitRepoCfg = volume.gitRepo
       var gitCmd = [
              "git",
              "clone",
       ]
       if (gitRepoCfg.revision) {
           gitCmd.push("--branch", gitRepoCfg.revision)
       }
       gitCmd.push("--", gitRepoCfg.repository)
       object.spec.initContainers = [
          ...(object.spec.initContainers || []),
          {
             name: "gitrepo-init-"+i,
             image: "bitnami/git",
             workingDir: "/repo-volume",
             command: gitCmd,
             volumeMounts: [{
                  mountPath: "/repo-volume",
                  name: volume.name
             }]
          }
       ]
       volume.emptyDir = {}
       delete volume.gitRepo
    }
    return true
```



