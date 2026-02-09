# rootkube 🔍

**Kubernetes root cause analysis tool**

Stop running 10+ commands to debug your broken pods. `rootkube` tells you the "single story" of why your pod is failing.

## The Problem

Your pod is in `CrashLoopBackOff` but everything looks "green":
- Deployment shows `1/1` replicas
- Service exists
- ConfigMaps are there
- ...yet the app is broken

Debugging requires jumping across layers: Pod → Events → Logs → ConfigMaps → Secrets → NetworkPolicies → DNS. It's slow and non-obvious.

## The Solution

```bash
rootkube analyze my-broken-pod
```

rootkube correlates:
- **Pod status** (phase, container states, exit codes)
- **Events** (scheduling failures, image pulls, probe failures)
- **Logs** (error patterns, stack traces, connection issues)
- **Configuration** (coming soon: ConfigMaps, Secrets, volumes)
- **Network** (coming soon: DNS, connectivity, NetworkPolicies)

...and tells you the most likely **root cause** in one command.

## Installation

### From Source

```bash
git clone https://github.com/mitz/rootkube.git
cd rootkube
go build -o rootkube .
sudo mv rootkube /usr/local/bin/
```

### Binary Releases

Coming soon.

## Usage

```bash
# Analyze a pod in the current namespace
rootkube analyze my-broken-pod

# Analyze a pod in a specific namespace
rootkube analyze my-broken-pod -n production

# Verbose output (show all findings)
rootkube analyze my-broken-pod -v

# Custom kubeconfig
rootkube analyze my-broken-pod --kubeconfig ~/.kube/my-cluster
```

## Example Output

```
 rootkube analysis 
────────────────────────────────────────────────────────
 Target: Pod default/my-app-7f8b9c6d4f-2x4k8
Time: 2024-01-15T10:30:00Z
────────────────────────────────────────────────────────

 SUMMARY

  ✖ 2 critical issue(s)
  ⚠ 1 warning(s)
  ℹ 3 info

 FINDINGS

✖ Container 'app' is in CrashLoopBackOff [pod]
  Container has crashed 5 times. Last state: Error
  → Check container logs for crash reason

✖ [app] Connection refused error [logs]
  dial tcp 10.96.0.100:5432: connect: connection refused
  → Target service may be down. Check Service endpoints

⚠ [Event] FailedMount: MountVolume.SetUp failed [events]
  configmap "app-config" not found
  → Check ConfigMap existence

────────────────────────────────────────────────────────
 LIKELY ROOT CAUSE

  ✖ [app] Connection refused error
  dial tcp 10.96.0.100:5432: connect: connection refused

  → Suggested Fix:
  Target service may be down or not listening. Check Service endpoints and NetworkPolicies

────────────────────────────────────────────────────────
Analysis completed in 1.234s
```

## Detected Issues

### Pod Status
- CrashLoopBackOff
- ImagePullBackOff / ErrImagePull
- CreateContainerConfigError
- OOMKilled (exit code 137)
- Init container failures
- Unschedulable pods

### Events
- FailedScheduling (resources, taints, affinity)
- FailedMount (volumes, ConfigMaps, Secrets)
- Unhealthy (probe failures)
- Evicted (node pressure)

### Logs
- Connection refused / timeout
- DNS resolution failures
- Authentication / authorization errors
- Database connection errors
- Memory exhaustion
- Missing config / files
- TLS certificate errors
- Application panics / exceptions

## Roadmap

- [x] **Phase 1**: Pod, Events, Logs analyzers
- [ ] **Phase 2**: Config analyzer (ConfigMaps, Secrets, Volumes)
- [ ] **Phase 3**: Network analyzer (DNS, connectivity, NetworkPolicies)
- [ ] **Phase 4**: Root cause intelligence (ML-based correlation)
- [ ] **Phase 5**: Service & Ingress analysis (expand beyond pods)

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    rootkube analyze                      │
└──────────────────────────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │    Pod     │   │   Events   │   │    Logs    │
   │  Analyzer  │   │  Analyzer  │   │  Analyzer  │
   └────────────┘   └────────────┘   └────────────┘
          │                │                │
          └────────────────┼────────────────┘
                           ▼
              ┌────────────────────────┐
              │   Root Cause Engine    │
              │ (Correlate & Rank)     │
              └────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │    Output Renderer     │
              │  (Color-coded CLI)     │
              └────────────────────────┘
```

## Contributing

Contributions welcome! Please read our contributing guidelines (coming soon).

## License

MIT License - see [LICENSE](LICENSE) for details.
