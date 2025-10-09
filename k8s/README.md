# Service Mesh Configuration for Marty

This directory contains Kubernetes configurations for setting up service mesh with either Istio or Linkerd.

## Prerequisites

### For Istio

```bash
# Install Istio CLI
curl -L https://istio.io/downloadIstio | sh -
export PATH=$PWD/istio-*/bin:$PATH

# Install Istio operator
istioctl install --set values.pilot.env.EXTERNAL_ISTIOD=false -y

# Apply Istio configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/istio/
```

### For Linkerd

```bash
# Install Linkerd CLI
curl -sL https://run.linkerd.io/install | sh
export PATH=$HOME/.linkerd2/bin:$PATH

# Verify cluster readiness
linkerd check --pre

# Install Linkerd control plane
linkerd install | kubectl apply -f -

# Install Linkerd viz extension
linkerd viz install | kubectl apply -f -

# Apply Linkerd configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/linkerd/
```

## Features

### Istio Features

- **Automatic mTLS**: All inter-service communication is encrypted with mutual TLS
- **Authorization Policies**: Fine-grained access control between services
- **Traffic Management**: Gateway and VirtualService for external access
- **Observability**: Integrated with Prometheus for metrics collection
- **Security**: Default deny-all policy with explicit allow rules

### Linkerd Features

- **Automatic mTLS**: Built-in mTLS for all service-to-service communication
- **Policy-based Authorization**: ServerAuthorization for access control
- **Traffic Routing**: HTTPRoute for intelligent traffic management
- **Ultra-lightweight**: Minimal resource overhead
- **Zero-config security**: mTLS enabled by default

## Configuration

### Service Mesh Toggle in Helm Charts

In your Helm values files, you can enable service mesh:

```yaml
serviceMesh:
  enabled: true
  type: "istio"  # or "linkerd"

  istio:
    injection: enabled
    mtls:
      mode: "STRICT"
    trafficPolicy:
      tls:
        mode: "ISTIO_MUTUAL"

  linkerd:
    injection: enabled
```

### Disabling Internal TLS when Mesh mTLS is Enabled

When service mesh mTLS is enabled, the Helm charts automatically disable internal application TLS to avoid double encryption:

```yaml
# In deployment template, this environment variable is set:
SERVICE_MESH_MTLS_ENABLED: "true"
INTERNAL_TLS_DISABLED: "true"
```

This reduces:

- Certificate management overhead
- Double encryption performance penalty
- Configuration complexity

## Monitoring

Both service meshes integrate with the existing Prometheus setup:

### Istio Metrics

- Connection metrics
- Request metrics  
- TCP metrics
- Control plane metrics

### Linkerd Metrics

- Success rates
- Request latencies
- Request volumes
- TCP metrics

## Security Policies

### Istio Security

- PeerAuthentication enforces STRICT mTLS
- AuthorizationPolicy provides fine-grained access control
- Default deny-all with explicit allow rules

### Linkerd Security

- mTLS is enabled by default
- ServerAuthorization controls access to services
- Traffic policies enforce secure communication

## Troubleshooting

### Istio

```bash
# Check configuration
istioctl analyze

# Verify mTLS
istioctl authn tls-check <pod>

# Proxy configuration
istioctl proxy-config cluster <pod>
```

### Linkerd

```bash
# Check cluster health
linkerd check

# Verify mTLS
linkerd viz stat deploy

# Debug proxy
linkerd viz top deploy
```

## Migration Strategy

1. **Phase 1**: Deploy service mesh control plane
2. **Phase 2**: Enable injection on marty namespace
3. **Phase 3**: Deploy services with mesh-aware configurations
4. **Phase 4**: Apply security policies
5. **Phase 5**: Disable internal TLS in applications

## Performance Considerations

- **Istio**: ~15-20MB memory overhead per sidecar
- **Linkerd**: ~10MB memory overhead per sidecar
- **CPU**: Minimal impact for most workloads
- **Latency**: ~1-2ms additional latency for mTLS encryption
