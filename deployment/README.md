# Deployment Configuration

This directory contains Kubernetes/OpenShift deployment configurations for the CVE Evaluation Toolkit.

## Structure

```
deployment/
├── Dockerfile              # Multi-stage Docker build
├── .dockerignore          # Files to exclude from Docker build
├── base/                  # Base Kustomize configuration
│   ├── kustomization.yaml
│   ├── deployment.yaml
│   ├── configmap.yaml
│   └── secret.yaml
└── overlays/              # Environment-specific overlays
    ├── dev/               # Development environment
    │   ├── kustomization.yaml
    │   ├── patches.yaml
    │   ├── secret.env.example
    │   └── README.md
    └── prod/              # Production environment
        ├── kustomization.yaml
        ├── patches.yaml
        ├── secret.env.example
        └── README.md
```

## Quick Start

### Prerequisites

- Docker
- kubectl or oc CLI
- Access to Kubernetes/OpenShift cluster
- Container registry (e.g., Quay.io)

### Build Docker Image

```bash
# From project root
docker build -t cve-evaluation:latest -f deployment/Dockerfile .
```

### Deploy to Development

```bash
# 1. Create secret.env file
cd deployment/overlays/dev
cp secret.env.example secret.env
# Edit secret.env with your credentials

# 2. Deploy
kubectl apply -k deployment/overlays/dev
```

### Deploy to Production

```bash
# 1. Build and tag production image
docker build -t quay.io/your-org/cve-evaluation:v1.0.0 -f deployment/Dockerfile .
docker push quay.io/your-org/cve-evaluation:v1.0.0

# 2. Update image tag in deployment/overlays/prod/kustomization.yaml

# 3. Configure secrets (use External Secrets Operator in production)

# 4. Deploy
kubectl apply -k deployment/overlays/prod
```

## Environments

### Development (`overlays/dev`)

- Lower resource limits
- Verbose logging (DEBUG)
- Processes fewer jobs (--limit 5)
- Doesn't submit results (--no-submit)
- Single replica

See [dev/README.md](overlays/dev/README.md) for details.

### Production (`overlays/prod`)

- Higher resource limits
- Standard logging (INFO)
- Processes more jobs (--limit 50)
- Submits results (--submit)
- Multiple replicas (2+)
- Pod anti-affinity for high availability

See [prod/README.md](overlays/prod/README.md) for details.

## Configuration

### ConfigMap (Non-sensitive)

```yaml
EXPLOIT_IQ_API_BASE: API endpoint URL
JUDGE_MODEL: LLM model name
JUDGE_BASE_URL: LLM API endpoint
LOG_LEVEL: Logging level
EVALUATION_TIMEOUT: Request timeout
```

### Secret (Sensitive)

```yaml
EXPLOIT_IQ_API_TOKEN: API authentication token
NGC_API_KEY: NVIDIA API key for LLM judge
```

## Customization

### Change Image Registry

Edit `base/kustomization.yaml`:

```yaml
images:
  - name: cve-evaluation
    newName: your-registry.io/your-org/cve-evaluation
    newTag: latest
```

### Adjust Resources

Edit overlay patches (e.g., `overlays/prod/patches.yaml`):

```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "8Gi"
    cpu: "4000m"
```

### Change Replicas

Edit overlay kustomization (e.g., `overlays/prod/kustomization.yaml`):

```yaml
replicas:
  - name: cve-evaluation
    count: 3
```

## Docker Image

The Dockerfile uses multi-stage build with uv package manager:

- **Builder stage**: Installs dependencies with uv
- **Final stage**: Minimal Python image with only runtime requirements
- **Non-root user**: Runs as user `evaluator` (UID 1000)
- **Health check**: Validates Python environment

### Image Size Optimization

- Multi-stage build reduces final image size
- Only production dependencies installed (--no-dev)
- .dockerignore excludes unnecessary files

## Security

### Secrets Management

**Development:**
- Use `secret.env` file (add to .gitignore)

**Production (Choose one):**
1. **External Secrets Operator** (Recommended)
   - Syncs secrets from Vault/AWS Secrets Manager
2. **Sealed Secrets**
   - Encrypted secrets in Git
3. **Manual Creation**
   - Create secrets directly in cluster

### Pod Security

- Runs as non-root user (UID 1000)
- No privilege escalation
- Read-only root filesystem (can be added)

## Troubleshooting

### Image Pull Errors

```bash
# Check image pull secrets
kubectl get secrets -n cve-evaluation-dev

# Verify image exists
docker pull quay.io/your-org/cve-evaluation:dev
```

### Pod Crashes

```bash
# View logs
kubectl logs -n cve-evaluation-dev <pod-name>

# Check previous logs if crashed
kubectl logs -n cve-evaluation-dev <pod-name> --previous

# Describe pod for events
kubectl describe pod -n cve-evaluation-dev <pod-name>
```

### Configuration Issues

```bash
# Verify ConfigMap
kubectl get configmap -n cve-evaluation-dev evaluation-config -o yaml

# Verify Secret (base64 encoded)
kubectl get secret -n cve-evaluation-dev evaluation-secret -o yaml

# Decode secret value
kubectl get secret -n cve-evaluation-dev evaluation-secret -o jsonpath='{.data.NGC_API_KEY}' | base64 -d
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Build image
      run: docker build -t quay.io/your-org/cve-evaluation:${{ github.sha }} -f deployment/Dockerfile .

    - name: Push image
      run: docker push quay.io/your-org/cve-evaluation:${{ github.sha }}

    - name: Deploy to dev
      run: |
        kubectl apply -k deployment/overlays/dev
```

## Monitoring

### Prometheus Metrics (Future)

Add annotations to deployment:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8080"
  prometheus.io/path: "/metrics"
```

### Logging

Logs are written to stdout and collected by cluster logging infrastructure.

## Support

For issues or questions:
1. Check environment-specific README files
2. Review troubleshooting sections
3. Check cluster events and logs
4. Contact DevOps team

## References

- [Kustomize Documentation](https://kustomize.io/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [OpenShift Documentation](https://docs.openshift.com/)
