# Development Environment Deployment

This overlay configures the CVE evaluation toolkit for the development environment.

## Setup

1. **Create secret.env file:**

```bash
cp secret.env.example secret.env
# Edit secret.env with your actual credentials
```

2. **Build and push Docker image:**

```bash
# From project root
docker build -t quay.io/your-org/cve-evaluation:dev -f deployment/Dockerfile .
docker push quay.io/your-org/cve-evaluation:dev
```

3. **Deploy to dev cluster:**

```bash
# Using kubectl
kubectl apply -k deployment/overlays/dev

# Or using oc (OpenShift)
oc apply -k deployment/overlays/dev
```

## Configuration

### Environment Variables (ConfigMap)

- `EXPLOIT_IQ_API_BASE`: Dev API endpoint
- `JUDGE_MODEL`: LLM model for evaluation
- `LOG_LEVEL`: DEBUG (more verbose for dev)
- `EVALUATION_TIMEOUT`: 600 seconds

### Secrets (secret.env)

- `EXPLOIT_IQ_API_TOKEN`: Dev API token
- `NGC_API_KEY`: NVIDIA API key for LLM judge

### Resource Limits

- **Requests**: 256Mi memory, 250m CPU
- **Limits**: 1Gi memory, 1000m CPU

### Behavior

- Runs with `--limit 5` (only 5 jobs)
- Uses `--no-submit` (doesn't submit results to API)
- Useful for testing without affecting production data

## Verify Deployment

```bash
# Check pod status
kubectl get pods -n cve-evaluation-dev

# View logs
kubectl logs -f -n cve-evaluation-dev deployment/dev-cve-evaluation

# Check config
kubectl get configmap -n cve-evaluation-dev evaluation-config -o yaml
```

## Troubleshooting

### Pod not starting

```bash
kubectl describe pod -n cve-evaluation-dev <pod-name>
```

### Check secrets

```bash
kubectl get secret -n cve-evaluation-dev evaluation-secret -o yaml
```

### View events

```bash
kubectl get events -n cve-evaluation-dev --sort-by='.lastTimestamp'
```
