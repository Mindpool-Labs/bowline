# Kubernetes production PoV example

This example deliberately runs one Bowline replica and one writer against a `ReadWriteOnce`
evidence volume. Replace the image, upstream URL, `actual_supply_id`, trusted proxy CIDRs, registry,
policy, resource limits, storage class, and retention settings with reviewed deployment values.

Create the immutable policy/registry ConfigMap, inspect the resulting objects, then apply:

```sh
kubectl create configmap bowline-static \
  --from-file=default.yaml=policies/default.yaml \
  --from-file=feed.json=registry/feed.json \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply --server-side --dry-run=server -f deploy/kubernetes/bowline.yaml
kubectl apply -f deploy/kubernetes/bowline.yaml
kubectl rollout status deployment/bowline
kubectl port-forward service/bowline 8080:8080
bowline health --url http://127.0.0.1:8080/health/ready
```

Run `bowline preflight` with the final configuration before accepting traffic. The pod filesystem
and config mounts are read-only; only `/evidence` is writable. Keep `replicas: 1` in Phase 1. A
rolling deployment or a second writer against the same directory is unsupported and is rejected by
the directory lock. Back up the PVC only after a clean shutdown or from a storage-level consistent
snapshot; see [operations](../../docs/operations.md).
