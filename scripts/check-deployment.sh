#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

failures=0

require_file() {
  if [ ! -f "$1" ]; then
    printf '%s\n' "missing deployment artifact: $1" >&2
    failures=$((failures + 1))
  fi
}

require() {
  pattern=$1
  file=$2
  if ! grep -Fq -- "$pattern" "$file"; then
    printf '%s\n' "missing deployment control '$pattern' in $file" >&2
    failures=$((failures + 1))
  fi
}

for file in Dockerfile .dockerignore docker-compose.production.yml \
  deploy/kubernetes/bowline.yaml deploy/kubernetes/README.md scripts/docker-smoke.sh; do
  require_file "$file"
done

if [ "$failures" -ne 0 ]; then
  exit 1
fi

require 'USER 65532:65532' Dockerfile
require '@sha256:' Dockerfile
require 'HEALTHCHECK' Dockerfile
require 'org.opencontainers.image.source' Dockerfile
require 'read_only: true' docker-compose.production.yml
require 'cap_drop:' docker-compose.production.yml
require 'no-new-privileges:true' docker-compose.production.yml
require 'replicas: 1' docker-compose.production.yml
require ':ro' docker-compose.production.yml
require 'bowline-evidence:/config/ledger' docker-compose.production.yml
require 'replicas: 1' deploy/kubernetes/bowline.yaml
require 'runAsNonRoot: true' deploy/kubernetes/bowline.yaml
require 'runAsUser: 65532' deploy/kubernetes/bowline.yaml
require 'readOnlyRootFilesystem: true' deploy/kubernetes/bowline.yaml
require 'allowPrivilegeEscalation: false' deploy/kubernetes/bowline.yaml
require 'seccompProfile:' deploy/kubernetes/bowline.yaml
require 'type: RuntimeDefault' deploy/kubernetes/bowline.yaml
require 'drop:' deploy/kubernetes/bowline.yaml
require 'readOnly: true' deploy/kubernetes/bowline.yaml
require 'readinessProbe:' deploy/kubernetes/bowline.yaml
require 'livenessProbe:' deploy/kubernetes/bowline.yaml
require 'resources:' deploy/kubernetes/bowline.yaml
require 'persistentVolumeClaim:' deploy/kubernetes/bowline.yaml

for deployment in bowline.example.yaml docker-compose.production.yml deploy/kubernetes/bowline.yaml; do
  if grep -Eq '^[[:space:]]*enforcement:' "$deployment"; then
    printf '%s\n' "shipped deployment must remain observe-by-default without enforcement: $deployment" >&2
    failures=$((failures + 1))
  fi
done

replicas=$(grep -Ec '^[[:space:]]*replicas:[[:space:]]*1[[:space:]]*$' deploy/kubernetes/bowline.yaml)
if [ "$replicas" -ne 1 ]; then
  printf '%s\n' "Kubernetes manifest must declare exactly one replicas: 1" >&2
  exit 1
fi

[ "$failures" -eq 0 ] || exit 1

if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.production.yml config --quiet
fi

printf '%s\n' 'deployment contract: PASS'
