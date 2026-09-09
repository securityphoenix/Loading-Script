# Phoenix Security Platform - Container Metadata Standard

## Overview

This document defines the standard metadata format for capturing container build information during CI/CD pipelines. This metadata enriches vulnerability scan results with build context, enabling better asset tracking, vulnerability correlation, and compliance reporting.

---

## Table of Contents

1. [Metadata Schema](#metadata-schema)
2. [Field Definitions](#field-definitions)
3. [Usage in Phoenix](#usage-in-phoenix)
4. [Pipeline Integration](#pipeline-integration)
5. [Examples](#examples)

---

## Metadata Schema

### Standard Container Metadata Format (YAML)

```yaml
# Phoenix Container Metadata Standard v1.0
metadata_version: "1.0"
capture_timestamp: "2024-01-15T10:30:00Z"

# ============================================================================
# CONTAINER IDENTITY
# ============================================================================
container:
  # Full image reference (registry/repository:tag@digest)
  image_full_ref: "registry.example.com/myapp/backend:v1.2.3@sha256:abc123..."
  
  # Image components
  registry: "registry.example.com"
  repository: "myapp/backend"
  image_name: "backend"
  tag: "v1.2.3"
  digest: "sha256:abc123def456..."
  
  # Image metadata
  image_id: "sha256:abc123..."
  created: "2024-01-15T10:25:00Z"
  size_bytes: 245678901
  size_human: "234.5 MB"
  architecture: "amd64"
  os: "linux"

# ============================================================================
# BASE IMAGE INFORMATION
# ============================================================================
base_image:
  image_ref: "python:3.11-slim-bookworm"
  registry: "docker.io"
  repository: "library/python"
  tag: "3.11-slim-bookworm"
  digest: "sha256:base123..."
  os_name: "debian"
  os_version: "bookworm"
  os_id: "debian"

# ============================================================================
# LAYER INFORMATION
# ============================================================================
layers:
  total_count: 12
  base_layers: 8
  application_layers: 4
  layer_details:
    - index: 0
      digest: "sha256:layer0..."
      size_bytes: 29456789
      created_by: "ADD file:... in /"
      is_base_layer: true
    - index: 8
      digest: "sha256:layer8..."
      size_bytes: 1234567
      created_by: "COPY requirements.txt /app/"
      is_base_layer: false

# ============================================================================
# SOURCE CODE INFORMATION
# ============================================================================
source:
  # Repository information
  repository_url: "https://github.com/myorg/myapp"
  repository_type: "git"
  
  # Commit information
  commit_sha: "abc123def456789..."
  commit_sha_short: "abc123d"
  commit_message: "feat: Add new authentication module"
  commit_author: "user@example.com"
  commit_timestamp: "2024-01-15T09:00:00Z"
  
  # Branch/Tag information
  branch: "main"
  tag: "v1.2.3"
  is_tag: true
  
  # Additional context
  pr_number: "456"
  pr_url: "https://github.com/myorg/myapp/pull/456"

# ============================================================================
# BUILD INFORMATION
# ============================================================================
build:
  # Build system
  builder: "docker"
  builder_version: "24.0.7"
  buildkit_version: "0.12.4"
  
  # Build context
  dockerfile_path: "Dockerfile"
  build_context: "."
  build_args:
    - name: "APP_VERSION"
      value: "1.2.3"
    - name: "BUILD_DATE"
      value: "2024-01-15"
  
  # Build timing
  build_start: "2024-01-15T10:20:00Z"
  build_end: "2024-01-15T10:25:00Z"
  build_duration_seconds: 300
  
  # Build host
  build_host: "github-runner-ubuntu-22.04"
  build_platform: "linux/amd64"

# ============================================================================
# CI/CD PIPELINE INFORMATION
# ============================================================================
pipeline:
  # Pipeline system
  ci_system: "github-actions"
  ci_system_version: "2.0"
  
  # Pipeline identifiers
  pipeline_id: "7890123456"
  pipeline_url: "https://github.com/myorg/myapp/actions/runs/7890123456"
  job_id: "build-container"
  job_url: "https://github.com/myorg/myapp/actions/runs/7890123456/job/12345"
  
  # Trigger information
  trigger_type: "push"
  trigger_actor: "user@example.com"
  trigger_ref: "refs/heads/main"

# ============================================================================
# SECURITY SCANNING INFORMATION
# ============================================================================
security_scans:
  - scanner: "trivy"
    scanner_version: "0.48.0"
    scan_timestamp: "2024-01-15T10:26:00Z"
    scan_type: "container"
    results_file: "trivy_results.json"
    summary:
      critical: 0
      high: 2
      medium: 5
      low: 12
  
  - scanner: "grype"
    scanner_version: "0.74.0"
    scan_timestamp: "2024-01-15T10:27:00Z"
    scan_type: "container"
    results_file: "grype_results.json"

# ============================================================================
# SBOM INFORMATION
# ============================================================================
sbom:
  generated: true
  format: "cyclonedx"
  format_version: "1.5"
  file_path: "sbom.json"
  generator: "syft"
  generator_version: "0.100.0"
  component_count: 245
  
# ============================================================================
# LABELS AND ANNOTATIONS
# ============================================================================
labels:
  # OCI standard labels
  "org.opencontainers.image.title": "Backend Service"
  "org.opencontainers.image.description": "Main backend API service"
  "org.opencontainers.image.version": "1.2.3"
  "org.opencontainers.image.vendor": "MyOrg"
  "org.opencontainers.image.source": "https://github.com/myorg/myapp"
  "org.opencontainers.image.revision": "abc123def456789"
  "org.opencontainers.image.created": "2024-01-15T10:25:00Z"
  
  # Custom labels
  "com.myorg.team": "platform"
  "com.myorg.cost-center": "CC-12345"
  "com.myorg.environment": "production"

# ============================================================================
# PHOENIX TAGS (Auto-generated for import)
# ============================================================================
phoenix_tags:
  - key: "image-name"
    value: "backend"
  - key: "image-tag"
    value: "v1.2.3"
  - key: "image-digest"
    value: "sha256:abc123..."
  - key: "base-image"
    value: "python:3.11-slim-bookworm"
  - key: "source-repo"
    value: "github.com/myorg/myapp"
  - key: "commit-sha"
    value: "abc123d"
  - key: "branch"
    value: "main"
  - key: "build-date"
    value: "2024-01-15"
  - key: "ci-system"
    value: "github-actions"
  - key: "pipeline-id"
    value: "7890123456"
```

---

## Field Definitions

### Container Identity Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `image_full_ref` | string | Yes | Complete image reference including registry, repo, tag, and digest |
| `registry` | string | Yes | Container registry hostname |
| `repository` | string | Yes | Image repository path |
| `image_name` | string | Yes | Short image name (last component of repository) |
| `tag` | string | Yes | Image tag |
| `digest` | string | Yes | Image digest (sha256) |
| `image_id` | string | Yes | Local image ID |
| `created` | datetime | Yes | Image creation timestamp |
| `size_bytes` | integer | No | Image size in bytes |
| `architecture` | string | Yes | CPU architecture (amd64, arm64) |
| `os` | string | Yes | Operating system (linux, windows) |

### Base Image Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `image_ref` | string | Yes | Base image reference |
| `registry` | string | No | Base image registry |
| `repository` | string | No | Base image repository |
| `tag` | string | No | Base image tag |
| `digest` | string | No | Base image digest |
| `os_name` | string | No | Base OS name (debian, alpine, ubuntu) |
| `os_version` | string | No | Base OS version |

### Layer Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `total_count` | integer | Yes | Total number of layers |
| `base_layers` | integer | No | Number of layers from base image |
| `application_layers` | integer | No | Number of application-specific layers |
| `layer_details` | array | No | Detailed information per layer |

### Source Code Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repository_url` | string | Yes | Source code repository URL |
| `commit_sha` | string | Yes | Full commit SHA |
| `commit_sha_short` | string | No | Short commit SHA (7 chars) |
| `branch` | string | No | Branch name |
| `tag` | string | No | Git tag if applicable |
| `commit_author` | string | No | Commit author email |
| `commit_timestamp` | datetime | No | Commit timestamp |

### Build Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `builder` | string | Yes | Build tool (docker, buildah, kaniko) |
| `builder_version` | string | No | Build tool version |
| `dockerfile_path` | string | No | Path to Dockerfile |
| `build_start` | datetime | No | Build start timestamp |
| `build_end` | datetime | No | Build end timestamp |
| `build_duration_seconds` | integer | No | Build duration |
| `build_platform` | string | No | Target platform |

### Pipeline Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ci_system` | string | Yes | CI/CD system name |
| `pipeline_id` | string | Yes | Pipeline/workflow run ID |
| `pipeline_url` | string | No | URL to pipeline run |
| `job_id` | string | No | Job/step ID |
| `trigger_type` | string | No | Trigger type (push, pr, schedule) |
| `trigger_actor` | string | No | User/system that triggered build |

---

## Usage in Phoenix

### Converting Metadata to Phoenix Tags

The `phoenix_tags` section in the metadata file can be directly used with the Loading Script:

```bash
# Extract phoenix_tags from metadata and create tag file
yq '.phoenix_tags' container_metadata.yaml > phoenix_container_tags.yaml

# Import scan results with container metadata tags
python phoenix_multi_scanner_enhanced.py \
  --file trivy_results.json \
  --scanner trivy \
  --tag-file phoenix_container_tags.yaml
```

### Recommended Phoenix Tags from Container Metadata

| Tag Key | Source Field | Priority | Description |
|---------|--------------|----------|-------------|
| `image-name` | `container.image_name` | High | Container image name |
| `image-tag` | `container.tag` | High | Image version tag |
| `image-digest` | `container.digest` | High | Immutable image identifier |
| `base-image` | `base_image.image_ref` | High | Base image reference |
| `source-repo` | `source.repository_url` | High | Source code repository |
| `commit-sha` | `source.commit_sha_short` | High | Git commit reference |
| `branch` | `source.branch` | Medium | Git branch |
| `build-date` | `build.build_end` | Medium | Build timestamp |
| `ci-system` | `pipeline.ci_system` | Medium | CI/CD platform |
| `pipeline-id` | `pipeline.pipeline_id` | Medium | Build pipeline ID |
| `layer-count` | `layers.total_count` | Low | Number of image layers |
| `os-base` | `base_image.os_name` | Low | Base OS type |

---

## Pipeline Integration

### Supported CI/CD Systems

The container metadata capture script supports:

- **GitHub Actions** - Full native support
- **GitLab CI** - Full native support
- **Jenkins** - Via environment variables
- **Azure DevOps** - Via environment variables
- **CircleCI** - Via environment variables
- **Bitbucket Pipelines** - Via environment variables

### Integration Points

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CI/CD PIPELINE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │  Build   │───▶│  Capture │───▶│   Scan   │───▶│  Upload to       │  │
│  │Container │    │ Metadata │    │Container │    │  Phoenix         │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────────────┘  │
│       │               │               │                   │             │
│       │               │               │                   │             │
│       ▼               ▼               ▼                   ▼             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │  Image   │    │ metadata │    │  scan    │    │  Enriched        │  │
│  │  :tag    │    │  .yaml   │    │ results  │    │  Vulnerabilities │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Examples

### Minimal Metadata (Required Fields Only)

```yaml
metadata_version: "1.0"
capture_timestamp: "2024-01-15T10:30:00Z"

container:
  image_full_ref: "myregistry.com/myapp:v1.0.0"
  registry: "myregistry.com"
  repository: "myapp"
  image_name: "myapp"
  tag: "v1.0.0"
  digest: "sha256:abc123..."
  image_id: "sha256:abc123..."
  created: "2024-01-15T10:25:00Z"
  architecture: "amd64"
  os: "linux"

source:
  repository_url: "https://github.com/myorg/myapp"
  commit_sha: "abc123def456789"

build:
  builder: "docker"

pipeline:
  ci_system: "github-actions"
  pipeline_id: "12345"
```

### Multi-Architecture Build Metadata

```yaml
metadata_version: "1.0"
capture_timestamp: "2024-01-15T10:30:00Z"

container:
  image_full_ref: "myregistry.com/myapp:v1.0.0"
  registry: "myregistry.com"
  repository: "myapp"
  image_name: "myapp"
  tag: "v1.0.0"
  # Manifest list digest for multi-arch
  digest: "sha256:manifest123..."
  
  # Platform-specific images
  platforms:
    - architecture: "amd64"
      os: "linux"
      digest: "sha256:amd64abc..."
      size_bytes: 245678901
    - architecture: "arm64"
      os: "linux"
      digest: "sha256:arm64def..."
      size_bytes: 234567890

build:
  builder: "docker"
  builder_version: "24.0.7"
  buildx_version: "0.12.0"
  build_platform: "linux/amd64,linux/arm64"
```

---

## See Also

- [TAG_CONFIGURATION_GUIDE.md](../guides/TAG_CONFIGURATION_GUIDE.md) - Tag configuration reference
- [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) - Complete documentation index
- `scripts/capture_container_metadata.sh` - Metadata capture script

---

*Last Updated: February 2026*
*Metadata Schema Version: 1.0*
