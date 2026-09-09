#!/bin/bash
# ============================================================================
# Phoenix Security - Container Metadata Capture Script
# ============================================================================
# Version: 1.0.0
# Description: Captures comprehensive container build metadata for Phoenix
#              Security Platform integration.
#
# Usage:
#   ./capture_container_metadata.sh <image_reference> [output_file]
#
# Examples:
#   ./capture_container_metadata.sh myapp:latest
#   ./capture_container_metadata.sh registry.io/myapp:v1.0.0 metadata.yaml
#   ./capture_container_metadata.sh myapp:latest --json
#
# Requirements:
#   - docker or podman
#   - jq (for JSON processing)
#   - yq (optional, for YAML output)
#   - git (for source information)
#
# CI/CD Support:
#   - GitHub Actions
#   - GitLab CI
#   - Jenkins
#   - Azure DevOps
#   - CircleCI
#   - Bitbucket Pipelines
# ============================================================================

set -euo pipefail

# Script version
SCRIPT_VERSION="1.0.0"
METADATA_VERSION="1.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
OUTPUT_FORMAT="yaml"
OUTPUT_FILE=""
VERBOSE=false
INCLUDE_LAYERS=true
INCLUDE_LABELS=true
GENERATE_PHOENIX_TAGS=true

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

show_help() {
    cat << EOF
Phoenix Security - Container Metadata Capture Script v${SCRIPT_VERSION}

USAGE:
    $(basename "$0") <image_reference> [options]

ARGUMENTS:
    image_reference    Docker image reference (e.g., myapp:latest, registry.io/myapp:v1.0.0)

OPTIONS:
    -o, --output FILE      Output file path (default: container_metadata.yaml)
    -f, --format FORMAT    Output format: yaml or json (default: yaml)
    --no-layers            Skip layer information capture
    --no-labels            Skip label information capture
    --no-phoenix-tags      Skip Phoenix tag generation
    -v, --verbose          Enable verbose output
    -h, --help             Show this help message

EXAMPLES:
    # Basic usage - capture metadata for local image
    $(basename "$0") myapp:latest

    # Capture metadata and save to specific file
    $(basename "$0") registry.io/myapp:v1.0.0 -o build_metadata.yaml

    # Output as JSON
    $(basename "$0") myapp:latest --format json -o metadata.json

    # Verbose mode for debugging
    $(basename "$0") myapp:latest -v

CI/CD INTEGRATION:
    The script automatically detects and captures CI/CD context from:
    - GitHub Actions
    - GitLab CI
    - Jenkins
    - Azure DevOps
    - CircleCI
    - Bitbucket Pipelines

EOF
}

check_dependencies() {
    local missing_deps=()
    
    # Check for container runtime
    if command -v docker &> /dev/null; then
        CONTAINER_RUNTIME="docker"
    elif command -v podman &> /dev/null; then
        CONTAINER_RUNTIME="podman"
    else
        missing_deps+=("docker or podman")
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    # Check for yq (optional, for YAML output)
    if [[ "$OUTPUT_FORMAT" == "yaml" ]] && ! command -v yq &> /dev/null; then
        log_warn "yq not found - will output JSON and convert manually"
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
    
    log_debug "Using container runtime: $CONTAINER_RUNTIME"
}

# ============================================================================
# CI/CD DETECTION FUNCTIONS
# ============================================================================

detect_ci_system() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "github-actions"
    elif [[ -n "${GITLAB_CI:-}" ]]; then
        echo "gitlab-ci"
    elif [[ -n "${JENKINS_URL:-}" ]]; then
        echo "jenkins"
    elif [[ -n "${AZURE_PIPELINES:-}" ]] || [[ -n "${TF_BUILD:-}" ]]; then
        echo "azure-devops"
    elif [[ -n "${CIRCLECI:-}" ]]; then
        echo "circleci"
    elif [[ -n "${BITBUCKET_PIPELINE_UUID:-}" ]]; then
        echo "bitbucket-pipelines"
    else
        echo "local"
    fi
}

get_pipeline_info() {
    local ci_system
    ci_system=$(detect_ci_system)
    
    case "$ci_system" in
        "github-actions")
            cat << EOF
{
    "ci_system": "github-actions",
    "ci_system_version": "2.0",
    "pipeline_id": "${GITHUB_RUN_ID:-}",
    "pipeline_url": "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}",
    "job_id": "${GITHUB_JOB:-}",
    "job_url": "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}",
    "trigger_type": "${GITHUB_EVENT_NAME:-}",
    "trigger_actor": "${GITHUB_ACTOR:-}",
    "trigger_ref": "${GITHUB_REF:-}",
    "workflow_name": "${GITHUB_WORKFLOW:-}",
    "runner_name": "${RUNNER_NAME:-}",
    "runner_os": "${RUNNER_OS:-}"
}
EOF
            ;;
        "gitlab-ci")
            cat << EOF
{
    "ci_system": "gitlab-ci",
    "ci_system_version": "${CI_SERVER_VERSION:-}",
    "pipeline_id": "${CI_PIPELINE_ID:-}",
    "pipeline_url": "${CI_PIPELINE_URL:-}",
    "job_id": "${CI_JOB_ID:-}",
    "job_url": "${CI_JOB_URL:-}",
    "trigger_type": "${CI_PIPELINE_SOURCE:-}",
    "trigger_actor": "${GITLAB_USER_LOGIN:-}",
    "trigger_ref": "${CI_COMMIT_REF_NAME:-}",
    "project_name": "${CI_PROJECT_NAME:-}",
    "project_path": "${CI_PROJECT_PATH:-}"
}
EOF
            ;;
        "jenkins")
            cat << EOF
{
    "ci_system": "jenkins",
    "ci_system_version": "",
    "pipeline_id": "${BUILD_NUMBER:-}",
    "pipeline_url": "${BUILD_URL:-}",
    "job_id": "${JOB_NAME:-}",
    "job_url": "${JOB_URL:-}",
    "trigger_type": "${BUILD_CAUSE:-}",
    "trigger_actor": "${BUILD_USER:-}",
    "trigger_ref": "${GIT_BRANCH:-}",
    "node_name": "${NODE_NAME:-}"
}
EOF
            ;;
        "azure-devops")
            cat << EOF
{
    "ci_system": "azure-devops",
    "ci_system_version": "",
    "pipeline_id": "${BUILD_BUILDID:-}",
    "pipeline_url": "${SYSTEM_TEAMFOUNDATIONCOLLECTIONURI:-}${SYSTEM_TEAMPROJECT:-}/_build/results?buildId=${BUILD_BUILDID:-}",
    "job_id": "${SYSTEM_JOBID:-}",
    "job_url": "",
    "trigger_type": "${BUILD_REASON:-}",
    "trigger_actor": "${BUILD_REQUESTEDFOR:-}",
    "trigger_ref": "${BUILD_SOURCEBRANCH:-}",
    "agent_name": "${AGENT_NAME:-}"
}
EOF
            ;;
        "circleci")
            cat << EOF
{
    "ci_system": "circleci",
    "ci_system_version": "",
    "pipeline_id": "${CIRCLE_WORKFLOW_ID:-}",
    "pipeline_url": "${CIRCLE_BUILD_URL:-}",
    "job_id": "${CIRCLE_JOB:-}",
    "job_url": "${CIRCLE_BUILD_URL:-}",
    "trigger_type": "",
    "trigger_actor": "${CIRCLE_USERNAME:-}",
    "trigger_ref": "${CIRCLE_BRANCH:-}",
    "project_name": "${CIRCLE_PROJECT_REPONAME:-}"
}
EOF
            ;;
        "bitbucket-pipelines")
            cat << EOF
{
    "ci_system": "bitbucket-pipelines",
    "ci_system_version": "",
    "pipeline_id": "${BITBUCKET_PIPELINE_UUID:-}",
    "pipeline_url": "https://bitbucket.org/${BITBUCKET_WORKSPACE:-}/${BITBUCKET_REPO_SLUG:-}/pipelines/results/${BITBUCKET_BUILD_NUMBER:-}",
    "job_id": "${BITBUCKET_STEP_UUID:-}",
    "job_url": "",
    "trigger_type": "${BITBUCKET_PR_ID:+pull_request}",
    "trigger_actor": "",
    "trigger_ref": "${BITBUCKET_BRANCH:-}"
}
EOF
            ;;
        *)
            cat << EOF
{
    "ci_system": "local",
    "ci_system_version": "",
    "pipeline_id": "local-$(date +%s)",
    "pipeline_url": "",
    "job_id": "",
    "job_url": "",
    "trigger_type": "manual",
    "trigger_actor": "$(whoami)",
    "trigger_ref": ""
}
EOF
            ;;
    esac
}

# ============================================================================
# SOURCE CODE INFORMATION
# ============================================================================

get_source_info() {
    local repo_url=""
    local commit_sha=""
    local commit_sha_short=""
    local commit_message=""
    local commit_author=""
    local commit_timestamp=""
    local branch=""
    local tag=""
    local is_tag="false"
    local pr_number=""
    local pr_url=""
    
    # Try to get info from CI environment first
    local ci_system
    ci_system=$(detect_ci_system)
    
    case "$ci_system" in
        "github-actions")
            repo_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}"
            commit_sha="${GITHUB_SHA:-}"
            branch="${GITHUB_REF_NAME:-}"
            if [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
                tag="${GITHUB_REF_NAME:-}"
                is_tag="true"
            fi
            if [[ -n "${GITHUB_HEAD_REF:-}" ]]; then
                pr_number="${GITHUB_REF_NAME:-}"
                pr_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/pull/${pr_number}"
            fi
            ;;
        "gitlab-ci")
            repo_url="${CI_PROJECT_URL:-}"
            commit_sha="${CI_COMMIT_SHA:-}"
            commit_message="${CI_COMMIT_MESSAGE:-}"
            commit_author="${CI_COMMIT_AUTHOR:-}"
            commit_timestamp="${CI_COMMIT_TIMESTAMP:-}"
            branch="${CI_COMMIT_REF_NAME:-}"
            tag="${CI_COMMIT_TAG:-}"
            if [[ -n "$tag" ]]; then
                is_tag="true"
            fi
            if [[ -n "${CI_MERGE_REQUEST_IID:-}" ]]; then
                pr_number="${CI_MERGE_REQUEST_IID}"
                pr_url="${CI_MERGE_REQUEST_PROJECT_URL:-}/merge_requests/${pr_number}"
            fi
            ;;
    esac
    
    # Fall back to git commands if available and info is missing
    if command -v git &> /dev/null && git rev-parse --git-dir &> /dev/null; then
        [[ -z "$repo_url" ]] && repo_url=$(git config --get remote.origin.url 2>/dev/null || echo "")
        [[ -z "$commit_sha" ]] && commit_sha=$(git rev-parse HEAD 2>/dev/null || echo "")
        [[ -z "$commit_message" ]] && commit_message=$(git log -1 --pretty=%B 2>/dev/null | head -1 || echo "")
        [[ -z "$commit_author" ]] && commit_author=$(git log -1 --pretty=%ae 2>/dev/null || echo "")
        [[ -z "$commit_timestamp" ]] && commit_timestamp=$(git log -1 --pretty=%aI 2>/dev/null || echo "")
        [[ -z "$branch" ]] && branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
        
        # Check if current commit is a tag
        if [[ -z "$tag" ]]; then
            tag=$(git describe --tags --exact-match 2>/dev/null || echo "")
            [[ -n "$tag" ]] && is_tag="true"
        fi
    fi
    
    # Generate short SHA
    [[ -n "$commit_sha" ]] && commit_sha_short="${commit_sha:0:7}"
    
    # Clean up repo URL (remove .git suffix and convert SSH to HTTPS)
    repo_url="${repo_url%.git}"
    repo_url="${repo_url/user@example.com:/https://github.com/}"
    repo_url="${repo_url/user@example.com:/https://gitlab.com/}"
    
    cat << EOF
{
    "repository_url": "$repo_url",
    "repository_type": "git",
    "commit_sha": "$commit_sha",
    "commit_sha_short": "$commit_sha_short",
    "commit_message": $(echo "$commit_message" | jq -Rs .),
    "commit_author": "$commit_author",
    "commit_timestamp": "$commit_timestamp",
    "branch": "$branch",
    "tag": "$tag",
    "is_tag": $is_tag,
    "pr_number": "$pr_number",
    "pr_url": "$pr_url"
}
EOF
}

# ============================================================================
# CONTAINER INFORMATION
# ============================================================================

get_container_info() {
    local image_ref="$1"
    
    log_debug "Inspecting image: $image_ref"
    
    # Get image inspection data
    local inspect_data
    inspect_data=$($CONTAINER_RUNTIME inspect "$image_ref" 2>/dev/null) || {
        log_error "Failed to inspect image: $image_ref"
        exit 1
    }
    
    # Parse image reference components
    local registry=""
    local repository=""
    local image_name=""
    local tag=""
    local digest=""
    
    # Extract digest if present in reference
    if [[ "$image_ref" == *"@sha256:"* ]]; then
        digest="${image_ref##*@}"
        image_ref="${image_ref%@*}"
    fi
    
    # Extract tag
    if [[ "$image_ref" == *":"* ]]; then
        tag="${image_ref##*:}"
        image_ref="${image_ref%:*}"
    else
        tag="latest"
    fi
    
    # Extract registry and repository
    if [[ "$image_ref" == *"/"* ]]; then
        # Check if first part is a registry (contains . or :)
        local first_part="${image_ref%%/*}"
        if [[ "$first_part" == *"."* ]] || [[ "$first_part" == *":"* ]] || [[ "$first_part" == "localhost" ]]; then
            registry="$first_part"
            repository="${image_ref#*/}"
        else
            registry="docker.io"
            repository="$image_ref"
        fi
    else
        registry="docker.io"
        repository="library/$image_ref"
    fi
    
    # Extract image name (last component)
    image_name="${repository##*/}"
    
    # Get digest from inspect if not in reference
    if [[ -z "$digest" ]]; then
        digest=$(echo "$inspect_data" | jq -r '.[0].RepoDigests[0] // ""' | grep -oP 'sha256:[a-f0-9]+' || echo "")
    fi
    
    # Extract other metadata from inspect
    local image_id
    local created
    local size_bytes
    local architecture
    local os
    
    image_id=$(echo "$inspect_data" | jq -r '.[0].Id // ""')
    created=$(echo "$inspect_data" | jq -r '.[0].Created // ""')
    size_bytes=$(echo "$inspect_data" | jq -r '.[0].Size // 0')
    architecture=$(echo "$inspect_data" | jq -r '.[0].Architecture // "amd64"')
    os=$(echo "$inspect_data" | jq -r '.[0].Os // "linux"')
    
    # Calculate human-readable size
    local size_human
    if [[ $size_bytes -gt 1073741824 ]]; then
        size_human="$(echo "scale=2; $size_bytes / 1073741824" | bc) GB"
    elif [[ $size_bytes -gt 1048576 ]]; then
        size_human="$(echo "scale=2; $size_bytes / 1048576" | bc) MB"
    else
        size_human="$(echo "scale=2; $size_bytes / 1024" | bc) KB"
    fi
    
    cat << EOF
{
    "image_full_ref": "${registry}/${repository}:${tag}${digest:+@$digest}",
    "registry": "$registry",
    "repository": "$repository",
    "image_name": "$image_name",
    "tag": "$tag",
    "digest": "$digest",
    "image_id": "$image_id",
    "created": "$created",
    "size_bytes": $size_bytes,
    "size_human": "$size_human",
    "architecture": "$architecture",
    "os": "$os"
}
EOF
}

get_base_image_info() {
    local image_ref="$1"
    
    log_debug "Extracting base image information"
    
    # Get image history
    local history
    history=$($CONTAINER_RUNTIME history --no-trunc --format '{{.CreatedBy}}' "$image_ref" 2>/dev/null | tail -n +1) || {
        log_warn "Could not get image history"
        echo '{"image_ref": "", "registry": "", "repository": "", "tag": "", "digest": "", "os_name": "", "os_version": "", "os_id": ""}'
        return
    }
    
    # Try to extract base image from labels first
    local inspect_data
    inspect_data=$($CONTAINER_RUNTIME inspect "$image_ref" 2>/dev/null)
    
    local base_image=""
    base_image=$(echo "$inspect_data" | jq -r '.[0].Config.Labels["org.opencontainers.image.base.name"] // ""')
    
    # If not in labels, try to detect from common patterns
    if [[ -z "$base_image" ]]; then
        # Check for common base images in history
        if echo "$history" | grep -qi "alpine"; then
            base_image="alpine"
        elif echo "$history" | grep -qi "debian\|bookworm\|bullseye\|buster"; then
            base_image="debian"
        elif echo "$history" | grep -qi "ubuntu\|focal\|jammy\|noble"; then
            base_image="ubuntu"
        elif echo "$history" | grep -qi "python"; then
            # Try to extract python version
            base_image=$(echo "$history" | grep -oiP 'python[:\s]*[\d.]+' | head -1 || echo "python")
        elif echo "$history" | grep -qi "node"; then
            base_image=$(echo "$history" | grep -oiP 'node[:\s]*[\d.]+' | head -1 || echo "node")
        elif echo "$history" | grep -qi "golang\|go:"; then
            base_image=$(echo "$history" | grep -oiP 'golang?[:\s]*[\d.]+' | head -1 || echo "golang")
        fi
    fi
    
    # Detect OS info from /etc/os-release if possible
    local os_name=""
    local os_version=""
    local os_id=""
    
    # Try to run a quick command to get OS info
    local os_release
    os_release=$($CONTAINER_RUNTIME run --rm --entrypoint cat "$image_ref" /etc/os-release 2>/dev/null || echo "")
    
    if [[ -n "$os_release" ]]; then
        os_name=$(echo "$os_release" | grep "^NAME=" | cut -d= -f2 | tr -d '"')
        os_version=$(echo "$os_release" | grep "^VERSION_ID=" | cut -d= -f2 | tr -d '"')
        os_id=$(echo "$os_release" | grep "^ID=" | cut -d= -f2 | tr -d '"')
    fi
    
    # Parse base image reference
    local base_registry=""
    local base_repository=""
    local base_tag=""
    
    if [[ -n "$base_image" ]]; then
        if [[ "$base_image" == *":"* ]]; then
            base_tag="${base_image##*:}"
            base_image="${base_image%:*}"
        fi
        if [[ "$base_image" == *"/"* ]]; then
            local first_part="${base_image%%/*}"
            if [[ "$first_part" == *"."* ]]; then
                base_registry="$first_part"
                base_repository="${base_image#*/}"
            else
                base_registry="docker.io"
                base_repository="$base_image"
            fi
        else
            base_registry="docker.io"
            base_repository="library/$base_image"
        fi
    fi
    
    cat << EOF
{
    "image_ref": "$base_image${base_tag:+:$base_tag}",
    "registry": "$base_registry",
    "repository": "$base_repository",
    "tag": "$base_tag",
    "digest": "",
    "os_name": "$os_name",
    "os_version": "$os_version",
    "os_id": "$os_id"
}
EOF
}

get_layer_info() {
    local image_ref="$1"
    
    if [[ "$INCLUDE_LAYERS" != "true" ]]; then
        echo '{"total_count": 0, "base_layers": 0, "application_layers": 0, "layer_details": []}'
        return
    fi
    
    log_debug "Extracting layer information"
    
    # Get image inspection data
    local inspect_data
    inspect_data=$($CONTAINER_RUNTIME inspect "$image_ref" 2>/dev/null)
    
    # Get layer digests
    local layers
    layers=$(echo "$inspect_data" | jq -r '.[0].RootFS.Layers // []')
    local total_count
    total_count=$(echo "$layers" | jq 'length')
    
    # Get history for layer details
    local history
    history=$($CONTAINER_RUNTIME history --no-trunc --format '{{json .}}' "$image_ref" 2>/dev/null || echo "[]")
    
    # Build layer details array
    local layer_details="[]"
    local index=0
    
    while read -r layer_digest; do
        [[ -z "$layer_digest" ]] && continue
        
        # Try to get corresponding history entry
        local created_by=""
        local size=0
        
        # Note: History is in reverse order (newest first)
        local history_entry
        history_entry=$(echo "$history" | jq -s ".[$index] // {}")
        created_by=$(echo "$history_entry" | jq -r '.CreatedBy // ""')
        size=$(echo "$history_entry" | jq -r '.Size // "0"' | grep -oP '\d+' | head -1 || echo "0")
        
        # Determine if this is a base layer (heuristic: early layers without COPY/ADD commands)
        local is_base_layer="false"
        if [[ $index -lt 5 ]] && [[ ! "$created_by" =~ ^(COPY|ADD) ]]; then
            is_base_layer="true"
        fi
        
        layer_details=$(echo "$layer_details" | jq --arg digest "$layer_digest" \
            --arg created_by "$created_by" \
            --argjson size "$size" \
            --argjson index "$index" \
            --argjson is_base "$is_base_layer" \
            '. + [{
                "index": $index,
                "digest": $digest,
                "size_bytes": $size,
                "created_by": $created_by,
                "is_base_layer": $is_base
            }]')
        
        ((index++))
    done < <(echo "$layers" | jq -r '.[]')
    
    # Count base vs application layers
    local base_layers
    local app_layers
    base_layers=$(echo "$layer_details" | jq '[.[] | select(.is_base_layer == true)] | length')
    app_layers=$(echo "$layer_details" | jq '[.[] | select(.is_base_layer == false)] | length')
    
    cat << EOF
{
    "total_count": $total_count,
    "base_layers": $base_layers,
    "application_layers": $app_layers,
    "layer_details": $layer_details
}
EOF
}

get_labels() {
    local image_ref="$1"
    
    if [[ "$INCLUDE_LABELS" != "true" ]]; then
        echo '{}'
        return
    fi
    
    log_debug "Extracting image labels"
    
    local inspect_data
    inspect_data=$($CONTAINER_RUNTIME inspect "$image_ref" 2>/dev/null)
    
    echo "$inspect_data" | jq '.[0].Config.Labels // {}'
}

get_build_info() {
    local image_ref="$1"
    
    log_debug "Extracting build information"
    
    # Get builder info
    local builder="$CONTAINER_RUNTIME"
    local builder_version=""
    local buildkit_version=""
    
    builder_version=$($CONTAINER_RUNTIME version --format '{{.Server.Version}}' 2>/dev/null || echo "")
    
    # Check for buildkit
    if [[ "$CONTAINER_RUNTIME" == "docker" ]]; then
        buildkit_version=$(docker buildx version 2>/dev/null | grep -oP 'v[\d.]+' | head -1 || echo "")
    fi
    
    # Try to get Dockerfile path from labels
    local inspect_data
    inspect_data=$($CONTAINER_RUNTIME inspect "$image_ref" 2>/dev/null)
    
    local dockerfile_path=""
    dockerfile_path=$(echo "$inspect_data" | jq -r '.[0].Config.Labels["dockerfile-path"] // "Dockerfile"')
    
    # Get build timestamp from image creation
    local build_end
    build_end=$(echo "$inspect_data" | jq -r '.[0].Created // ""')
    
    # Build args (if available from labels)
    local build_args="[]"
    
    # Get build host info
    local build_host=""
    local ci_system
    ci_system=$(detect_ci_system)
    
    case "$ci_system" in
        "github-actions")
            build_host="${RUNNER_NAME:-github-runner}"
            ;;
        "gitlab-ci")
            build_host="${CI_RUNNER_DESCRIPTION:-gitlab-runner}"
            ;;
        *)
            build_host="$(hostname 2>/dev/null || echo 'local')"
            ;;
    esac
    
    cat << EOF
{
    "builder": "$builder",
    "builder_version": "$builder_version",
    "buildkit_version": "$buildkit_version",
    "dockerfile_path": "$dockerfile_path",
    "build_context": ".",
    "build_args": $build_args,
    "build_start": "",
    "build_end": "$build_end",
    "build_duration_seconds": 0,
    "build_host": "$build_host",
    "build_platform": "linux/$(uname -m)"
}
EOF
}

# ============================================================================
# PHOENIX TAGS GENERATION
# ============================================================================

generate_phoenix_tags() {
    local container_info="$1"
    local source_info="$2"
    local pipeline_info="$3"
    local base_image_info="$4"
    local layers_info="$5"
    
    if [[ "$GENERATE_PHOENIX_TAGS" != "true" ]]; then
        echo '[]'
        return
    fi
    
    log_debug "Generating Phoenix tags"
    
    local tags="[]"
    
    # Container tags
    local image_name
    local image_tag
    local image_digest
    
    image_name=$(echo "$container_info" | jq -r '.image_name // ""')
    image_tag=$(echo "$container_info" | jq -r '.tag // ""')
    image_digest=$(echo "$container_info" | jq -r '.digest // ""')
    
    [[ -n "$image_name" ]] && tags=$(echo "$tags" | jq --arg v "$image_name" '. + [{"key": "image-name", "value": $v}]')
    [[ -n "$image_tag" ]] && tags=$(echo "$tags" | jq --arg v "$image_tag" '. + [{"key": "image-tag", "value": $v}]')
    [[ -n "$image_digest" ]] && tags=$(echo "$tags" | jq --arg v "${image_digest:0:20}" '. + [{"key": "image-digest", "value": $v}]')
    
    # Base image tag
    local base_image
    base_image=$(echo "$base_image_info" | jq -r '.image_ref // ""')
    [[ -n "$base_image" ]] && tags=$(echo "$tags" | jq --arg v "$base_image" '. + [{"key": "base-image", "value": $v}]')
    
    # Source tags
    local repo_url
    local commit_sha
    local branch
    
    repo_url=$(echo "$source_info" | jq -r '.repository_url // ""')
    commit_sha=$(echo "$source_info" | jq -r '.commit_sha_short // ""')
    branch=$(echo "$source_info" | jq -r '.branch // ""')
    
    # Clean repo URL for tag value
    repo_url="${repo_url#https://}"
    repo_url="${repo_url#http://}"
    
    [[ -n "$repo_url" ]] && tags=$(echo "$tags" | jq --arg v "$repo_url" '. + [{"key": "source-repo", "value": $v}]')
    [[ -n "$commit_sha" ]] && tags=$(echo "$tags" | jq --arg v "$commit_sha" '. + [{"key": "commit-sha", "value": $v}]')
    [[ -n "$branch" ]] && tags=$(echo "$tags" | jq --arg v "$branch" '. + [{"key": "branch", "value": $v}]')
    
    # Pipeline tags
    local ci_system
    local pipeline_id
    
    ci_system=$(echo "$pipeline_info" | jq -r '.ci_system // ""')
    pipeline_id=$(echo "$pipeline_info" | jq -r '.pipeline_id // ""')
    
    [[ -n "$ci_system" ]] && tags=$(echo "$tags" | jq --arg v "$ci_system" '. + [{"key": "ci-system", "value": $v}]')
    [[ -n "$pipeline_id" ]] && tags=$(echo "$tags" | jq --arg v "$pipeline_id" '. + [{"key": "pipeline-id", "value": $v}]')
    
    # Build date
    local build_date
    build_date=$(date +%Y-%m-%d)
    tags=$(echo "$tags" | jq --arg v "$build_date" '. + [{"key": "build-date", "value": $v}]')
    
    # Layer count
    local layer_count
    layer_count=$(echo "$layers_info" | jq -r '.total_count // 0')
    [[ "$layer_count" -gt 0 ]] && tags=$(echo "$tags" | jq --arg v "$layer_count" '. + [{"key": "layer-count", "value": $v}]')
    
    echo "$tags"
}

# ============================================================================
# MAIN OUTPUT GENERATION
# ============================================================================

generate_metadata() {
    local image_ref="$1"
    
    log_info "Capturing metadata for: $image_ref"
    
    # Capture all information
    log_info "Gathering container information..."
    local container_info
    container_info=$(get_container_info "$image_ref")
    
    log_info "Gathering base image information..."
    local base_image_info
    base_image_info=$(get_base_image_info "$image_ref")
    
    log_info "Gathering layer information..."
    local layers_info
    layers_info=$(get_layer_info "$image_ref")
    
    log_info "Gathering source information..."
    local source_info
    source_info=$(get_source_info)
    
    log_info "Gathering build information..."
    local build_info
    build_info=$(get_build_info "$image_ref")
    
    log_info "Gathering pipeline information..."
    local pipeline_info
    pipeline_info=$(get_pipeline_info)
    
    log_info "Gathering labels..."
    local labels
    labels=$(get_labels "$image_ref")
    
    log_info "Generating Phoenix tags..."
    local phoenix_tags
    phoenix_tags=$(generate_phoenix_tags "$container_info" "$source_info" "$pipeline_info" "$base_image_info" "$layers_info")
    
    # Build complete metadata JSON
    local metadata
    metadata=$(jq -n \
        --arg metadata_version "$METADATA_VERSION" \
        --arg capture_timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson container "$container_info" \
        --argjson base_image "$base_image_info" \
        --argjson layers "$layers_info" \
        --argjson source "$source_info" \
        --argjson build "$build_info" \
        --argjson pipeline "$pipeline_info" \
        --argjson labels "$labels" \
        --argjson phoenix_tags "$phoenix_tags" \
        '{
            metadata_version: $metadata_version,
            capture_timestamp: $capture_timestamp,
            container: $container,
            base_image: $base_image,
            layers: $layers,
            source: $source,
            build: $build,
            pipeline: $pipeline,
            labels: $labels,
            phoenix_tags: $phoenix_tags
        }')
    
    echo "$metadata"
}

output_metadata() {
    local metadata="$1"
    local output_file="$2"
    local format="$3"
    
    local output
    
    if [[ "$format" == "yaml" ]]; then
        if command -v yq &> /dev/null; then
            output=$(echo "$metadata" | yq -P '.')
        else
            # Fallback: output JSON with YAML header comment
            output="# Phoenix Container Metadata (JSON format - install yq for YAML)
$metadata"
        fi
    else
        output=$(echo "$metadata" | jq '.')
    fi
    
    if [[ -n "$output_file" ]]; then
        echo "$output" > "$output_file"
        log_success "Metadata written to: $output_file"
    else
        echo "$output"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    local image_ref=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --no-layers)
                INCLUDE_LAYERS=false
                shift
                ;;
            --no-labels)
                INCLUDE_LABELS=false
                shift
                ;;
            --no-phoenix-tags)
                GENERATE_PHOENIX_TAGS=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --json)
                OUTPUT_FORMAT="json"
                shift
                ;;
            --yaml)
                OUTPUT_FORMAT="yaml"
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$image_ref" ]]; then
                    image_ref="$1"
                else
                    log_error "Unexpected argument: $1"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$image_ref" ]]; then
        log_error "Image reference is required"
        show_help
        exit 1
    fi
    
    # Set default output file if not specified
    if [[ -z "$OUTPUT_FILE" ]]; then
        OUTPUT_FILE="container_metadata.${OUTPUT_FORMAT}"
    fi
    
    # Check dependencies
    check_dependencies
    
    # Generate and output metadata
    local metadata
    metadata=$(generate_metadata "$image_ref")
    
    output_metadata "$metadata" "$OUTPUT_FILE" "$OUTPUT_FORMAT"
    
    log_success "Container metadata capture complete!"
    
    # Print summary
    echo ""
    log_info "Summary:"
    echo "  Image: $(echo "$metadata" | jq -r '.container.image_full_ref')"
    echo "  Base: $(echo "$metadata" | jq -r '.base_image.image_ref // "unknown"')"
    echo "  Layers: $(echo "$metadata" | jq -r '.layers.total_count')"
    echo "  Commit: $(echo "$metadata" | jq -r '.source.commit_sha_short // "unknown"')"
    echo "  CI System: $(echo "$metadata" | jq -r '.pipeline.ci_system')"
    echo "  Phoenix Tags: $(echo "$metadata" | jq '.phoenix_tags | length')"
}

# Run main function
main "$@"
