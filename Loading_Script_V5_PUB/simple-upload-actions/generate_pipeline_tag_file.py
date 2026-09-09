#!/usr/bin/env python3
"""
Generate a Phoenix tag YAML file from CI/CD environment metadata.

This file is intended for direct uploads with:
  phoenix_multi_scanner_enhanced.py --tag-file <generated-file>
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, Tuple

import yaml


def _first_env(*keys: str) -> str:
    for key in keys:
        value = os.getenv(key, "").strip()
        if value:
            return value
    return ""


def _detect_provider() -> str:
    if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
        return "github_actions"
    if os.getenv("JENKINS_URL"):
        return "jenkins"
    if os.getenv("GITLAB_CI", "").lower() == "true":
        return "gitlab_ci"
    if os.getenv("TF_BUILD", "").lower() == "true":
        return "azure_devops"
    return "generic_ci"


def _collect_metadata() -> Tuple[Dict[str, str], str]:
    provider = _detect_provider()

    metadata: Dict[str, str] = {
        "ci_provider": provider,
        "ci_repo": _first_env("GITHUB_REPOSITORY", "JOB_NAME", "BUILD_REPOSITORY_NAME", "CI_PROJECT_PATH"),
        "ci_branch": _first_env("GITHUB_REF_NAME", "BRANCH_NAME", "BUILD_SOURCEBRANCHNAME", "CI_COMMIT_REF_NAME"),
        "ci_commit": _first_env("GITHUB_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION", "CI_COMMIT_SHA"),
        "ci_run_id": _first_env("GITHUB_RUN_ID", "BUILD_NUMBER", "BUILD_BUILDID", "CI_PIPELINE_ID"),
        "ci_job": _first_env("GITHUB_JOB", "STAGE_NAME", "BUILD_DEFINITIONNAME", "CI_JOB_NAME"),
        "ci_actor": _first_env("GITHUB_ACTOR", "BUILD_REQUESTEDFOR", "GITLAB_USER_LOGIN"),
        "ci_workflow": _first_env("GITHUB_WORKFLOW", "BUILD_DEFINITIONNAME", "CI_PIPELINE_SOURCE"),
        "ci_pipeline_url": _first_env("GITHUB_SERVER_URL", "BUILD_URL", "CI_PIPELINE_URL"),
    }

    # Convert GitHub server URL to the actual run URL when possible.
    if provider == "github_actions":
        server = _first_env("GITHUB_SERVER_URL")
        repo = _first_env("GITHUB_REPOSITORY")
        run_id = _first_env("GITHUB_RUN_ID")
        if server and repo and run_id:
            metadata["ci_pipeline_url"] = f"{server}/{repo}/actions/runs/{run_id}"

    return metadata, provider


def _build_tag_payload(metadata: Dict[str, str]) -> Dict[str, object]:
    tags = [{"key": key, "value": value} for key, value in metadata.items() if value]
    return {"custom_data": tags}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CI metadata tags for Phoenix upload")
    parser.add_argument(
        "--output",
        default="pipeline-tags.yaml",
        help="Output YAML tag file path (default: pipeline-tags.yaml)",
    )
    parser.add_argument(
        "--metadata-json",
        default="pipeline-metadata.json",
        help="Output metadata JSON path for audit/debug (default: pipeline-metadata.json)",
    )
    args = parser.parse_args()

    metadata, provider = _collect_metadata()
    payload = _build_tag_payload(metadata)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    metadata_path = Path(args.metadata_json)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Generated tag file: {output_path}")
    print(f"Generated metadata snapshot: {metadata_path}")
    print(f"Detected CI provider: {provider}")
    print(f"Exported metadata tags: {sum(1 for v in metadata.values() if v)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
