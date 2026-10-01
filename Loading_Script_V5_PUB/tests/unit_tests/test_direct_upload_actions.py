#!/usr/bin/env python3
"""simple-upload-actions: run_direct_upload.sh works from any working directory, Azure DevOps
metadata records the job name as ci_job, and the CI templates are single, valid documents that
point at this Loading_Script_V5_PUB directory. The Jenkins examples keep reading the API URL from
the phoenix-api-base-url credential, as existing jobs expect."""

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = ROOT / "simple-upload-actions"


class _DuplicateKeyLoader(yaml.SafeLoader):
    pass


def _mapping_without_duplicates(loader, node, deep=False):
    keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
    duplicates = sorted({k for k in keys if keys.count(k) > 1}, key=str)
    if duplicates:
        raise ValueError(f"duplicate keys {duplicates} at line {node.start_mark.line + 1}")
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_DuplicateKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_without_duplicates)


class TestRunDirectUpload(unittest.TestCase):
    def test_runs_from_another_working_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp) / "calls.jsonl"
            shim = Path(tmp) / "python"  # records how the wrapper invokes python instead of running it
            shim.write_text("#!/bin/sh\nexec \"%s\" -c 'import json,sys; open(sys.argv[1],\"a\").write("
                            "json.dumps(sys.argv[2:])+\"\\n\")' \"%s\" \"$@\"\n" % (sys.executable, calls))
            shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=f"{tmp}{os.pathsep}{os.environ['PATH']}")
            subprocess.run(["bash", str(ACTIONS / "run_direct_upload.sh"), "--file", "scan.json"],
                           cwd=tmp, env=env, check=True, capture_output=True)
            tag_call, import_call = [json.loads(line) for line in calls.read_text().splitlines()]
        self.assertEqual(Path(tag_call[0]), ACTIONS / "generate_pipeline_tag_file.py")
        self.assertEqual(Path(import_call[0]), ROOT / "phoenix_multi_scanner_enhanced.py")
        self.assertEqual(Path(import_call[import_call.index("--tag-file") + 1]), ROOT / "pipeline-tags.yaml")


class TestPipelineMetadata(unittest.TestCase):
    def test_azure_ci_job_is_the_job_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PATH": os.environ["PATH"], "TF_BUILD": "True",
                   "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://dev.azure.example.invalid/",
                   "SYSTEM_JOBDISPLAYNAME": "Security scan job", "BUILD_DEFINITIONNAME": "Pipeline name"}
            subprocess.run([sys.executable, str(ACTIONS / "generate_pipeline_tag_file.py"),
                            "--output", "tags.yaml", "--metadata-json", "meta.json"],
                           cwd=tmp, env=env, check=True, capture_output=True)
            metadata = json.loads((Path(tmp) / "meta.json").read_text())
        self.assertEqual(metadata["ci_job"], "Security scan job")
        self.assertEqual(metadata["ci_workflow"], "Pipeline name")


class TestTemplates(unittest.TestCase):
    TEMPLATES = ("github-actions-direct-upload.yml", "github-actions-direct-upload-minimal.yml",
                 "Jenkinsfile.direct-upload", "Jenkinsfile.direct-upload-minimal")

    def test_github_workflows_have_no_duplicate_keys(self):
        for name in self.TEMPLATES[:2]:
            with self.subTest(template=name):
                workflow = yaml.load((ACTIONS / name).read_text(), _DuplicateKeyLoader)
                self.assertIn("jobs", workflow)

    def test_jenkinsfiles_have_one_pipeline_and_one_parameters_block(self):
        for name in self.TEMPLATES[2:]:
            with self.subTest(template=name):
                text = (ACTIONS / name).read_text()
                self.assertEqual(len(re.findall(r"^pipeline\s*\{", text, re.M)), 1)
                self.assertEqual(len(re.findall(r"^\s*parameters\s*\{", text, re.M)), 1)

    def test_jenkinsfiles_take_the_api_url_from_the_credential(self):
        for name in self.TEMPLATES[2:]:
            with self.subTest(template=name):
                text = (ACTIONS / name).read_text()
                self.assertIn("PHOENIX_API_BASE_URL = credentials('phoenix-api-base-url')", text)
                self.assertNotIn("params.PHOENIX_API_BASE_URL", text)

    def test_templates_use_this_directory(self):
        for name in self.TEMPLATES:
            with self.subTest(template=name):
                self.assertIsNone(re.search(r"Loading_Script_V5(?!_PUB)", (ACTIONS / name).read_text()))


if __name__ == "__main__":
    unittest.main()
