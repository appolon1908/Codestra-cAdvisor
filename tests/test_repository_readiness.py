from __future__ import annotations
import json, subprocess, unittest
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[1]
class ReadinessTests(unittest.TestCase):
    def test_validator(self) -> None:
        subprocess.run(["python3", "scripts/validate_repository_readiness.py"], cwd=ROOT, check=True)
    def test_two_release_jobs_are_structurally_pinned(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/release-images.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(jobs["release-cadvisor"]["with"]["image_id"], "cadvisor")
        self.assertEqual(jobs["release-proxy"]["with"]["image_id"], "cadvisor-proxy")
        for name in ("release-cadvisor", "release-proxy"):
            self.assertTrue(jobs[name]["uses"].endswith("@9a6aebb849bbc068105c10d9d1dfd39ebf6f78bd"))
    def test_base_lock_and_manifests_agree(self) -> None:
        lock = json.loads((ROOT / "codestra/release/runtime-base.lock.json").read_text())
        cadvisor = json.loads((ROOT / "codestra/release/cadvisor-image-build.v1.json").read_text())
        proxy = json.loads((ROOT / "codestra/release/proxy-image-build.v1.json").read_text())
        self.assertEqual(cadvisor["buildArgs"]["CADVISOR_BASE_IMAGE"], lock["cadvisorBaseImage"])
        self.assertEqual(proxy["buildArgs"]["PROXY_RUNTIME_IMAGE"], lock["proxyRuntimeImage"])
        self.assertEqual(lock["cadvisorBinaryRevisionReadback"], lock["vendoredSourceSnapshotCommit"][:7])
        self.assertTrue(lock["vendoredSourceUsedByImageBuild"])
    def test_legacy_unsafe_manifests_are_absent(self) -> None:
        for relative in ("deploy/compose.yaml", "codestra/runtime-v1/compose.yaml", "codestra/runtime-v1/compose-codestra.yaml"):
            self.assertFalse((ROOT / relative).exists())
    def test_vendored_upstream_is_byte_preserved(self) -> None:
        self.assertEqual((ROOT / ".gitattributes").read_text().splitlines()[-1], "upstream/** -whitespace")
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        tree = subprocess.run(
            ["git", "rev-parse", "HEAD:upstream"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(lock["imported_tree_sha"], tree)
        workflow = (ROOT / ".github/workflows/validate-repository-readiness.yml").read_text()
        self.assertIn("git diff --check \"$BASE_SHA\" \"$HEAD_SHA\" -- . ':(exclude)upstream/**'", workflow)

    def test_runtime_image_validator_rejects_mutable_and_malformed_values(self) -> None:
        import importlib.util

        path = ROOT / "scripts/validate_runtime_images.py"
        spec = importlib.util.spec_from_file_location("runtime_images", path)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        good = {
            name: f"registry.example/codestra/{name.lower()}:v1@sha256:{'a' * 64}"
            for name in module.REQUIRED
        }
        module.validate(good)
        good["CODESTRA_CADVISOR_IMAGE"] = (
            f"registry.example:5000/team/cadvisor@sha256:{'b' * 64}"
        )
        module.validate(good)
        for numeric_tag in ("0", "65536", "99999"):
            good["CODESTRA_CADVISOR_IMAGE"] = (
                f"repo:{numeric_tag}@sha256:{'b' * 64}"
            )
            module.validate(good)
        for invalid in (
            "repo:latest",
            "repo:sha256-test",
            "repo@sha256:1234",
            f"registry.example:0/team/cadvisor@sha256:{'c' * 64}",
            f"registry.example:65536/team/cadvisor@sha256:{'d' * 64}",
            f"registry.example:99999/team/cadvisor@sha256:{'e' * 64}",
        ):
            values = dict(good)
            values["CODESTRA_CADVISOR_IMAGE"] = invalid
            with self.assertRaises(SystemExit):
                module.validate(values)

        workflow = (ROOT / ".github/workflows/validate-codestra-cadvisor.yml").read_text()
        self.assertIn("from scripts.validate_runtime_images import valid_image", workflow)
if __name__ == "__main__": unittest.main()
