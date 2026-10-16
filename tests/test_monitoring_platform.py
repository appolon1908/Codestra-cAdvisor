"""Monitoring-platform contract: private listener, credentials only as OpenBao references, no business effect."""
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("monitoring_platform", ROOT / "scripts" / "validate_monitoring_platform.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class MonitoringPlatformTests(unittest.TestCase):
    def test_validator_passes(self) -> None:
        result = subprocess.run([sys.executable, "scripts/validate_monitoring_platform.py"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MONITORING_PLATFORM_PUBLIC_LISTENER=NONE", result.stdout)

    def test_declaration_is_private_and_effect_free(self) -> None:
        platform = json.loads((ROOT / "codestra/monitoring-platform.v1.json").read_text(encoding="utf-8"))
        self.assertFalse(platform["listener"]["hostPortPublished"])
        self.assertFalse(platform["listener"]["internetIngress"])
        self.assertFalse(platform["businessEffects"]["providerWrites"])
        self.assertFalse(platform["credentialPolicy"]["secretMaterialInGit"])
        self.assertFalse(platform["runtimeApplyAuthorized"])

    def test_inline_credentials_are_detected_but_file_and_secret_names_are_not(self) -> None:
        self.assertIsNone(MODULE.inline_credential("DATA_SOURCE_PASS_FILE: /run/secrets/x\nREDIS_EXPORTER_PASSWORD_MAP_SECRET=codestra-redis-map\n"))
        self.assertEqual(MODULE.inline_credential("REDIS_PASSWORD=Sup3rSecretValue99\n"), "REDIS_PASSWORD")

    def test_secret_references_never_carry_values(self) -> None:
        path = ROOT / "codestra/secret-references.v1.json"
        if not path.exists():
            self.skipTest("credential-free exporter")
        document = json.loads(path.read_text(encoding="utf-8"))
        poisoned = copy.deepcopy(document)
        poisoned["references"][0]["password"] = "x"
        with self.assertRaises(SystemExit):
            MODULE.reject_secret_material(poisoned, "root")
        for reference in document["references"]:
            self.assertEqual(reference["provider"], "openbao")
            self.assertTrue(reference["secret_ref"].startswith(f"codestra/{reference['environment']}/observability/exporters/"))


if __name__ == "__main__":
    unittest.main()
