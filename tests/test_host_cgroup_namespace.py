from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HostCgroupNamespaceTests(unittest.TestCase):
    def test_candidate_and_contract_require_host_cgroup_namespace(self) -> None:
        compose = (ROOT / "codestra/deploy/compose.candidate.yaml").read_text()
        self.assertEqual(compose.count("\n    cgroup: host\n"), 1)
        runtime = json.loads((ROOT / "codestra/runtime.v1.json").read_text())
        self.assertIs(runtime["hostAccess"]["hostCgroupNamespace"], True)
        validator = (ROOT / "scripts/validate_codestra_cadvisor.py").read_text()
        self.assertIn('cadvisor.get("cgroup") != "host"', validator)
        self.assertIn('host_access.get("hostCgroupNamespace") is not True', validator)


if __name__ == "__main__":
    unittest.main()
