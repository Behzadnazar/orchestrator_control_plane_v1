from __future__ import annotations

import pytest

from tests.common import ControlPlaneBaseTestCase


@pytest.mark.smoke
class ControlPlaneSmokeTests(ControlPlaneBaseTestCase):
    def test_health_and_worker_registration(self) -> None:
        health = self.service.health()
        self.assertEqual(health["status"], "ok")
        self.assertIn("backend-worker-v2", health["registered_workers"])
        self.assertGreaterEqual(health["worker_count"], 3)
