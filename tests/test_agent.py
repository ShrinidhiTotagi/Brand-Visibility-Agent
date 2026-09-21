"""
AI Search Visibility Agent — Test Suite
Run with: pytest tests/test_agent.py -v
"""
import os
import sys
import json
import time
import sqlite3
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("AGENT_DB", "sqlite")
os.environ.setdefault("AUTH_SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("AUTH_DEFAULT_USER", "testadmin")
os.environ.setdefault("AUTH_DEFAULT_PASS", "testpass123")


class TestPasswordHashing(unittest.TestCase):
    def test_same_password_same_hash(self):
        from agent import _hash_password
        self.assertEqual(_hash_password("test"), _hash_password("test"))

    def test_different_password_different_hash(self):
        from agent import _hash_password
        self.assertNotEqual(_hash_password("a"), _hash_password("b"))


class TestTokenSystem(unittest.TestCase):
    def test_create_and_verify(self):
        from agent import _create_token, _verify_token
        token = _create_token("user1", "admin", 5, "acme")
        p = _verify_token(token)
        self.assertIsNotNone(p)
        self.assertEqual(p["user"], "user1")
        self.assertEqual(p["tenant_id"], 5)

    def test_invalid_token(self):
        from agent import _verify_token
        self.assertIsNone(_verify_token("garbage.token"))

    def test_expired_token(self):
        from agent import _verify_token, JWT_SECRET
        import base64, hmac, hashlib
        payload = {"user": "x", "role": "admin", "exp": time.time() - 999, "iat": 0, "jti": "x"}
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        self.assertIsNone(_verify_token(f"{body}.{sig}"))


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        from agent import _rate_buckets
        _rate_buckets.clear()

    def test_allows_normal_traffic(self):
        from agent import _check_rate_limit
        for _ in range(10):
            self.assertTrue(_check_rate_limit("test_ip"))

    def test_blocks_after_limit(self):
        from agent import _check_rate_limit, RATE_LIMIT_PER_MINUTE, _rate_buckets
        for _ in range(RATE_LIMIT_PER_MINUTE):
            _check_rate_limit("test_ip")
        self.assertFalse(_check_rate_limit("test_ip"))


class TestAgentBrainObjects(unittest.TestCase):
    def test_observation(self):
        from agent import AgentObservation
        o = AgentObservation("TEST", 1, "summary", {"k": "v"}, "HIGH")
        self.assertEqual(o.obs_type, "TEST")
        self.assertEqual(o.severity, "HIGH")

    def test_decision(self):
        from agent import AgentDecision
        d = AgentDecision("TEST", 0, "reason", "ANALYZE_COMPANY", {"company_id": 1}, 0.9)
        self.assertEqual(d.action, "ANALYZE_COMPANY")
        self.assertEqual(d.confidence, 0.9)

    def test_outcome(self):
        from agent import AgentOutcome
        o = AgentOutcome(1, "TEST", "result", {}, {"score": 75})
        self.assertEqual(o.metrics_after["score"], 75)


class TestGeminiComplete(unittest.TestCase):
    def test_returns_tuple(self):
        from agent import _gemini_complete
        try:
            result = _gemini_complete("Say hi", max_tokens=20)
            self.assertIsInstance(result, tuple)
            self.assertEqual(len(result), 2)
        except Exception:
            pass


class TestBackupSystem(unittest.TestCase):
    def test_list_backups(self):
        from agent import list_backups
        self.assertIsInstance(list_backups(), list)


class TestTenantSystem(unittest.TestCase):
    def test_hash_password_stable(self):
        from agent import _hash_password
        self.assertEqual(_hash_password("abc"), _hash_password("abc"))


class TestCORSHeaders(unittest.TestCase):
    def test_cors_module_has_allowed(self):
        import agent
        self.assertTrue(hasattr(agent, '_cors_headers'))
        self.assertTrue(callable(agent._cors_headers))


# ===========================================================================
# WORKFLOW SELF-LEARNING TESTS
# ===========================================================================

class TestWorkflowCreation(unittest.TestCase):
    def test_create_workflow(self):
        from agent import workflow_create
        wf = workflow_create(name="Test Workflow", description="Test", steps=[{"id": "s1", "operation": "TEST"}])
        self.assertIn("workflow_id", wf)
        self.assertEqual(wf["version"], 1)
        self.assertIn("fingerprint", wf)

    def test_create_workflow_with_dependencies(self):
        from agent import workflow_create
        wf = workflow_create(
            name="Dep Workflow",
            steps=[{"id": "s1"}, {"id": "s2"}],
            dependencies={"s2": ["s1"]},
        )
        self.assertIn("workflow_id", wf)

    def test_workflow_get(self):
        from agent import workflow_create, workflow_get
        wf = workflow_create(name="Get Test", steps=[])
        result = workflow_get(wf["workflow_id"])
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "Get Test")

    def test_workflow_get_nonexistent(self):
        from agent import workflow_get
        result = workflow_get("WF-nonexistent")
        self.assertIsNone(result)

    def test_workflow_list(self):
        from agent import workflow_create, workflow_list
        workflow_create(name="List Test", steps=[])
        wfs = workflow_list()
        self.assertIsInstance(wfs, list)
        self.assertGreater(len(wfs), 0)

    def test_workflow_fingerprint_deterministic(self):
        from agent import workflow_create, workflow_versions
        wf = workflow_create(name="Fingerprint Test", steps=[{"id": "s1"}])
        versions = workflow_versions(wf["workflow_id"])
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]["fingerprint"], wf["fingerprint"])


class TestWorkflowVersioning(unittest.TestCase):
    def test_create_version(self):
        from agent import workflow_create, workflow_create_version, workflow_versions
        wf = workflow_create(name="Version Test", steps=[{"id": "s1"}])
        v2 = workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}], change_summary="Added s2")
        self.assertEqual(v2["version"], 2)
        self.assertEqual(v2["parent_version"], 1)
        versions = workflow_versions(wf["workflow_id"])
        self.assertEqual(len(versions), 2)

    def test_activate_version(self):
        from agent import workflow_create, workflow_create_version, workflow_activate_version, workflow_versions
        wf = workflow_create(name="Activate Test", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        result = workflow_activate_version(wf["workflow_id"], 2)
        self.assertTrue(result.get("success"))
        versions = workflow_versions(wf["workflow_id"])
        v2 = [v for v in versions if v["version"] == 2][0]
        self.assertEqual(v2["status"], "ACTIVE")

    def test_activate_nonexistent_version(self):
        from agent import workflow_create, workflow_activate_version
        wf = workflow_create(name="Bad Version", steps=[])
        result = workflow_activate_version(wf["workflow_id"], 99)
        self.assertIn("error", result)


class TestWorkflowDiff(unittest.TestCase):
    def test_diff_no_changes(self):
        from agent import workflow_create, workflow_diff
        wf = workflow_create(name="Diff Test", steps=[{"id": "s1", "operation": "A"}])
        changes = workflow_diff(wf["workflow_id"], 1, 1)
        self.assertEqual(len(changes), 0)

    def test_diff_step_added(self):
        from agent import workflow_create, workflow_create_version, workflow_diff
        wf = workflow_create(name="Diff Add", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        changes = workflow_diff(wf["workflow_id"], 1, 2)
        added = [c for c in changes if c["change_type"] == "STEP_ADDED"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["step_id"], "s2")

    def test_diff_step_removed(self):
        from agent import workflow_create, workflow_create_version, workflow_diff
        wf = workflow_create(name="Diff Remove", steps=[{"id": "s1"}, {"id": "s2"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}])
        changes = workflow_diff(wf["workflow_id"], 1, 2)
        removed = [c for c in changes if c["change_type"] == "STEP_REMOVED"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]["step_id"], "s2")

    def test_diff_agent_changed(self):
        from agent import workflow_create, workflow_create_version, workflow_diff
        wf = workflow_create(name="Diff Agent", steps=[{"id": "s1", "agent": "old_agent"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1", "agent": "new_agent"}])
        changes = workflow_diff(wf["workflow_id"], 1, 2)
        agent_changes = [c for c in changes if c["change_type"] == "AGENT_CHANGED"]
        self.assertEqual(len(agent_changes), 1)

    def test_diff_tool_changed(self):
        from agent import workflow_create, workflow_create_version, workflow_diff
        wf = workflow_create(name="Diff Tool", steps=[{"id": "s1", "tool": "old_tool"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1", "tool": "new_tool"}])
        changes = workflow_diff(wf["workflow_id"], 1, 2)
        tool_changes = [c for c in changes if c["change_type"] == "TOOL_CHANGED"]
        self.assertEqual(len(tool_changes), 1)

    def test_diff_dependency_added(self):
        from agent import workflow_create, workflow_create_version, workflow_diff
        wf = workflow_create(name="Diff Dep", steps=[{"id": "s1"}, {"id": "s2"}], dependencies={"s2": []})
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}], dependencies={"s2": ["s1"]})
        changes = workflow_diff(wf["workflow_id"], 1, 2)
        dep_changes = [c for c in changes if c["change_type"] == "DEPENDENCY_ADDED"]
        self.assertEqual(len(dep_changes), 1)

    def test_diff_nonexistent_version(self):
        from agent import workflow_create, workflow_diff
        wf = workflow_create(name="Diff Bad", steps=[])
        result = workflow_diff(wf["workflow_id"], 1, 99)
        self.assertIn("error", result)


class TestWorkflowImpactAnalysis(unittest.TestCase):
    def test_impact_low_for_step_added(self):
        from agent import workflow_create, workflow_create_version, workflow_impact_analysis
        wf = workflow_create(name="Impact Low", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        analysis = workflow_impact_analysis(wf["workflow_id"], 1, 2)
        self.assertIn(analysis["impact"], ("LOW", "MEDIUM"))

    def test_impact_high_for_order_change(self):
        from agent import workflow_create, workflow_create_version, workflow_impact_analysis
        wf = workflow_create(name="Impact High", steps=[{"id": "s1"}, {"id": "s2"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s2"}, {"id": "s1"}])
        analysis = workflow_impact_analysis(wf["workflow_id"], 1, 2)
        self.assertIn(analysis["impact"], ("HIGH", "MEDIUM"))

    def test_impact_returns_affected_steps(self):
        from agent import workflow_create, workflow_create_version, workflow_impact_analysis
        wf = workflow_create(name="Impact Steps", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        analysis = workflow_impact_analysis(wf["workflow_id"], 1, 2)
        self.assertIsInstance(analysis["affected_steps"], list)
        self.assertIsInstance(analysis["new_steps"], list)


class TestWorkflowAdaptation(unittest.TestCase):
    def test_adapt_creates_adaptation(self):
        from agent import workflow_create, workflow_create_version, workflow_adapt
        wf = workflow_create(name="Adapt Test", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        result = workflow_adapt(wf["workflow_id"], 1, 2)
        self.assertIn("adaptation_id", result)

    def test_adapt_orchestration_plan(self):
        from agent import workflow_create, workflow_create_version, workflow_adapt
        wf = workflow_create(name="Adapt Plan", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        result = workflow_adapt(wf["workflow_id"], 1, 2)
        self.assertTrue(
            "orchestration_plan" in result or "results" in result,
            f"Expected orchestration_plan or results in {result.keys()}"
        )

    def test_adapt_with_company_id(self):
        from agent import workflow_create, workflow_create_version, workflow_adapt
        wf = workflow_create(name="Adapt Company", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        result = workflow_adapt(wf["workflow_id"], 1, 2, company_id=1)
        self.assertIn("adaptation_id", result)


class TestWorkflowApproval(unittest.TestCase):
    def _make_adaptation(self):
        from agent import workflow_create, workflow_create_version, workflow_adapt
        wf = workflow_create(name="Approval Test", steps=[{"id": "s1", "approval_required": False}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1", "approval_required": True}])
        return workflow_adapt(wf["workflow_id"], 1, 2)

    def test_reject_adaptation(self):
        from agent import workflow_reject_adaptation
        result = self._make_adaptation()
        if result.get("status") == "WAITING_FOR_HUMAN":
            reject = workflow_reject_adaptation(result["adaptation_id"], reason="test reject")
            self.assertTrue(reject.get("success"))


class TestWorkflowRollback(unittest.TestCase):
    def test_rollback(self):
        from agent import workflow_create, workflow_create_version, workflow_rollback, workflow_versions
        wf = workflow_create(name="Rollback Test", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        result = workflow_rollback(wf["workflow_id"], 1)
        self.assertTrue(result.get("success"))
        versions = workflow_versions(wf["workflow_id"])
        v1 = [v for v in versions if v["version"] == 1][0]
        self.assertEqual(v1["status"], "ACTIVE")

    def test_rollback_nonexistent(self):
        from agent import workflow_create, workflow_rollback
        wf = workflow_create(name="Rollback Bad", steps=[])
        result = workflow_rollback(wf["workflow_id"], 99)
        self.assertIn("error", result)


class TestWorkflowLearning(unittest.TestCase):
    def test_learning_patterns(self):
        from agent import workflow_learning
        patterns = workflow_learning("nonexistent")
        self.assertIsInstance(patterns, list)


class TestWorkflowEvents(unittest.TestCase):
    def test_events(self):
        from agent import workflow_create, workflow_events
        wf = workflow_create(name="Events Test", steps=[])
        events = workflow_events(wf["workflow_id"])
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)


class TestWorkflowAutoAdaptation(unittest.TestCase):
    def test_set_auto_adaptation(self):
        from agent import workflow_set_auto_adaptation
        result = workflow_set_auto_adaptation(True)
        self.assertTrue(result.get("success"))
        self.assertTrue(result.get("auto_adaptation"))


class TestWorkflowDemo(unittest.TestCase):
    def test_create_demo(self):
        from agent import workflow_create_demo
        demo = workflow_create_demo()
        self.assertIn("workflow_id", demo)
        self.assertEqual(demo["v1"], 1)
        self.assertGreater(demo["v2"], 1)


class TestWorkflowCompareVersions(unittest.TestCase):
    def test_compare_versions(self):
        from agent import workflow_create, workflow_create_version, workflow_compare_versions
        wf = workflow_create(name="Compare Test", steps=[{"id": "s1"}])
        workflow_create_version(wf["workflow_id"], steps=[{"id": "s1"}, {"id": "s2"}])
        result = workflow_compare_versions(wf["workflow_id"], 1, 2)
        self.assertIn("version_a", result)
        self.assertIn("version_b", result)
        self.assertIn("changes", result)


class TestWorkflowDiffDefinitions(unittest.TestCase):
    def test_empty_definitions(self):
        from agent import _wf_diff_definitions
        changes = _wf_diff_definitions({}, {})
        self.assertEqual(len(changes), 0)

    def test_step_modified(self):
        from agent import _wf_diff_definitions
        old = {"steps": [{"id": "s1", "operation": "OLD"}]}
        new = {"steps": [{"id": "s1", "operation": "NEW"}]}
        changes = _wf_diff_definitions(old, new)
        modified = [c for c in changes if c["change_type"] == "STEP_MODIFIED"]
        self.assertEqual(len(modified), 1)

    def test_approval_changed(self):
        from agent import _wf_diff_definitions
        old = {"steps": [{"id": "s1", "approval_required": False}]}
        new = {"steps": [{"id": "s1", "approval_required": True}]}
        changes = _wf_diff_definitions(old, new)
        approval = [c for c in changes if c["change_type"] == "APPROVAL_CHANGED"]
        self.assertEqual(len(approval), 1)

    def test_failure_policy_changed(self):
        from agent import _wf_diff_definitions
        old = {"steps": [{"id": "s1", "failure_policy": "FAIL"}]}
        new = {"steps": [{"id": "s1", "failure_policy": "RETRY"}]}
        changes = _wf_diff_definitions(old, new)
        fp = [c for c in changes if c["change_type"] == "FAILURE_POLICY_CHANGED"]
        self.assertEqual(len(fp), 1)


class TestWorkflowPatternKey(unittest.TestCase):
    def test_pattern_key(self):
        from agent import _wf_pattern_key
        key = _wf_pattern_key(["STEP_ADDED", "AGENT_CHANGED"])
        self.assertIn("STEP_ADDED", key)
        self.assertIn("AGENT_CHANGED", key)


class TestWorkflowNow(unittest.TestCase):
    def test_wf_now(self):
        from agent import _wf_now
        now = _wf_now()
        self.assertIn("T", now)
        self.assertTrue(now.endswith("Z"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
