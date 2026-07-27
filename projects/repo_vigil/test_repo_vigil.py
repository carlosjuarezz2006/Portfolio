import unittest
import json
import os
import time
from repo_vigil import RepoVigil, RepoHealth, CommitActivity, RepoReport
from datetime import datetime, timezone


class TestRepoVigil(unittest.TestCase):
    """Test suite for RepoVigil GitHub repository health monitor."""

    def setUp(self):
        self.vigil = RepoVigil(timeout=10, storage_path="test_vigil_data.json")

    def tearDown(self):
        if os.path.exists("test_vigil_data.json"):
            os.remove("test_vigil_data.json")
        if os.path.exists("test_report.json"):
            os.remove("test_report.json")

    def test_inspect_valid_repo(self):
        """Test inspecting a valid public repository."""
        health = self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.assertIsNotNone(health)
        self.assertIsInstance(health, RepoHealth)
        self.assertEqual(health.full_name, "carlosjuarezz2006/Portfolio")
        self.assertGreaterEqual(health.score, 0)
        self.assertLessEqual(health.score, 100)
        self.assertIn(
            health.health_status,
            ["Excellent", "Good", "Fair", "Poor", "Inactive"]
        )
        self.assertIn("name", health.__dict__)
        self.assertIn("stars", health.__dict__)
        self.assertIn("forks", health.__dict__)
        self.assertIn("has_discussions", health.__dict__)
        self.assertIn("is_archived", health.__dict__)
        self.assertIn("default_branch", health.__dict__)

    def test_inspect_invalid_repo(self):
        """Test inspecting a non-existent repository returns None."""
        health = self.vigil.inspect_repo(
            "nonexistentuser/nonexistentrepo12345"
        )
        self.assertIsNone(health)

    def test_inspect_empty_string(self):
        """Test inspecting with empty string returns None."""
        health = self.vigil.inspect_repo("")
        self.assertIsNone(health)

    def test_inspect_none(self):
        """Test inspecting with None returns None."""
        health = self.vigil.inspect_repo(None)  # type: ignore
        self.assertIsNone(health)

    def test_calculate_health_score_active(self):
        """Test high score for very active repo."""
        score = self.vigil._calculate_health_score({
            "pushed_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S%z"
            ),
            "stargazers_count": 100,
            "open_issues_count": 0,
            "description": "A great project",
            "has_wiki": True,
            "has_projects": True,
            "has_discussions": True,
            "has_issues": True,
            "topics": ["python", "security"],
            "license": {"spdx_id": "MIT"}
        })
        self.assertGreaterEqual(score, 80)

    def test_calculate_health_score_inactive(self):
        """Test low score for inactive repo."""
        score = self.vigil._calculate_health_score({
            "pushed_at": "2020-01-01T00:00:00Z",
            "stargazers_count": 0,
            "open_issues_count": 50,
            "description": "",
            "has_wiki": False,
            "has_projects": False,
            "has_discussions": False,
            "has_issues": False,
            "topics": [],
            "license": None
        })
        self.assertLessEqual(score, 20)

    def test_calculate_health_score_no_pushed_at(self):
        """Test score with no push date."""
        score = self.vigil._calculate_health_score({
            "pushed_at": "",
            "stargazers_count": 0,
            "open_issues_count": 0,
            "description": "",
            "has_wiki": False,
            "has_projects": False,
            "has_discussions": False,
            "has_issues": False,
            "topics": [],
            "license": None
        })
        self.assertGreaterEqual(score, 0)

    def test_health_status_labels(self):
        """Test health status label mapping."""
        self.assertEqual(
            self.vigil._get_health_status(90), "Excellent"
        )
        self.assertEqual(self.vigil._get_health_status(70), "Good")
        self.assertEqual(self.vigil._get_health_status(50), "Fair")
        self.assertEqual(self.vigil._get_health_status(30), "Poor")
        self.assertEqual(self.vigil._get_health_status(10), "Inactive")

    def test_get_summary(self):
        """Test summary after inspecting a repository."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        summary = self.vigil.get_summary()
        self.assertIn("average_health_score", summary)
        self.assertIn("health_distribution", summary)
        self.assertIn("top_repository", summary)
        self.assertIn("total_stars", summary)
        self.assertIn("total_forks", summary)
        self.assertGreater(summary["repositories_inspected"], 0)

    def test_multiple_inspections(self):
        """Test inspecting multiple repositories accumulates history."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.assertEqual(len(self.vigil.health_history), 2)

    def test_get_report_after_inspection(self):
        """Test getting a structured report."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        report = self.vigil.get_report()
        self.assertIsInstance(report, RepoReport)
        self.assertGreater(report.repositories_inspected, 0)
        self.assertGreaterEqual(report.average_health_score, 0)
        self.assertIn("Excellent", report.health_distribution)

    def test_report_empty(self):
        """Test report with no inspections."""
        report = self.vigil.get_report()
        self.assertEqual(report.repositories_inspected, 0)
        self.assertEqual(report.average_health_score, 0.0)
        self.assertIsNone(report.top_repository)

    def test_save_report(self):
        """Test saving report to file."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.vigil.save_report("test_report.json")
        self.assertTrue(os.path.exists("test_report.json"))
        with open("test_report.json") as f:
            data = json.load(f)
        self.assertIn("summary", data)
        self.assertIn("health_history", data)
        self.assertIn("commit_history", data)

    def test_persistence(self):
        """Test that data persists across instances."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.vigil._save_data()

        # New instance should load old data
        vigil2 = RepoVigil(
            timeout=10, storage_path="test_vigil_data.json"
        )
        self.assertGreater(len(vigil2.health_history), 0)

    def test_summary_empty(self):
        """Test summary with no data."""
        summary = RepoVigil(timeout=10).get_summary()
        self.assertEqual(summary["repositories_inspected"], 0)

    def test_api_get_failure(self):
        """Test API call with a malformed endpoint."""
        result = self.vigil._api_get(
            "this/is/not/a/valid/endpoint/999999"
        )
        self.assertIsNone(result)

    def test_commit_activity_has_primary_contributor(self):
        """Test that commit activity returns a primary contributor."""
        activity = self.vigil.get_commit_activity(
            "carlosjuarezz2006/Portfolio"
        )
        if activity:  # Could be None if API rate limited
            self.assertIsInstance(activity.primary_contributor, str)
            self.assertGreater(len(activity.primary_contributor), 0)


if __name__ == '__main__':
    unittest.main()