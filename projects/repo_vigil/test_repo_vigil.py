import unittest
import json
import os
import time
from repo_vigil import RepoVigil, RepoHealth, CommitActivity
from datetime import datetime, timezone


class TestRepoVigil(unittest.TestCase):
    """Test suite for RepoVigil GitHub repository health monitor."""

    def setUp(self):
        self.vigil = RepoVigil(timeout=10)

    def test_inspect_valid_repo(self):
        """Test inspecting a valid public repository."""
        health = self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.assertIsNotNone(health)
        self.assertIsInstance(health, RepoHealth)
        self.assertEqual(health.full_name, "carlosjuarezz2006/Portfolio")
        self.assertGreaterEqual(health.score, 0)
        self.assertLessEqual(health.score, 100)
        self.assertIn(health.health_status, ["Excellent", "Good", "Fair", "Poor", "Inactive"])
        self.assertIn("name", health.__dict__)
        self.assertIn("stars", health.__dict__)
        self.assertIn("forks", health.__dict__)

    def test_inspect_invalid_repo(self):
        """Test inspecting a non-existent repository returns None."""
        health = self.vigil.inspect_repo("nonexistentuser/nonexistentrepo12345")
        self.assertIsNone(health)

    def test_inspect_empty_string(self):
        """Test inspecting with an empty string."""
        health = self.vigil.inspect_repo("")
        self.assertIsNone(health)

    def test_health_score_calculation(self):
        """Test health score calculation with known data."""
        mock_data = {
            "stargazers_count": 10,
            "pushed_at": datetime.now(timezone.utc).isoformat(),
            "open_issues_count": 0,
            "has_wiki": True,
            "license": {"spdx_id": "MIT"},
            "description": "A well-documented project with a long description"
        }
        score = self.vigil._calculate_health_score(mock_data)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_health_score_minimum(self):
        """Test health score with minimum viable data."""
        mock_data = {
            "stargazers_count": 0,
            "pushed_at": "2020-01-01T00:00:00Z",
            "open_issues_count": 100,
            "has_wiki": False,
            "license": None,
            "description": ""
        }
        score = self.vigil._calculate_health_score(mock_data)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_health_status_mapping(self):
        """Test health status mapping from scores."""
        self.assertEqual(self.vigil._determine_health_status(85), "Excellent")
        self.assertEqual(self.vigil._determine_health_status(70), "Good")
        self.assertEqual(self.vigil._determine_health_status(50), "Fair")
        self.assertEqual(self.vigil._determine_health_status(30), "Poor")
        self.assertEqual(self.vigil._determine_health_status(10), "Inactive")

    def test_get_commit_activity_valid(self):
        """Test commit activity for a valid repository."""
        activity = self.vigil.get_commit_activity("carlosjuarezz2006/Portfolio")
        self.assertIsNotNone(activity)
        self.assertIsInstance(activity, CommitActivity)
        self.assertEqual(activity.repo_name, "carlosjuarezz2006/Portfolio")
        self.assertIn("total_commits", activity.__dict__)
        self.assertIn("active_contributors", activity.__dict__)

    def test_get_commit_activity_invalid(self):
        """Test commit activity for a non-existent repository."""
        activity = self.vigil.get_commit_activity("nonexistentuser/nonexistentrepo12345")
        self.assertIsNone(activity)

    def test_inspect_user_repos(self):
        """Test inspecting all repositories for a valid user."""
        repos = self.vigil.inspect_user_repos("carlosjuarezz2006", max_repos=5)
        self.assertIsInstance(repos, list)
        self.assertGreater(len(repos), 0)
        for repo in repos:
            self.assertIsInstance(repo, RepoHealth)
            self.assertIn("carlosjuarezz2006", repo.full_name)

    def test_inspect_user_repos_invalid(self):
        """Test inspecting repositories for a non-existent user."""
        repos = self.vigil.inspect_user_repos("nonexistentuser999999999")
        self.assertEqual(repos, [])

    def test_save_report(self):
        """Test saving report to JSON file."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.vigil.save_report("test_report.json")
        self.assertTrue(os.path.exists("test_report.json"))
        with open("test_report.json") as f:
            report = json.load(f)
        self.assertIn("repositories_inspected", report)
        self.assertIn("health_history", report)
        self.assertGreater(len(report["health_history"]), 0)
        os.remove("test_report.json")

    def test_get_summary_no_data(self):
        """Test summary with no data returns empty status."""
        empty_vigil = RepoVigil()
        summary = empty_vigil.get_summary()
        self.assertEqual(summary["status"], "No data")
        self.assertEqual(summary["repositories_inspected"], 0)

    def test_get_summary_with_data(self):
        """Test summary after inspecting a repository."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        summary = self.vigil.get_summary()
        self.assertIn("average_health_score", summary)
        self.assertIn("health_distribution", summary)
        self.assertIn("top_repository", summary)
        self.assertGreater(summary["repositories_inspected"], 0)

    def test_multiple_inspections(self):
        """Test inspecting multiple repositories accumulates history."""
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.vigil.inspect_repo("carlosjuarezz2006/Portfolio")
        self.assertEqual(len(self.vigil.health_history), 2)

    def test_api_get_failure(self):
        """Test API call with a malformed endpoint."""
        result = self.vigil._api_get("this/is/not/a/valid/endpoint/999999")
        self.assertIsNone(result)

    def test_commit_activity_has_primary_contributor(self):
        """Test that commit activity returns a primary contributor."""
        activity = self.vigil.get_commit_activity("carlosjuarezz2006/Portfolio")
        if activity:  # Could be None if API rate limited
            self.assertIsInstance(activity.primary_contributor, str)
            self.assertGreater(len(activity.primary_contributor), 0)


if __name__ == '__main__':
    unittest.main()