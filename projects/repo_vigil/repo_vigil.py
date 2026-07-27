"""
RepoVigil: A GitHub repository health monitor with health scoring.
==================================================================
Inspects repositories, analyzes commit activity, tracks contributor
metrics, and provides structured health reports with JSON export.

Grok Build Standards:
- OOP: Clean separation with RepoVigil, RepoHealth, CommitActivity, RepoReport
- Security: Uses requests library with configurable timeouts and error handling
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import requests
import json
import time
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RepoVigil")


@dataclass
class RepoHealth:
    """Data class representing a repository's health snapshot."""
    name: str
    full_name: str
    description: str
    stars: int
    forks: int
    open_issues: int
    watchers: int
    language: str
    license_name: str
    created_at: str
    updated_at: str
    pushed_at: str
    size_kb: int
    has_issues: bool
    has_wiki: bool
    has_projects: bool
    has_discussions: bool
    is_archived: bool
    is_fork: bool
    default_branch: str
    days_since_last_push: int
    topics: List[str]
    score: float
    health_status: str
    timestamp: float


@dataclass
class CommitActivity:
    """Data class for a commit activity snapshot."""
    repo_name: str
    total_commits: int
    recent_commits_last_30d: int
    active_contributors: int
    primary_contributor: str
    timestamp: float


@dataclass
class RepoReport:
    """Aggregate report across multiple repositories."""
    repositories_inspected: int
    average_health_score: float
    health_distribution: Dict[str, int]
    top_repository: Optional[Dict[str, Any]]
    total_stars: int
    total_forks: int
    timestamp: float


class RepoVigil:
    """
    RepoVigil: A GitHub repository health monitor.

    Inspects repositories, analyzes commit activity, tracks contributor
    metrics, and provides structured health reports with JSON export
    and persistent storage.
    """

    GITHUB_API = "https://api.github.com"

    def __init__(
        self,
        timeout: int = 10,
        token: Optional[str] = None,
        storage_path: Optional[str] = None
    ):
        self.timeout = timeout
        self.storage_path = storage_path or "repo_vigil_data.json"
        self.health_history: List[RepoHealth] = []
        self.commit_history: List[CommitActivity] = []

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RepoVigil/1.0 (Portfolio Project; +https://github.com/carlosjuarezz2006/Portfolio)"
        })
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})

        # Load persistent data
        self._load_data()

    def _load_data(self) -> None:
        """Load persisted health and commit history from disk."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                self.health_history = [
                    RepoHealth(**h) for h in data.get("health_history", [])
                ]
                self.commit_history = [
                    CommitActivity(**c) for c in data.get("commit_history", [])
                ]
                logger.info(
                    f"Loaded {len(self.health_history)} health records "
                    f"and {len(self.commit_history)} commit records"
                )
            except Exception as e:
                logger.warning(f"Could not load existing data: {e}")

    def _save_data(self) -> None:
        """Persist health and commit history to disk."""
        try:
            data = {
                "health_history": [asdict(h) for h in self.health_history],
                "commit_history": [asdict(c) for c in self.commit_history],
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Data saved to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save data: {e}")

    def _api_get(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Make a GET request to the GitHub API.

        Args:
            endpoint: API endpoint path (e.g., 'repos/user/repo')

        Returns:
            JSON response dict or None on failure
        """
        url = f"{self.GITHUB_API}/{endpoint.lstrip('/')}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                logger.warning(f"Rate limited on {endpoint}")
                return None
            elif response.status_code == 404:
                logger.warning(f"Not found: {endpoint}")
                return None
            else:
                logger.warning(
                    f"HTTP {response.status_code} on {endpoint}"
                )
                return None
        except requests.exceptions.Timeout:
            logger.error(f"Timeout on {endpoint}")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error on {endpoint}")
            return None
        except Exception as e:
            logger.error(f"Request failed on {endpoint}: {e}")
            return None

    def _calculate_health_score(self, repo_data: Dict[str, Any]) -> float:
        """
        Calculate a health score (0-100) for a repository.

        Scoring factors:
        - Recent push activity (40 points)
        - Stars popularity (10 points)
        - Issue resolution ratio (20 points)
        - Documentation presence (10 points)
        - Feature completeness (20 points)
        """
        score = 0.0

        # 1. Activity: recency of last push (40 points max)
        pushed_at = repo_data.get("pushed_at", "")
        if pushed_at:
            try:
                pushed = datetime.strptime(
                    pushed_at.replace("Z", "+00:00"),
                    "%Y-%m-%dT%H:%M:%S%z"
                )
                days_since = (datetime.now(timezone.utc) - pushed).days
                if days_since < 1:
                    score += 40
                elif days_since < 7:
                    score += 35
                elif days_since < 30:
                    score += 25
                elif days_since < 90:
                    score += 15
                elif days_since < 365:
                    score += 5
            except ValueError:
                score += 10

        # 2. Stars: popularity (10 points max)
        stars = repo_data.get("stargazers_count", 0)
        if stars >= 100:
            score += 10
        elif stars >= 10:
            score += 7
        elif stars >= 1:
            score += 4

        # 3. Issues: open vs closed ratio (20 points max)
        open_issues = repo_data.get("open_issues_count", 0)
        if open_issues == 0:
            score += 20
        elif open_issues <= 5:
            score += 15
        elif open_issues <= 20:
            score += 10
        elif open_issues <= 50:
            score += 5

        # 4. Documentation: has README, wiki, etc (10 points max)
        has_wiki = repo_data.get("has_wiki", False)
        has_projects = repo_data.get("has_projects", False)
        has_discussions = repo_data.get("has_discussions", False)
        description = repo_data.get("description", "")
        if description:
            score += 4
        if has_wiki:
            score += 3
        if has_projects:
            score += 2
        if has_discussions:
            score += 1

        # 5. Feature completeness (20 points max)
        has_issues = repo_data.get("has_issues", False)
        topics = repo_data.get("topics", [])
        license_info = repo_data.get("license")
        if has_issues:
            score += 8
        if topics:
            score += 6
        if license_info:
            score += 6

        return min(score, 100.0)

    def _get_health_status(self, score: float) -> str:
        """Convert a numeric score to a health status label."""
        if score >= 80:
            return "Excellent"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        elif score >= 20:
            return "Poor"
        else:
            return "Inactive"

    def inspect_repo(self, repo_full_name: str) -> Optional[RepoHealth]:
        """
        Inspect a GitHub repository and return a health snapshot.

        Args:
            repo_full_name: Repository in 'owner/repo' format

        Returns:
            RepoHealth dataclass or None on failure
        """
        endpoint = f"repos/{repo_full_name}"
        data = self._api_get(endpoint)

        if not data:
            return None

        # Calculate days since last push
        pushed_at = data.get("pushed_at", "")
        days_since = 0
        if pushed_at:
            try:
                pushed = datetime.strptime(
                    pushed_at.replace("Z", "+00:00"),
                    "%Y-%m-%dT%H:%M:%S%z"
                )
                days_since = (datetime.now(timezone.utc) - pushed).days
            except ValueError:
                days_since = 0

        # Calculate health score
        score = self._calculate_health_score(data)
        status = self._get_health_status(score)

        license_name = "None"
        if data.get("license"):
            license_name = data["license"].get("spdx_id", "Unknown")

        # Description fallback
        description = data.get("description") or "No description"

        health = RepoHealth(
            name=data.get("name", "unknown"),
            full_name=data.get("full_name", repo_full_name),
            description=description,
            stars=data.get("stargazers_count", 0),
            forks=data.get("forks_count", 0),
            open_issues=data.get("open_issues_count", 0),
            watchers=data.get("watchers_count", 0),
            language=data.get("language") or "Unknown",
            license_name=license_name,
            created_at=data.get("created_at", "unknown"),
            updated_at=data.get("updated_at", "unknown"),
            pushed_at=pushed_at,
            size_kb=data.get("size", 0),
            has_issues=data.get("has_issues", False),
            has_wiki=data.get("has_wiki", False),
            has_projects=data.get("has_projects", False),
            has_discussions=data.get("has_discussions", False),
            is_archived=data.get("archived", False),
            is_fork=data.get("fork", False),
            default_branch=data.get("default_branch", "main"),
            days_since_last_push=days_since,
            topics=data.get("topics", []),
            score=round(score, 2),
            health_status=status,
            timestamp=time.time()
        )

        self.health_history.append(health)
        self._save_data()

        logger.info(
            f"Repo: {health.full_name} | "
            f"Score: {health.score}/100 ({health.health_status}) | "
            f"Stars: {health.stars} | Forks: {health.forks}"
        )

        return health

    def get_commit_activity(
        self, repo_full_name: str, weeks: int = 4
    ) -> Optional[CommitActivity]:
        """
        Get commit activity statistics for a repository.

        Args:
            repo_full_name: Repository in 'owner/repo' format
            weeks: Number of weeks of activity to analyze

        Returns:
            CommitActivity dataclass or None on failure
        """
        endpoint = f"repos/{repo_full_name}/stats/commit_activity"
        data = self._api_get(endpoint)

        if not data:
            return None

        # Calculate recent commits (last N weeks)
        recent_commits = sum(
            week.get("total", 0) for week in data[-weeks:]
        )

        # Get total commits
        total_endpoint = f"repos/{repo_full_name}/commits"
        total_data = self._api_get(total_endpoint)
        total_commits = 0
        if total_data:
            # GitHub API returns paginated results; try to get total from link header
            # or approximate from the page count
            total_commits = len(total_data)

        # Get contributors
        contrib_endpoint = f"repos/{repo_full_name}/contributors"
        contrib_data = self._api_get(contrib_endpoint)
        active_contributors = 0
        primary_contributor = "Unknown"
        if contrib_data:
            active_contributors = len(contrib_data)
            if contrib_data:
                primary_contributor = contrib_data[0].get(
                    "login", "Unknown"
                )

        activity = CommitActivity(
            repo_name=repo_full_name,
            total_commits=total_commits,
            recent_commits_last_30d=recent_commits,
            active_contributors=active_contributors,
            primary_contributor=primary_contributor,
            timestamp=time.time()
        )

        self.commit_history.append(activity)
        self._save_data()

        logger.info(
            f"Activity for {repo_full_name}: "
            f"{recent_commits} commits in last {weeks} weeks, "
            f"{active_contributors} contributors"
        )

        return activity

    def inspect_user_repos(
        self, username: str, max_repos: int = 10
    ) -> List[RepoHealth]:
        """
        Inspect all (or top N) repositories for a GitHub user.

        Args:
            username: GitHub username
            max_repos: Maximum number of repos to inspect

        Returns:
            List of RepoHealth dataclass instances
        """
        endpoint = f"users/{username}/repos?per_page={max_repos}&sort=updated"
        repos_data = self._api_get(endpoint)

        if not repos_data:
            logger.warning(f"No repositories found for {username}")
            return []

        results = []
        for repo_data in repos_data[:max_repos]:
            repo_name = repo_data.get("full_name", repo_data.get("name", ""))
            health = self.inspect_repo(repo_name)
            if health:
                results.append(health)

        return results

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all monitoring activities.

        Returns:
            Dictionary with aggregate statistics
        """
        total = len(self.health_history)
        if total == 0:
            return {"status": "No data", "repositories_inspected": 0}

        avg_score = sum(h.score for h in self.health_history) / total
        total_stars = sum(h.stars for h in self.health_history)
        total_forks = sum(h.forks for h in self.health_history)

        # Distribution
        distribution: Dict[str, int] = {}
        for h in self.health_history:
            distribution[h.health_status] = \
                distribution.get(h.health_status, 0) + 1

        # Top repo
        top = max(self.health_history, key=lambda h: h.score)

        return {
            "repositories_inspected": total,
            "average_health_score": round(avg_score, 2),
            "health_distribution": distribution,
            "top_repository": {
                "name": top.full_name,
                "score": top.score,
                "status": top.health_status
            },
            "total_stars": total_stars,
            "total_forks": total_forks,
            "commit_records": len(self.commit_history),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

    def save_report(self, filename: Optional[str] = None) -> None:
        """
        Save a comprehensive report to a JSON file.

        Args:
            filename: Output file path (defaults to 'repo_vigil_report.json')
        """
        path = filename or "repo_vigil_report.json"
        report = {
            "summary": self.get_summary(),
            "health_history": [asdict(h) for h in self.health_history],
            "commit_history": [asdict(c) for c in self.commit_history],
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        try:
            with open(path, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Report saved to {path}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def get_report(self) -> RepoReport:
        """
        Get a structured RepoReport dataclass.

        Returns:
            RepoReport with aggregate statistics
        """
        total = len(self.health_history)
        if total == 0:
            return RepoReport(
                repositories_inspected=0,
                average_health_score=0.0,
                health_distribution={},
                top_repository=None,
                total_stars=0,
                total_forks=0,
                timestamp=time.time()
            )

        avg_score = sum(h.score for h in self.health_history) / total
        total_stars = sum(h.stars for h in self.health_history)
        total_forks = sum(h.forks for h in self.health_history)

        distribution: Dict[str, int] = {}
        for h in self.health_history:
            distribution[h.health_status] = \
                distribution.get(h.health_status, 0) + 1

        top = max(self.health_history, key=lambda h: h.score)

        return RepoReport(
            repositories_inspected=total,
            average_health_score=round(avg_score, 2),
            health_distribution=distribution,
            top_repository={
                "name": top.full_name,
                "score": top.score,
                "status": top.health_status
            },
            total_stars=total_stars,
            total_forks=total_forks,
            timestamp=time.time()
        )


if __name__ == "__main__":
    vigil = RepoVigil()

    print("Inspecting carlosjuarezz2006/Portfolio...")
    health = vigil.inspect_repo("carlosjuarezz2006/Portfolio")
    if health:
        print(f"  Name: {health.full_name}")
        print(f"  Description: {health.description}")
        print(f"  Stars: {health.stars} | Forks: {health.forks}")
        print(f"  Language: {health.language}")
        print(f"  Last push: {health.days_since_last_push} days ago")
        print(f"  Health Score: {health.score}/100 ({health.health_status})")
        print(f"  Topics: {', '.join(health.topics) if health.topics else 'None'}")

    # Get commit activity
    print("\nGetting commit activity...")
    activity = vigil.get_commit_activity("carlosjuarezz2006/Portfolio")
    if activity:
        print(f"  Total commits: {activity.total_commits}")
        print(f"  Recent commits (30d): {activity.recent_commits_last_30d}")
        print(f"  Contributors: {activity.active_contributors}")
        print(f"  Primary: {activity.primary_contributor}")

    # Inspect all user repos
    print("\nInspecting all user repositories...")
    repos = vigil.inspect_user_repos("carlosjuarezz2006", max_repos=10)
    print(f"  Found {len(repos)} repositories")

    # Save report
    vigil.save_report()
    print("\n=== Summary ===")
    print(json.dumps(vigil.get_summary(), indent=2))