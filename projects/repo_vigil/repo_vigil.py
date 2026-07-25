import requests
import json
import time
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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


class RepoVigil:
    """
    RepoVigil: A GitHub repository health and activity monitoring tool.
    Fetches repository metadata, calculates health scores, and tracks
    commit activity for any public GitHub repository.
    """

    GITHUB_API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RepoVigil/1.0"
        })
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})
        self.health_history: List[RepoHealth] = []
        self.commit_history: List[CommitActivity] = []

    def _api_get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """
        Perform a GitHub API GET request with error handling.

        Returns parsed JSON response (dict or list depending on endpoint),
        or None on failure.
        """
        url = f"{self.GITHUB_API_BASE}/{endpoint.lstrip('/')}"
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out: {url}")
            return None
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "N/A"
            logger.error(f"HTTP {status} for {url}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

    def _calculate_health_score(self, repo_data: Dict[str, Any]) -> float:
        """
        Calculate a repository health score (0-100) based on:
        - Stars (weight: 20%)
        - Recency of last push (weight: 30%)
        - Issues closed vs open ratio (weight: 20%)
        - Has documentation (has_wiki) (weight: 10%)
        - Has license (weight: 10%)
        - Description presence (weight: 10%)
        """
        score = 0.0

        # Stars score (0-20 points, logarithmic scale)
        stars = repo_data.get("stargazers_count", 0)
        score += min(20, (stars ** 0.5) * 4)

        # Recency of last push (0-30 points)
        pushed_at_str = repo_data.get("pushed_at", "")
        if pushed_at_str:
            try:
                pushed_at = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
                days_since = (datetime.now(timezone.utc) - pushed_at).days
                if days_since <= 7:
                    score += 30
                elif days_since <= 30:
                    score += 25
                elif days_since <= 90:
                    score += 20
                elif days_since <= 180:
                    score += 10
                else:
                    score += 5
            except (ValueError, TypeError):
                pass

        # Open issues penalty (0-20 points)
        open_issues = repo_data.get("open_issues_count", 0)
        if open_issues == 0:
            score += 20
        elif open_issues <= 5:
            score += 15
        elif open_issues <= 20:
            score += 10
        elif open_issues <= 50:
            score += 5
        else:
            score += 0

        # Has wiki (0-10 points)
        if repo_data.get("has_wiki"):
            score += 10

        # Has license (0-10 points)
        if repo_data.get("license") and repo_data["license"].get("spdx_id"):
            score += 10

        # Has description (0-10 points)
        description = repo_data.get("description", "")
        if description and len(description.strip()) > 10:
            score += 10
        elif description and len(description.strip()) > 0:
            score += 5

        return round(min(100, score), 2)

    def _determine_health_status(self, score: float) -> str:
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
        Inspect a single GitHub repository and return a health report.

        Args:
            repo_full_name: Full repository name (e.g., 'carlosjuarezz2006/Portfolio')

        Returns:
            RepoHealth dataclass with the repository health snapshot, or None on failure.
        """
        endpoint = f"repos/{repo_full_name}"
        data = self._api_get(endpoint)
        if not data:
            logger.error(f"Could not fetch repository: {repo_full_name}")
            return None

        pushed_at_str = data.get("pushed_at", "")
        days_since_last_push = 0
        if pushed_at_str:
            try:
                pushed_at = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
                days_since_last_push = (datetime.now(timezone.utc) - pushed_at).days
            except (ValueError, TypeError):
                pass

        score = self._calculate_health_score(data)
        health_status = self._determine_health_status(score)

        health = RepoHealth(
            name=data.get("name", ""),
            full_name=data.get("full_name", ""),
            description=data.get("description", "") or "",
            stars=data.get("stargazers_count", 0),
            forks=data.get("forks_count", 0),
            open_issues=data.get("open_issues_count", 0),
            watchers=data.get("watchers_count", 0),
            language=data.get("language") or "N/A",
            license_name=data["license"]["spdx_id"] if data.get("license") else "None",
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            pushed_at=pushed_at_str,
            size_kb=data.get("size", 0),
            has_issues=data.get("has_issues", False),
            has_wiki=data.get("has_wiki", False),
            has_projects=data.get("has_projects", False),
            days_since_last_push=days_since_last_push,
            topics=data.get("topics", []),
            score=score,
            health_status=health_status,
            timestamp=time.time()
        )

        self.health_history.append(health)
        logger.info(f"Inspected {repo_full_name}: score={score}, status={health_status}")
        return health

    def inspect_user_repos(self, username: str, max_repos: int = 30) -> List[RepoHealth]:
        """
        Inspect all repositories for a given GitHub user.

        Args:
            username: GitHub username (e.g., 'carlosjuarezz2006')
            max_repos: Maximum number of repositories to inspect

        Returns:
            List of RepoHealth dataclass instances
        """
        repos_data = self._api_get(
            f"users/{username}/repos",
            params={"per_page": max_repos, "sort": "updated", "direction": "desc"}
        )
        if not repos_data:
            logger.error(f"Could not fetch repositories for user: {username}")
            return []

        results = []
        for repo_data in repos_data:
            name = repo_data.get("full_name", "")
            health = self.inspect_repo(name)
            if health:
                results.append(health)

        logger.info(f"Inspected {len(results)} repositories for user {username}")
        return results

    def get_commit_activity(self, repo_full_name: str) -> Optional[CommitActivity]:
        """
        Get commit activity statistics for a repository.

        Args:
            repo_full_name: Full repository name (e.g., 'carlosjuarezz2006/Portfolio')

        Returns:
            CommitActivity dataclass with commit statistics, or None on failure.
        """
        # Get contributors
        contributors = self._api_get(f"repos/{repo_full_name}/contributors", params={"per_page": 5})
        total_commits = 0
        active_contributors = 0
        primary_contributor = "N/A"

        if contributors:
            total_commits = sum(c.get("contributions", 0) for c in contributors)
            active_contributors = len(contributors)
            if contributors:
                primary_contributor = contributors[0].get("login", "N/A")

        # Get recent commits (last 30 days)
        recent_commits = self._api_get_list(
            f"repos/{repo_full_name}/commits",
            params={"per_page": 100, "since": datetime.now(timezone.utc).isoformat()}
        )
        recent_count = len(recent_commits) if recent_commits else 0

        # Fallback: count from all-time if recent endpoint fails
        if recent_commits is None:
            recent_count = 0

        activity = CommitActivity(
            repo_name=repo_full_name,
            total_commits=total_commits,
            recent_commits_last_30d=recent_count,
            active_contributors=active_contributors,
            primary_contributor=primary_contributor,
            timestamp=time.time()
        )

        self.commit_history.append(activity)
        logger.info(
            f"Commit activity for {repo_full_name}: "
            f"{total_commits} total, {recent_count} recent, "
            f"{active_contributors} contributors"
        )
        return activity

    def save_report(self, filename: str = "repo_vigil_report.json") -> None:
        """Save all collected health and commit activity data to a JSON file."""
        try:
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "repositories_inspected": len(self.health_history),
                "health_history": [asdict(h) for h in self.health_history],
                "commit_history": [asdict(c) for c in self.commit_history]
            }
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """Generate a summary of all inspections performed."""
        if not self.health_history:
            return {"status": "No data", "repositories_inspected": 0}

        total = len(self.health_history)
        avg_score = sum(h.score for h in self.health_history) / total
        status_counts: Dict[str, int] = {}
        for h in self.health_history:
            status_counts[h.health_status] = status_counts.get(h.health_status, 0) + 1

        top_repo = max(self.health_history, key=lambda h: h.score)

        return {
            "repositories_inspected": total,
            "average_health_score": round(avg_score, 2),
            "health_distribution": status_counts,
            "top_repository": {
                "name": top_repo.full_name,
                "score": top_repo.score,
                "status": top_repo.health_status
            },
            "total_commit_activities": len(self.commit_history),
            "last_inspection": asdict(self.health_history[-1])
        }


if __name__ == "__main__":
    vigil = RepoVigil()
    print("=== RepoVigil: GitHub Repository Health Monitor ===\n")

    # Inspect the user's portfolio repo
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