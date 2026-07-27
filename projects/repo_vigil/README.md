# RepoVigil

A GitHub repository health monitor with health scoring, commit activity tracking, contributor metrics, and persistent JSON reporting.

## Features
- **Health Scoring**: Multi-factor scoring algorithm (0-100) based on activity, popularity, issue management, documentation, and feature completeness.
- **Commit Activity Tracking**: Analyzes recent commits, total commits, active contributors, and primary contributor.
- **User Repository Inspection**: Scan all repositories for a GitHub user and sort by health score.
- **Persistent Storage**: Automatic load/save of health and commit history to disk.
- **Structured Reports**: `RepoReport` dataclass with aggregate statistics and JSON export.
- **Rate Limit Handling**: Graceful degradation when GitHub API rate limits are hit.
- **Comprehensive Fields**: Tracks 30+ repository attributes including discussions, archival status, fork status, default branch, and topics.

## Grok Build Standards
- **OOP Architecture**: Clean separation with `RepoVigil`, `RepoHealth`, `CommitActivity`, and `RepoReport` classes.
- **Security**: Uses `requests` library with configurable timeouts, error handling, and optional token authentication.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 20+ unit tests.

## Usage
```python
from repo_vigil import RepoVigil

vigil = RepoVigil()

# Inspect a single repository
health = vigil.inspect_repo("carlosjuarezz2006/Portfolio")
print(f"Health Score: {health.score}/100 ({health.health_status})")
print(f"Stars: {health.stars} | Forks: {health.forks}")
print(f"Language: {health.language}")
print(f"Last push: {health.days_since_last_push} days ago")

# Get commit activity
activity = vigil.get_commit_activity("carlosjuarezz2006/Portfolio")
print(f"Recent commits: {activity.recent_commits_last_30d}")
print(f"Contributors: {activity.active_contributors}")

# Inspect all user repositories
repos = vigil.inspect_user_repos("carlosjuarezz2006", max_repos=10)

# Get structured report
report = vigil.get_report()
print(f"Avg Score: {report.average_health_score}")
print(f"Distribution: {report.health_distribution}")

# Save report
vigil.save_report("health_report.json")

# Get summary
print(vigil.get_summary())
```

## CLI Usage
```bash
python repo_vigil.py
```

## Health Score Factors
| Factor | Max Points | Description |
|--------|-----------|-------------|
| Activity | 40 | Recency of last push (recent = higher) |
| Stars | 10 | Popularity based on stargazers |
| Issues | 20 | Low open issue count = higher score |
| Documentation | 10 | Description, wiki, projects, discussions |
| Features | 20 | Issues enabled, topics, license |
| **Total** | **100** | |