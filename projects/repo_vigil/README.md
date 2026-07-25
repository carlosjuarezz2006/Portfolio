# RepoVigil

RepoVigil is a GitHub repository health and activity monitoring tool. It fetches repository metadata, calculates a composite health score, and tracks commit activity for any public GitHub repository.

## Features
- **Repository Health Scoring**: Calculates a 0-100 health score based on stars, recency of pushes, open issues, documentation, license, and description quality.
- **Commit Activity Tracking**: Fetches total commits, recent commits (last 30 days), contributor count, and primary contributor.
- **User Repository Inspection**: Inspect all repositories for a given GitHub user with a single call.
- **Structured JSON Reports**: Save all inspection data to a timestamped JSON report.
- **Summary Statistics**: Get aggregate health distribution, average scores, and top repositories.

## Grok Build Standards
- **Cryptographic Security**: No secrets in code — GitHub token passed via env var or constructor parameter.
- **OOP Architecture**: Clean separation with `RepoHealth` and `CommitActivity` dataclasses, and `RepoVigil` class with single-responsibility private methods.
- **Professional Documentation**: Full type hinting, comprehensive docstrings, structured logging, and error handling for all API calls.

## Usage
```python
from repo_vigil import RepoVigil

vigil = RepoVigil()
health = vigil.inspect_repo("carlosjuarezz2006/Portfolio")
print(f"Health Score: {health.score}/100 ({health.health_status})")

# Inspect all user repos
repos = vigil.inspect_user_repos("carlosjuarezz2006")
print(f"Found {len(repos)} repositories")
```