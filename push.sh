#!/usr/bin/env bash
# Usage: ./push.sh <github-username> [repo-name]
set -euo pipefail
USER_NAME="${1:?usage: ./push.sh <github-username> [repo-name]}"
REPO="${2:-code-security-auditor-skill}"
sed -i.bak "s/YOUR-USERNAME/${USER_NAME}/g" README.md && rm -f README.md.bak
python3 -m unittest discover -s tests
git init -b main
git add .
git commit -m "Code Security Auditor skill: scanner, report generator, references, tests, CI"
if command -v gh >/dev/null 2>&1; then
  gh repo create "${USER_NAME}/${REPO}" --public --source=. --push \
    --description "AI skill that audits code, finds vulnerabilities with exact file and line, patches them, and writes the report"
else
  git remote add origin "https://github.com/${USER_NAME}/${REPO}.git"
  git push -u origin main
fi
