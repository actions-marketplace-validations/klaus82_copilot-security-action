# Terraform Security Analysis Action

A GitHub Action that analyzes Terraform PR changes for security misconfigurations using GitHub Copilot. It posts a prioritized, actionable security report as a PR comment.

## What it does

On every pull request that touches `.tf` or `.tfvars` files, the action:

1. Collects the changed Terraform files (scoped to a configurable directory)
2. Sends them to GitHub Copilot (via GitHub Models) with a specialized security-engineer system prompt
3. Receives a structured report covering IAM, network exposure, encryption, logging, secrets, and more
4. Posts (or updates) the report as a PR comment

The analysis covers ten security categories:

- Identity and Access Management (IAM)
- Network exposure
- Data encryption at rest and in transit
- Public access and data exposure
- Logging and monitoring gaps
- Hardcoded secrets and sensitive values
- Kubernetes / EKS configuration
- Compute (EC2, Lambda, Auto Scaling)
- Container registry and supply chain
- Terraform state backend security

Each finding includes a severity rating (CRITICAL / HIGH / MEDIUM / LOW / INFO), a concrete attack scenario, the insecure HCL snippet, and a ready-to-apply fix.

## Usage

```yaml
- uses: your-org/copilot-security-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Full example workflow

```yaml
name: Terraform Security Analysis

on:
  pull_request:
    paths:
      - "**.tf"
      - "**.tfvars"

permissions:
  contents: read
  pull-requests: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: your-org/copilot-security-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          terraform-directory: infra
          model: gpt-4o
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `github-token` | No | `${{ github.token }}` | GitHub token for Copilot API calls and posting PR comments |
| `terraform-directory` | No | `.` | Root directory to scan for Terraform files (relative to repo root) |
| `max-files` | No | `10` | Maximum number of changed Terraform files to include in the analysis |
| `model` | No | `gpt-5` | GitHub Models model ID to use for the analysis |
| `post-pr-comment` | No | `true` | Post the analysis as a PR comment (`true`/`false`) |
| `custom-prompt` | No | `""` | Custom analysis prompt. Use `{TERRAFORM_FILES}` as the placeholder for file contents. Overrides the built-in security agent when set. |

## Outputs

| Output | Description |
|---|---|
| `report` | The security analysis report in Markdown format |
| `changed-files` | Newline-separated list of changed Terraform files that were analyzed |

### Using outputs in subsequent steps

```yaml
- id: security
  uses: your-org/copilot-security-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Fail on critical findings
  run: |
    if echo "${{ steps.security.outputs.report }}" | grep -q "CRITICAL"; then
      echo "Critical security findings detected. Review the PR comment."
      exit 1
    fi
```

## Supported triggers

| Event | Behavior |
|---|---|
| `pull_request` | Diffs against the base branch; posts a PR comment |
| `push` | Diffs against the previous commit |
| `workflow_dispatch` | Scans all Terraform files in `terraform-directory` |

## Permissions

The action requires the following permissions:

```yaml
permissions:
  contents: read      # to read Terraform files
  pull-requests: write  # to post PR comments
```

## Requirements

- The repository must have access to **GitHub Copilot** (GitHub Models). The built-in `GITHUB_TOKEN` is sufficient when Copilot is enabled for the organization or repository.
- `jq` must be available on the runner (pre-installed on all GitHub-hosted runners).
- For `pull_request` events, the checkout step must use `fetch-depth: 0` so that the base branch ref is available for diffing.

## License

[MIT](LICENSE)
