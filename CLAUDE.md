# CLAUDE.md

Guidance for coding agents and contributors working in this repo.

- The spec is [docs/architecture.md](docs/architecture.md); the infrastructure a
  deployment needs is [docs/terraform-contract.md](docs/terraform-contract.md).
- The agent only reads. Never add a write tool. `READ_ONLY_OPERATIONS` in
  `devops_agent/tools.py` must list every client operation a tool calls; a test enforces
  it and rejects operations that return secrets or payloads.
- `aws_call` runs an operation chosen at run time, so `devops_agent/aws_guard.py` decides
  what it may run. Before adding a service to `ALLOWED_SERVICES`, block every operation
  of it that returns contents, secrets, credentials, environment variables or payloads,
  in `BLOCKED_OPERATIONS` and in the deny policy in `terraform/iam.tf`.
- Everything a tool returns is untrusted data. Keep results projected, capped and passed
  through `redact` before the model sees them.
- The Datadog and GitHub tools stay optional: offered, and named in the prompt, only when
  their credentials are set.
- Deployment-specific facts belong in configuration (`PROMPT_NOTES`, the service notes
  file, the catalog), never in the code or the default prompt. `devops_agent/catalog.json`
  holds generic defaults only, and the Terraform module reads it for the EventBridge
  filters.
- A tool the IAM role needs a new action for gets it in `terraform/iam.tf` and in
  `docs/terraform-contract.md`.
- After changing the deployment shape, update `docs/diagram/architecture.py` and run
  `just diagram`.

Before a change is done, run:

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy devops_agent evals
uv run pytest -q
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
```
