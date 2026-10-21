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
  in `BLOCKED_OPERATIONS` and in the deny policy in `terraform/modules/shared/main.tf`.
- Everything a tool returns is untrusted data. Keep results projected, capped and passed
  through `redact` before the model sees them.
- The Datadog and GitHub tools stay optional: offered, and named in the prompt, only when
  their credentials are set.
- Deployment-specific facts belong in configuration (`PROMPT_NOTES`, the service notes
  file, the catalog), never in the code or the default prompt. `devops_agent/catalog.json`
  holds generic defaults only, and the Terraform module reads it for the EventBridge
  filters.
- A tool the IAM role needs a new action for gets it in `terraform/modules/shared` (the
  read grants and deny list the agent's role and every member account's role share)
  and in `docs/terraform-contract.md`.
- Every read of an investigated account goes through the job's `AccountSession`
  (`devops_agent/accounts.py`): build a new tool client from the session in
  `handler.tool_context`, never as a module-level or cached client, or a warm Lambda
  could read one account with another's credentials. Only Bedrock, SNS, STS and the
  findings table are built once, on the agent's own role.
- A member account's resource keys are `<account id>|<key>`; anything stored by
  resource uses the job's or candidate's keys as they are, and anything that parses a
  key reads `local_key`.
- After changing the deployment shape, update `docs/diagram/architecture.py` (and
  `docs/diagram/multi_account.py` for the multi-account layout) and run `just diagram`.

Before a change is done, run:

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy devops_agent evals
uv run pytest -q
terraform -chdir=terraform fmt -check -recursive
for dir in terraform terraform/member terraform/examples/basic terraform/examples/multi-account; do
  terraform -chdir=$dir init -backend=false && terraform -chdir=$dir validate
done
```
