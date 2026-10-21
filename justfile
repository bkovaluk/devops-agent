# List the recipes.
default:
    @just --list

# Build the Lambda zip from the locked dependencies.
build:
    scripts/build.sh

# Run the tests.
test:
    uv run pytest -q

# Lint, format check, type check and terraform fmt.
lint:
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy devops_agent evals
    terraform fmt -check -recursive terraform

# Re-render the README diagrams, dark and light.
diagram:
    uv run python docs/diagram/architecture.py docs
    uv run python docs/diagram/multi_account.py docs
    uv run python docs/diagram/flows.py docs
