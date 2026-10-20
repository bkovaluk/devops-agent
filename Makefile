build:
	scripts/build.sh

test:
	uv run pytest -q

diagram:
	uv run python docs/diagram/architecture.py docs

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy devops_agent evals
	terraform fmt -check -recursive terraform

.PHONY: build test diagram lint
