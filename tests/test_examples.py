"""The example findings-table items in docs/examples match the Finding model."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from devops_agent.models import Finding

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "docs" / "examples"

# Each example file and the kind and outcome its name promises.
EXPECTED = {
    "finding-reported.json": ("alarm", "reported"),
    "finding-incomplete.json": ("alarm", "incomplete"),
    "finding-account-refused.json": ("alarm", "incomplete"),
    "finding-incident.json": ("incident", "reported"),
    "finding-skipped.json": ("skipped", "triaged"),
    "finding-linked.json": ("linked", "triaged"),
    "finding-grouped.json": ("grouped", "triaged"),
    "finding-storm.json": ("storm", "triaged"),
    "finding-deferred-skipped.json": ("skipped", "triaged"),
    "finding-datadog.json": ("deferred", "triaged"),
}


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("examples", ROOT / "scripts" / "examples.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_example_file_is_expected() -> None:
    assert sorted(path.name for path in EXAMPLES.glob("finding-*.json")) == sorted(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_example_is_a_valid_finding_of_its_kind_and_outcome(name: str) -> None:
    item = json.loads((EXAMPLES / name).read_text())
    pk = item.pop("pk")
    finding = Finding.model_validate(item)
    assert pk == f"finding#{finding.finding_id}"
    assert (finding.kind.value, finding.outcome) == EXPECTED[name]


def test_examples_are_what_the_builders_write_today() -> None:
    generator = _generator()
    assert set(generator.EXAMPLES) == set(EXPECTED)
    for name, build in generator.EXAMPLES.items():
        assert (EXAMPLES / name).read_text() == generator.render(build()), (
            f"{name} is stale: run just examples"
        )
