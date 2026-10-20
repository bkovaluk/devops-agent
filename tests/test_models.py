"""Effort grade ordering."""

from __future__ import annotations

from devops_agent.models import EFFORT_DEFINITIONS, Effort


def test_effort_grades_are_ordered_low_to_very_high() -> None:
    graded = [Effort.LOW, Effort.MEDIUM, Effort.HIGH, Effort.VERY_HIGH]
    assert [effort.rank for effort in graded] == [0, 1, 2, 3]


def test_unknown_effort_has_no_rank() -> None:
    assert Effort.UNKNOWN.rank is None


def test_effort_label_reads_as_words() -> None:
    assert Effort.VERY_HIGH.label == "very high"
    assert Effort.LOW.label == "low"


def test_every_effort_grade_is_defined() -> None:
    assert set(EFFORT_DEFINITIONS) == set(Effort)
