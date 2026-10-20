"""Service notes: team-maintained facts the agent cannot observe, kept in a TOML file.

The agent reads ``service_notes.toml`` next to this module, or the file SERVICE_NOTES_FILE
names, and runs without notes when the file does not exist. ``service_notes.example.toml``
shows the format.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

NOTES_FILE = "service_notes.toml"
EXAMPLE_NOTES_FILE = "service_notes.example.toml"
NOTES_FILE_ENV = "SERVICE_NOTES_FILE"


class ServiceNote(BaseModel):
    service: str = Field(min_length=1)
    match: list[str] = Field(min_length=1)
    notes: list[str] = Field(min_length=1, max_length=5)


def load_notes(text: str) -> tuple[ServiceNote, ...]:
    """The notes in a service notes TOML document, in file order."""
    return tuple(
        ServiceNote.model_validate({"service": service, **entry})
        for service, entry in tomllib.loads(text).items()
    )


def read_notes(path: Path) -> tuple[ServiceNote, ...]:
    """The notes in the file at ``path``; none when there is no such file."""
    if not path.is_file():
        return ()
    return load_notes(path.read_text(encoding="utf-8"))


def notes_path() -> Path:
    configured = os.environ.get(NOTES_FILE_ENV)
    return Path(configured) if configured else Path(__file__).with_name(NOTES_FILE)


SERVICE_NOTES = read_notes(notes_path())
