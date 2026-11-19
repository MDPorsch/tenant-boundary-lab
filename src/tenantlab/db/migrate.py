"""Programmatic Alembic entry point.

Migrations are run explicitly (`upgrade_to_head`, or the CLI later). They NEVER run as a side
effect of starting the application (docs/architecture.md s5).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources

from alembic import command
from alembic.config import Config


@contextmanager
def _alembic_config(database_url: str) -> Iterator[Config]:
    with resources.as_file(resources.files("tenantlab.db").joinpath("migrations")) as script_dir:
        config = Config()
        # ConfigParser interpolation treats '%' specially; a path may legitimately contain one.
        config.set_main_option("script_location", str(script_dir).replace("%", "%%"))
        # Passed as an attribute, not an ini option: the URL may hold a password and '%' escapes.
        config.attributes["database_url"] = database_url
        yield config


def upgrade_to_head(database_url: str) -> None:
    """Apply every migration to `database_url` (a synchronous SQLAlchemy URL)."""
    with _alembic_config(database_url) as config:
        command.upgrade(config, "head")


def _downgrade_to_base(database_url: str) -> None:
    """Drop everything this project created. Private: used by tests of the downgrade path only."""
    with _alembic_config(database_url) as config:
        command.downgrade(config, "base")
