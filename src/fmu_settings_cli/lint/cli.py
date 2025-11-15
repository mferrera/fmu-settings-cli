"""The 'lint' command."""

from typing import Final

import typer
from fmu.settings import find_nearest_fmu_directory

from fmu_settings_cli.prints import (
    error,
    success,
)

from .linter import Linter, Severity
from .rules.deprecated_keyword import DeprecatedKeywordRule

lint_cmd = typer.Typer(
    help="Lint your FMU project",
    add_completion=True,
)

REQUIRED_FMU_PROJECT_SUBDIRS: Final[list[str]] = ["ert"]


def create_linter() -> Linter:
    """Create and configure the linter with all rules.

    Returns:
        Configured Linter instance
    """
    linter = Linter()

    # Example: Deprecated keyword arguments in ExportData
    linter.add_rule(
        DeprecatedKeywordRule(
            rule_id="FMU001",
            module_path="fmu.dataio",
            class_or_function="ExportData",
            deprecated_kwargs={
                "some": "This parameter has been removed",
            },
            description="Deprecated keyword arguments in ExportData",
            severity=Severity.WARNING,
        )
    )

    # Example: Additional deprecated parameters
    linter.add_rule(
        DeprecatedKeywordRule(
            rule_id="FMU002",
            module_path="fmu.dataio",
            class_or_function="ExportData",
            deprecated_kwargs={
                "legacy_mode": "Use 'mode' parameter instead",
                "old_format": "",  # Empty string means just remove it
            },
            description="Additional deprecated parameters in ExportData",
            severity=Severity.WARNING,
        )
    )

    # Add more rules here as needed...

    return linter


@lint_cmd.callback(invoke_without_command=True)
def lint(ctx: typer.Context) -> None:
    """The main entry point for the init command."""
    if ctx.invoked_subcommand is not None:  # pragma: no cover
        return

    try:
        fmu_dir = find_nearest_fmu_directory()
    except Exception as e:
        error(
            "Unable to find .fmu directory",
            reason=str(e),
            suggestion=(
                "This is an unknown error. Please report this as a bug in "
                "'#fmu-settings' on Slack, Viva Engage, or the FMU Portal."
            ),
        )
        raise typer.Abort from e

    lint(fmu_dir.path.parent)
    success("All done! You can now use the 'fmu settings' application.")
