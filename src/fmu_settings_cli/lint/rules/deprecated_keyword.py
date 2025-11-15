"""Deprecated Keyword Rule.

Rule for detecting deprecated keyword arguments in function/class calls.
"""

import ast
import re
from collections.abc import Callable
from dataclasses import dataclass

from fmu_settings_cli.lint.linter import BaseRule, Fix, FixableLintIssue, Severity


@dataclass(frozen=True)
class KeywordDeprecationInfo:
    """Information about a deprecated keyword argument."""

    message: str
    replacement: str | None
    transform: Callable[[ast.expr], dict[str, str]] | None


class DeprecatedKeywordRule(BaseRule):
    """Detects deprecated keyword arguments in function or class calls."""

    def __init__(  # noqa: PLR0913
        self,
        rule_id: str,
        module_path: str,
        class_or_function: str,
        deprecated_kwargs: dict[str, KeywordDeprecationInfo],
        description: str | None = None,
        severity: Severity = Severity.WARNING,
    ) -> None:
        """Initialize the rule.

        Args:
            rule_id: Unique identifier for this rule (e.g., "FMU001")
            module_path: Full module path (e.g., "fmu.dataio")
            class_or_function: Name of class or function (e.g., "ExportData")
            deprecated_kwargs: Dict mapping deprecated kwarg names to messages
                Value can be empty string for simple removal
            description: Human-readable description (optional)
            severity: Severity level (default: WARNING)
        """
        super().__init__(
            rule_id=rule_id,
            description=(
                description or f"Deprecated keyword arguments in {class_or_function}"
            ),
            severity=severity,
        )
        self.module_path = module_path
        self.class_or_function = class_or_function
        self.deprecated_kwargs = deprecated_kwargs

        # Track imports found in the current file
        self.imported_names: dict[str, str] = {}

    @property
    def node_types(self) -> set[type[ast.AST]]:
        """We care about imports and function calls."""
        return {ast.ImportFrom, ast.Import, ast.Call}

    def begin_check(self, source: str, tree: ast.AST) -> None:
        """Reset import tracking for new file."""
        super().begin_check(source, tree)
        self.imported_names = {}

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track 'from X import Y' statements."""
        module_parts = self.module_path.split(".")

        # Pattern: from fmu.dataio import ExportData
        if node.module == self.module_path:
            for alias in node.names:
                if alias.name == self.class_or_function:
                    local_name = alias.asname or alias.name
                    self.imported_names[local_name] = "direct"

        # Pattern: from fmu import dataio
        elif len(module_parts) > 1:
            parent_module = ".".join(module_parts[:-1])
            last_part = module_parts[-1]

            if node.module == parent_module:
                for alias in node.names:
                    if alias.name == last_part:
                        local_name = alias.asname or alias.name
                        self.imported_names[local_name] = "module"

    def visit_Import(self, node: ast.Import) -> None:
        """Track 'import X' statements."""
        for alias in node.names:
            if alias.name == self.module_path:
                local_name = alias.asname or alias.name
                self.imported_names[local_name] = "full_path"

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for deprecated keywords."""
        if not self._is_target_call(node):
            return

        for keyword in node.keywords:
            if keyword.arg and keyword.arg in self.deprecated_kwargs:
                self._add_deprecated_kwarg_issue(node, keyword)

    def _is_target_call(self, node: ast.Call) -> bool:
        """Check if this call is to our target class/function."""
        # Directly calls i.e. ExportData(...)
        if isinstance(node.func, ast.Name):
            name = node.func.id
            return name in self.imported_names and self.imported_names[name] == "direct"

        # Attribute calls i.e. dataio.ExportData(...) or fmu.dataio.ExportData(...)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr != self.class_or_function:
                return False

            # Check what it's being called on
            if isinstance(node.func.value, ast.Name):
                # dataio.ExportData() - check if 'dataio' was imported
                module_name = node.func.value.id
                return (
                    module_name in self.imported_names
                    and self.imported_names[module_name] == "module"
                )

            if isinstance(node.func.value, ast.Attribute):
                # fmu.dataio.ExportData() - reconstruct full path
                full_path = self._get_full_attribute_path(node.func.value)
                return (
                    full_path in self.imported_names
                    and self.imported_names[full_path] == "full_path"
                )

        return False

    def _get_full_attribute_path(self, node: ast.Attribute) -> str:
        """Reconstruct full path like 'fmu.dataio' from nested Attributes."""
        parts = []
        current: ast.Attribute | ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _add_deprecated_kwarg_issue(
        self, call_node: ast.Call, keyword_node: ast.keyword
    ) -> None:
        """Create and add an issue for a deprecated keyword argument."""
        kwarg_name = keyword_node.arg
        if kwarg_name is None:
            # Shouldn't happen, is already filtered
            return

        message = (
            f"Deprecated keyword argument '{kwarg_name}' in {self.class_or_function}"
        )

        deprecation_info = self.deprecated_kwargs[kwarg_name]
        if deprecation_info.message:
            message += f": {deprecation_info.message}"

        fix = self._create_fix(call_node, keyword_node, kwarg_name)
        issue = FixableLintIssue(
            line=keyword_node.lineno,
            column=keyword_node.col_offset,
            end_line=keyword_node.end_lineno or keyword_node.lineno,
            end_column=keyword_node.end_col_offset or keyword_node.col_offset,
            message=message,
            severity=self.severity,
            rule_id=self.rule_id,
            fix=fix,
        )
        self.issues.append(issue)

    def _create_fix(
        self, call_node: ast.Call, keyword_node: ast.keyword, kwarg_name: str
    ) -> Fix:
        """Create a fix that removes, replaces, or transforms the keyword argument."""
        lines = self.source.splitlines(keepends=True)

        start_line_idx = keyword_node.lineno - 1
        start_col = keyword_node.col_offset
        start_pos = sum(len(line) for line in lines[:start_line_idx]) + start_col

        end_line_idx = (keyword_node.end_lineno or keyword_node.lineno) - 1
        end_col = keyword_node.end_col_offset or keyword_node.col_offset
        end_pos = sum(len(line) for line in lines[:end_line_idx]) + end_col

        deprecation_info = self.deprecated_kwargs[kwarg_name]
        transform = deprecation_info.transform

        if transform:
            new_kwargs = transform(keyword_node.value)

            replacement_parts = [f"{k}={v}" for k, v in new_kwargs.items()]
            replacement = ", ".join(replacement_parts)

            return Fix(
                description=(
                    f"Replace '{kwarg_name}' with {', '.join(new_kwargs.keys())}"
                ),
                start_pos=start_pos,
                end_pos=end_pos,
                replacement=replacement,
            )

        if deprecation_info.replacement:
            end_pos = start_pos + len(kwarg_name)
            return Fix(
                description=f"Replace '{kwarg_name}' with '{replacement}'",
                start_pos=start_pos,
                end_pos=end_pos,
                replacement=deprecation_info.replacement,
            )

        # Handle complete removal (your existing logic)
        replacement = ""

        # Handle comma removal intelligently
        remaining = self.source[end_pos : min(end_pos + 50, len(self.source))]
        trailing_comma_match = re.match(r"^(\s*,\s*)", remaining)

        if trailing_comma_match:
            comma_and_space = trailing_comma_match.group(1)
            if "\n" in comma_and_space:
                newline_pos = comma_and_space.index("\n")
                end_pos += newline_pos
            else:
                end_pos += len(comma_and_space)
        else:
            preceding = self.source[max(0, start_pos - 50) : start_pos]
            comma_match = re.search(r",(\s*)$", preceding)
            if comma_match:
                start_pos -= len(comma_match.group(0))

        return Fix(
            description=f"Remove deprecated keyword argument '{kwarg_name}'",
            start_pos=start_pos,
            end_pos=end_pos,
            replacement=replacement,
        )
