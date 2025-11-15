"""Base classes for linting."""

import ast
from dataclasses import asdict, dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Severity levels for lint issues."""

    WARNING = "warning"
    ERROR = "error"
    INFO = "info"


@dataclass
class LintIssue:
    """Represents a single lint issue found in code."""

    line: int
    column: int
    end_line: int
    end_column: int
    message: str
    severity: Severity
    rule_id: str


@dataclass
class Fix:
    """Represents a fix that can be applied to code."""

    description: str
    start_pos: int  # Character position in source
    end_pos: int  # Character position in source
    replacement: str


@dataclass
class FixableLintIssue(LintIssue):
    """Represents a single, fixable lint issue."""

    fix: Fix


class BaseRule:
    """Base class for all linting rules.

    Subclasses should:
    1. Set node_types property to specify which AST nodes they care about
    2. Implement visit_* methods for those node types
    3. Call add_issue() when problems are found
    """

    def __init__(
        self,
        rule_id: str,
        description: str,
        severity: Severity = Severity.WARNING,
    ) -> None:
        """Initializes a rule."""
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.issues: list[LintIssue | FixableLintIssue] = []
        self.source = ""

    @property
    def node_types(self) -> set[type[ast.AST]]:
        """Return set of AST node types this rule cares about.

        Example:
            return {ast.Call, ast.ImportFrom, ast.Import}
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement node_types property"
        )

    def begin_check(self, source: str, tree: ast.AST) -> None:
        """Called before AST traversal begins."""
        self.source = source
        self.issues = []

    def end_check(self) -> list[LintIssue]:
        """Called after AST traversal completes. Returns all collected issues."""
        return self.issues

    def add_issue(
        self, node: ast.expr | ast.stmt, message: str, fix: Fix | None = None
    ) -> None:
        """Helper method to add an issue for a given node."""
        issue = LintIssue(
            line=node.lineno,
            column=node.col_offset,
            end_line=node.end_lineno or node.lineno,
            end_column=node.end_col_offset or node.col_offset,
            message=message,
            severity=self.severity,
            rule_id=self.rule_id,
        )
        if fix:
            issue = FixableLintIssue(**asdict(issue), fix=fix)
        self.issues.append(issue)


class RuleVisitor(ast.NodeVisitor):
    """AST visitor that dispatches to multiple rules efficiently.

    This class performs a single traversal of the AST and dispatches
    each node to all rules that have registered interest in that node type.
    """

    def __init__(self, rules: list[BaseRule]):
        """Initializes a rule visitor."""
        self.rules = rules

        self.dispatch: dict[type[ast.AST], list[BaseRule]] = {}

        for rule in rules:
            for node_type in rule.node_types:
                if node_type not in self.dispatch:
                    self.dispatch[node_type] = []
                self.dispatch[node_type].append(rule)

    def visit(self, node: ast.AST) -> None:
        """Visit a node and dispatch to all interested rules.

        This is called automatically by ast.NodeVisitor for each node.
        """
        node_type = type(node)

        if node_type in self.dispatch:
            for rule in self.dispatch[node_type]:
                method_name = f"visit_{node_type.__name__}"
                visitor_method = getattr(rule, method_name, None)
                if visitor_method:
                    visitor_method(node)

        self.generic_visit(node)


class Linter:
    """Main linter class that manages rules and performs linting."""

    def __init__(self) -> None:
        """The main linter."""
        self.rules: list[BaseRule] = []

    def add_rule(self, rule: BaseRule) -> None:
        """Add a linting rule."""
        self.rules.append(rule)

    def lint(
        self, source: str, filename: str = "<string>"
    ) -> list[FixableLintIssue | LintIssue]:
        """Lint source code and return all issues found.

        Args:
            source: Python source code as string
            filename: Filename for error reporting

        Returns:
            List of [Fixable]LintIssue objects sorted by position
        """
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            return [
                LintIssue(
                    line=e.lineno or 1,
                    column=e.offset or 0,
                    end_line=e.lineno or 1,
                    end_column=e.offset or 0,
                    message=f"Syntax error: {e.msg}",
                    severity=Severity.ERROR,
                    rule_id="syntax-error",
                )
            ]

        for rule in self.rules:
            rule.begin_check(source, tree)

        visitor = RuleVisitor(self.rules)
        visitor.visit(tree)

        all_issues = []
        for rule in self.rules:
            all_issues.extend(rule.end_check())

        all_issues.sort(key=lambda i: (i.line, i.column))

        return all_issues

    def apply_fixes(self, source: str, issues: list[LintIssue]) -> str:
        """Apply all fixes from issues to source code.

        Args:
            source: Original source code
            issues: List of issues with fixes

        Returns:
            Fixed source code
        """
        fixable_issues = [
            issue for issue in issues if isinstance(issue, FixableLintIssue)
        ]
        fixable_issues.sort(key=lambda i: i.fix.start_pos)

        merged_fixes = []
        i = 0
        while i < len(fixable_issues):
            current = fixable_issues[i]
            current_start = current.fix.start_pos
            current_end = current.fix.end_pos

            # Look ahead and merge all overlapping fixes
            j = i + 1
            while j < len(fixable_issues):
                next_fix = fixable_issues[j]

                if next_fix.fix.start_pos < current_end:
                    current_end = max(current_end, next_fix.fix.end_pos)
                    j += 1
                else:
                    break

            # If we merged multiple fixes, create a combined fix
            if j > i + 1:
                merged = FixableLintIssue(
                    line=current.line,
                    column=current.column,
                    end_line=current.end_line,
                    end_column=current.end_column,
                    message=current.message,
                    severity=current.severity,
                    rule_id=current.rule_id,
                    fix=Fix(
                        description="Remove deprecated parameters",
                        start_pos=current_start,
                        end_pos=current_end,
                        replacement="",
                    ),
                )
                merged_fixes.append(merged)
            else:
                merged_fixes.append(current)

            i = j

        merged_fixes.sort(key=lambda i: i.fix.start_pos, reverse=True)

        result = source
        for issue in merged_fixes:
            fix = issue.fix
            result = result[: fix.start_pos] + fix.replacement + result[fix.end_pos :]

        return result
