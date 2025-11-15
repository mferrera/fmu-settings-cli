"""Rules related to fmu-dataio."""

import ast

from fmu_settings_cli.lint.rules import DeprecatedKeywordRule, KeywordDeprecationInfo


def split_access_ssdl(value_node: ast.expr) -> dict[str, str]:
    """Split access_ssdl into classification and rep_include."""
    if isinstance(value_node, ast.Dict):
        key_value_map = {}
        for key_node, val_node in zip(value_node.keys, value_node.values, strict=False):
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                key_value_map[key_node.value] = ast.unparse(val_node)
        rep_include_value = key_value_map.get("rep_include", "False")

        return {
            "classification": "'internal'",
            "rep_include": rep_include_value,
        }
    value_str = ast.unparse(value_node)
    return {
        "classification": "'internal'",
        "rep_include": f"{value_str}.get('rep_include', False)",
    }


rules = [
    DeprecatedKeywordRule(
        rule_id="DATAIO001",
        module_path="fmu.dataio",
        class_or_function="ExportData",
        deprecated_kwargs={
            "access_ssdl": KeywordDeprecationInfo(
                message="Replaced by the `classification` and `rep_include` arguments",
                replacement=None,
                transform=split_access_ssdl,
            ),
        },
    )
]
