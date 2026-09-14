"""Оркестровка: собрать все анализы вместе и пройти по файлам проекта."""

from __future__ import annotations

import ast
import os
import time
from dataclasses import dataclass, field

from .analyses.constants import ConstantEnv
from .analyses.nullness import NullnessAnalysis
from .analyses.taint import TaintAnalysis
from .core.cfg import CFGBuilder, function_scopes
from .core.findings import Confidence, Finding, Severity
from .core.symbols import SymbolTable
from .rules import catalog as _catalog  # noqa: F401  — регистрирует правила
from .rules.engine import CATALOG, RuleContext, define, run_rules

PARSE_ERROR = define(
    id="AEG-PARSE-001",
    title="Файл не разбирается",
    message="синтаксическая ошибка не даёт проанализировать файл",
    severity=Severity.MEDIUM,
    cwe=None,
    category="parse",
    remediation="Исправьте синтаксис или исключите файл из проверки.",
)

DEFAULT_EXCLUDES = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env", "node_modules", "build", "dist", ".tox", ".eggs",
    "site-packages",
})

MAX_FILE_BYTES = 2_000_000


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duration: float = 0.0

    def by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {level: 0 for level in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


class Analyzer:
    """Точка входа: анализирует исходный текст, файл или каталог."""

    def __init__(
        self,
        min_severity: Severity = Severity.LOW,
        min_confidence: Confidence = Confidence.LOW,
        enabled_rules: set[str] | None = None,
        disabled_rules: set[str] | None = None,
        excludes: set[str] | None = None,
    ) -> None:
        self.min_severity = min_severity
        self.min_confidence = min_confidence
        self.enabled_rules = enabled_rules
        self.disabled_rules = disabled_rules or set()
        self.excludes = set(DEFAULT_EXCLUDES) | (excludes or set())

    # --- анализ одного файла ----------------------------------------------

    def analyze_source(self, source: str, path: str = "<строка>") -> list[Finding]:
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as error:
            finding = Finding(
                rule_id=PARSE_ERROR.id,
                title=PARSE_ERROR.title,
                message=f"{error.msg} (строка {error.lineno})",
                severity=PARSE_ERROR.severity,
                confidence=Confidence.HIGH,
                path=path,
                line=error.lineno or 1,
                column=(error.offset or 1) - 1,
                cwe=None,
                category="parse",
                remediation=PARSE_ERROR.remediation,
            )
            return self._finalize([finding], source)

        symbols = SymbolTable.from_module(tree)
        symbols.shadow_module_definitions(tree)
        findings: list[Finding] = []

        findings += TaintAnalysis(tree, symbols, path).run()

        nullness = NullnessAnalysis(tree, symbols, path)
        for name, node, body in function_scopes(tree):
            nullness.run_scope(CFGBuilder.build(name, node, body), node)
        findings += nullness.findings

        context = RuleContext(path, tree, symbols, ConstantEnv.from_scope(tree.body), source)
        findings += run_rules(context)

        return self._finalize(findings, source)

    def analyze_file(self, path: str) -> list[Finding]:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            source = handle.read()
        return self.analyze_source(source, path)

    # --- обход проекта ------------------------------------------------------

    def analyze_paths(self, paths: list[str]) -> Report:
        started = time.perf_counter()
        report = Report()
        for target in self._discover(paths):
            try:
                if os.path.getsize(target) > MAX_FILE_BYTES:
                    report.files_skipped += 1
                    continue
                report.findings.extend(self.analyze_file(target))
                report.files_scanned += 1
            except OSError:
                report.files_skipped += 1
        report.findings.sort(key=lambda f: f.sort_key())
        report.duration = time.perf_counter() - started
        return report

    def _discover(self, paths: list[str]) -> list[str]:
        found: list[str] = []
        for target in paths:
            if os.path.isfile(target):
                found.append(target)
                continue
            for root, directories, files in os.walk(target):
                directories[:] = sorted(d for d in directories if d not in self.excludes and not d.startswith("."))
                for name in sorted(files):
                    if name.endswith(".py"):
                        found.append(os.path.join(root, name))
        return found

    # --- фильтрация и оформление -------------------------------------------

    def _finalize(self, findings: list[Finding], source: str) -> list[Finding]:
        lines = source.splitlines()
        result: list[Finding] = []
        for finding in findings:
            if finding.severity < self.min_severity:
                continue
            if finding.confidence < self.min_confidence:
                continue
            if self.enabled_rules is not None and finding.rule_id not in self.enabled_rules:
                continue
            if finding.rule_id in self.disabled_rules:
                continue
            if _suppressed(lines, finding):
                continue
            if 0 < finding.line <= len(lines):
                finding.snippet = lines[finding.line - 1].strip()
            result.append(finding)
        return result


def _suppressed(lines: list[str], finding: Finding) -> bool:
    """Поддержка подавления комментарием ``# aegis: ignore`` или ``# noqa``."""
    if not (0 < finding.line <= len(lines)):
        return False
    comment = lines[finding.line - 1]
    marker = "# aegis:"
    if marker in comment:
        directive = comment.split(marker, 1)[1].strip()
        if directive.startswith("ignore"):
            _, _, rules = directive.partition("=")
            if not rules.strip():
                return True
            return finding.rule_id in {r.strip() for r in rules.split(",")}
    return False


def all_rules() -> list[dict]:
    """Полный каталог проверок — и по образцу, и по потоку данных."""
    from .analyses.taint_spec import SINKS

    entries = [
        {
            "id": meta.id,
            "title": meta.title,
            "severity": str(meta.severity),
            "cwe": meta.cwe,
            "category": meta.category,
            "kind": "образец",
        }
        for meta in CATALOG.values()
    ]
    seen = {entry["id"] for entry in entries}
    for spec in SINKS:
        if spec.rule_id in seen:
            continue
        seen.add(spec.rule_id)
        entries.append(
            {
                "id": spec.rule_id,
                "title": spec.title,
                "severity": str(spec.severity),
                "cwe": spec.cwe,
                "category": spec.category,
                "kind": "поток данных",
            }
        )
    entries.append(
        {
            "id": "AEG-BUG-001",
            "title": "Возможное обращение к None",
            "severity": str(Severity.MEDIUM),
            "cwe": "CWE-476",
            "category": "reliability",
            "kind": "поток данных",
        }
    )
    return sorted(entries, key=lambda e: e["id"])
