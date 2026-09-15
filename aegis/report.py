"""Вывод результатов: текст для человека, JSON и SARIF для инструментов."""

from __future__ import annotations

import json

from .core.findings import Finding, Severity
from .engine import Report

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

_LABELS = {
    Severity.CRITICAL: "КРИТИЧНО",
    Severity.HIGH: "ВЫСОКИЙ",
    Severity.MEDIUM: "СРЕДНИЙ",
    Severity.LOW: "НИЗКИЙ",
    Severity.INFO: "СПРАВКА",
}

_CONFIDENCE = {"high": "высокая", "medium": "средняя", "low": "низкая"}


class _Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def severity(self, level: Severity, text: str) -> str:
        return f"{_COLORS[level]}{text}{_RESET}" if self.enabled else text

    def dim(self, text: str) -> str:
        return f"{_DIM}{text}{_RESET}" if self.enabled else text

    def bold(self, text: str) -> str:
        return f"{_BOLD}{text}{_RESET}" if self.enabled else text


def render_text(report: Report, color: bool = True) -> str:
    palette = _Palette(color)
    out: list[str] = []

    if not report.findings:
        out.append(palette.bold("Проблем не найдено."))
        out.append(palette.dim(_summary_line(report)))
        return "\n".join(out)

    current_file = None
    for finding in report.findings:
        if finding.path != current_file:
            current_file = finding.path
            out.append("")
            out.append(palette.bold(f"── {current_file}"))
        out.append("")
        out.append(_render_finding(finding, palette))

    out.append("")
    out.append(palette.bold("Итого"))
    counts = report.by_severity()
    for level in sorted(Severity, reverse=True):
        if counts[level]:
            out.append(f"  {palette.severity(level, _LABELS[level]):<20} {counts[level]}")
    out.append(palette.dim(_summary_line(report)))
    return "\n".join(out)


def _render_finding(finding: Finding, palette: _Palette) -> str:
    label = palette.severity(finding.severity, f" {_LABELS[finding.severity]} ")
    confidence = _CONFIDENCE.get(str(finding.confidence), str(finding.confidence))
    header = f"{label} {palette.bold(finding.title)}  {palette.dim(finding.rule_id)}"

    lines = [header]
    lines.append(f"  {finding.path}:{finding.line}:{finding.column}"
                 f"{palette.dim('  · уверенность: ' + confidence)}"
                 f"{palette.dim('  · ' + finding.cwe) if finding.cwe else ''}")
    lines.append(f"  {finding.message}")
    if finding.snippet:
        lines.append(f"  {palette.dim('│')} {finding.snippet}")
    if finding.trace:
        lines.append(f"  {palette.dim('путь данных:')}")
        for step in finding.trace:
            lines.append(f"    {palette.dim(str(step.line) + ':')} {step.description}")
    if finding.remediation:
        lines.append(f"  {palette.bold('как исправить:')} {finding.remediation}")
    verdict = finding.notes.get("ai_verdict")
    if verdict:
        lines.append(f"  {palette.bold('разбор моделью:')} {verdict}"
                     f"{palette.dim(' (справочно, находка остаётся)')}")
        reason = finding.notes.get("ai_reason")
        if reason:
            lines.append(f"    {reason}")
        impact = finding.notes.get("ai_impact")
        if impact:
            lines.append(f"    {palette.dim('последствия: ' + impact)}")
    return "\n".join(lines)


def _summary_line(report: Report) -> str:
    return (
        f"Проверено файлов: {report.files_scanned}"
        f"{', пропущено: ' + str(report.files_skipped) if report.files_skipped else ''}"
        f" · за {report.duration:.2f} с"
    )


def render_json(report: Report) -> str:
    payload = {
        "tool": "aegis",
        "version": _version(),
        "summary": {
            "files_scanned": report.files_scanned,
            "files_skipped": report.files_skipped,
            "duration_seconds": round(report.duration, 4),
            "counts": {str(level): count for level, count in report.by_severity().items() if count},
            "total": len(report.findings),
        },
        "findings": [finding.to_dict() for finding in report.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(report: Report) -> str:
    """SARIF 2.1.0 — понимают GitHub Code Scanning и большинство CI."""
    rules: dict[str, dict] = {}
    results = []
    for finding in report.findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation or finding.message},
                "properties": {
                    "category": finding.category,
                    "tags": [t for t in (finding.category, finding.cwe) if t],
                },
            }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.title}: {finding.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": max(finding.line, 1),
                                "startColumn": finding.column + 1,
                                "endLine": max(finding.end_line or finding.line, 1),
                            },
                        }
                    }
                ],
                "codeFlows": _sarif_flow(finding),
            }
        )
        if not results[-1]["codeFlows"]:
            results[-1].pop("codeFlows")

    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "aegis",
                            "version": _version(),
                            "informationUri": "https://github.com/prunik-96/GJHYJ.EXE",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


def _sarif_flow(finding: Finding) -> list:
    if not finding.trace:
        return []
    return [
        {
            "threadFlows": [
                {
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.path},
                                    "region": {"startLine": max(step.line, 1)},
                                },
                                "message": {"text": step.description},
                            }
                        }
                        for step in finding.trace
                    ]
                }
            ]
        }
    ]


def _version() -> str:
    from . import __version__

    return __version__


RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}
