"""Командный интерфейс анализатора."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core.findings import Confidence, Severity
from .engine import Analyzer, all_rules
from .report import RENDERERS

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Статический анализатор: ищет уязвимости и ошибки в коде на Python.",
        epilog="Код возврата: 0 — чисто, 1 — есть находки не ниже порога --fail-on, 2 — ошибка запуска.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="файлы или каталоги (по умолчанию текущий)")
    parser.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text", help="формат вывода")
    parser.add_argument("-o", "--output", help="записать отчёт в файл вместо вывода на экран")
    parser.add_argument("--min-severity", default="low", help="не показывать находки ниже уровня")
    parser.add_argument("--min-confidence", default="low", help="не показывать находки с меньшей уверенностью")
    parser.add_argument("--fail-on", default="medium", help="уровень, начиная с которого код возврата равен 1")
    parser.add_argument("--rule", action="append", metavar="ID", help="включить только указанные правила")
    parser.add_argument("--disable", action="append", metavar="ID", help="отключить правило")
    parser.add_argument("--exclude", action="append", metavar="ИМЯ", help="пропустить каталог с таким именем")
    parser.add_argument("--list-rules", action="store_true", help="показать каталог проверок и выйти")
    parser.add_argument("--no-color", action="store_true", help="не раскрашивать вывод")
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    return parser


def _print_rules() -> int:
    rules = all_rules()
    width = max(len(rule["id"]) for rule in rules)
    print(f"Всего проверок: {len(rules)}\n")
    for rule in rules:
        cwe = f"  [{rule['cwe']}]" if rule["cwe"] else ""
        print(f"{rule['id']:<{width}}  {rule['severity']:<8} {rule['kind']:<12} {rule['title']}{cwe}")
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        return _print_rules()

    try:
        min_severity = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on)
        min_confidence = Confidence[args.min_confidence.upper()]
    except (ValueError, KeyError) as error:
        parser.error(str(error))
        return EXIT_USAGE

    analyzer = Analyzer(
        min_severity=min_severity,
        min_confidence=min_confidence,
        enabled_rules=set(args.rule) if args.rule else None,
        disabled_rules=set(args.disable or ()),
        excludes=set(args.exclude or ()),
    )

    paths = args.paths or ["."]
    report = analyzer.analyze_paths(paths)

    color = not args.no_color and args.output is None and sys.stdout.isatty()
    renderer = RENDERERS[args.format]
    text = renderer(report, color) if args.format == "text" else renderer(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        print(f"Отчёт записан: {args.output}")
    else:
        print(text)

    worst = report.worst()
    if worst is not None and worst >= fail_on:
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
