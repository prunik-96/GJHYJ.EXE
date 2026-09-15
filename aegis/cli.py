"""Командный интерфейс анализатора."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core.findings import Confidence, Severity
from .ai.provider import DEFAULT_MODEL, build_provider
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

    group = parser.add_argument_group(
        "связка с языковой моделью",
        "Модель предлагает, анализатор проверяет. Требуется пакет anthropic и ключ доступа.",
    )
    group.add_argument("--ai-triage", action="store_true",
                       help="добавить к находкам разбор модели (справочно, ничего не удаляется)")
    group.add_argument("--ai-fix", action="store_true",
                       help="предложить исправления; принимаются только прошедшие проверку")
    group.add_argument("--ai-apply", action="store_true",
                       help="записать принятые исправления в файлы (по умолчанию только показ)")
    group.add_argument("--ai-model", default=DEFAULT_MODEL, help="модель (по умолчанию %(default)s)")
    group.add_argument("--ai-effort", default="high",
                       choices=["low", "medium", "high", "xhigh", "max"],
                       help="глубина рассуждений модели")
    group.add_argument("--ai-attempts", type=int, default=3,
                       help="сколько раз повторять при отказе проверки")
    group.add_argument("--ai-limit", type=int, default=10,
                       help="сколько находок обрабатывать моделью")
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

    if args.ai_triage or args.ai_fix:
        provider = build_provider(model=args.ai_model, effort=args.ai_effort)
        if args.ai_triage:
            _run_triage(provider, report, args.ai_limit)
        if args.ai_fix:
            _run_autofix(provider, analyzer, report, args)

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


def _group_by_file(report) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for finding in report.findings:
        grouped.setdefault(finding.path, []).append(finding)
    return grouped


def _read(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def _run_triage(provider, report, limit: int) -> None:
    from .ai.triage import Triager

    triager = Triager(provider, max_findings=limit)
    for path, findings in _group_by_file(report).items():
        source = _read(path)
        if source is not None:
            triager.annotate(source, findings)


def _run_autofix(provider, analyzer, report, args) -> None:
    from .ai.autofix import AutoFixer

    fixer = AutoFixer(provider, analyzer, max_attempts=args.ai_attempts)
    print("\nИсправления, предложенные моделью и проверенные анализатором\n")
    accepted_total = 0

    for path, findings in _group_by_file(report).items():
        source = _read(path)
        if source is None:
            continue
        outcomes = fixer.fix_all(source, findings[: args.ai_limit])
        for outcome in outcomes:
            mark = "принято" if outcome.success else "отклонено"
            print(f"  [{mark}] {outcome.finding.rule_id} {path}:{outcome.finding.line}"
                  f" — {outcome.explain()}")
            for attempt in outcome.attempts:
                if attempt.result is None:
                    continue
                for check in attempt.result.checks:
                    symbol = "+" if check.passed else "-"
                    print(f"        {symbol} {check.name}: {check.detail}")
        accepted = [o for o in outcomes if o.success]
        accepted_total += len(accepted)
        if not accepted:
            continue
        final = AutoFixer.final_source(source, outcomes)
        if args.ai_apply:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(final)
            print(f"  файл обновлён: {path}")
        else:
            print(f"\n  --- предлагаемый вид {path} ---")
            print(accepted[-1].attempts[-1].result.diff)

    print(f"\nПринято исправлений: {accepted_total}")
    if accepted_total and not args.ai_apply:
        print("Чтобы записать их в файлы, добавьте --ai-apply")


if __name__ == "__main__":
    raise SystemExit(main())
