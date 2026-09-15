"""Тесты связки анализатора с языковой моделью.

Основная часть проверок — враждебные: модель вернула мусор, сломала
синтаксис, заглушила находку комментарием, вырезала код вместе с проблемой
или переписала весь файл. Ни один такой ответ не должен быть принят.

Все тесты идут на подставной модели, без сети и без ключа.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis import Analyzer  # noqa: E402
from aegis.ai.autofix import AutoFixer, build_request, extract_code  # noqa: E402
from aegis.ai.provider import AnthropicProvider, LLMUnavailable, ScriptedProvider  # noqa: E402
from aegis.ai.triage import Triager, parse_note  # noqa: E402
from aegis.ai.verify import PatchVerifier  # noqa: E402

ANALYZER = Analyzer()

VULNERABLE = '''import os


def ping():
    host = input("host: ")
    os.system("ping -c 1 " + host)


def greet(name):
    print("hello " + name)
'''

CORRECT_FIX = '''import os
import shlex


def ping():
    host = input("host: ")
    os.system("ping -c 1 " + shlex.quote(host))


def greet(name):
    print("hello " + name)
'''


def target_finding(source: str = VULNERABLE, rule: str = "AEG-INJ-001"):
    return [f for f in ANALYZER.analyze_source(source, "app.py") if f.rule_id == rule][0]


def fenced(code: str) -> str:
    return f"Вот исправление:\n\n```python\n{code}```\n"


class TestExtractCode(unittest.TestCase):
    def test_fenced_block(self):
        self.assertEqual(extract_code("текст\n```python\nx = 1\n```\nещё"), "x = 1\n")

    def test_bare_python(self):
        self.assertEqual(extract_code("y = 2"), "y = 2\n")

    def test_trailing_newline_is_preserved(self):
        """Файл должен оканчиваться переводом строки — иначе портится diff."""
        self.assertTrue(extract_code("```python\nx = 1\n```").endswith("\n"))

    def test_prose_is_rejected(self):
        self.assertIsNone(extract_code("Я не могу этого сделать, извините."))

    def test_picks_the_parsable_block(self):
        response = "```\nне код ???\n```\n```python\nz = 3\n```"
        self.assertEqual(extract_code(response), "z = 3\n")


class TestVerifierAcceptsGoodPatch(unittest.TestCase):
    def setUp(self):
        self.verifier = PatchVerifier(ANALYZER)
        self.finding = target_finding()

    def test_correct_fix_is_accepted(self):
        result = self.verifier.verify(VULNERABLE, CORRECT_FIX, self.finding, "app.py")
        self.assertTrue(result.accepted, result.summary())

    def test_all_checks_pass(self):
        result = self.verifier.verify(VULNERABLE, CORRECT_FIX, self.finding, "app.py")
        self.assertEqual(result.failures, [])

    def test_resolved_finding_is_reported(self):
        result = self.verifier.verify(VULNERABLE, CORRECT_FIX, self.finding, "app.py")
        self.assertIn("AEG-INJ-001", {f.rule_id for f in result.resolved})

    def test_diff_is_produced(self):
        result = self.verifier.verify(VULNERABLE, CORRECT_FIX, self.finding, "app.py")
        self.assertIn("shlex", result.diff)


class TestVerifierRejectsBadPatches(unittest.TestCase):
    """Каждый случай — правдоподобный ответ модели, который принимать нельзя."""

    def setUp(self):
        self.verifier = PatchVerifier(ANALYZER)
        self.finding = target_finding()

    def _reject_reason(self, patched: str) -> str:
        result = self.verifier.verify(VULNERABLE, patched, self.finding, "app.py")
        self.assertFalse(result.accepted, "патч не должен быть принят")
        return " ".join(check.name for check in result.failures)

    def test_broken_syntax(self):
        broken = "import os\n\ndef ping(:\n    pass\n"
        self.assertIn("синтаксис", self._reject_reason(broken))

    def test_suppression_comment_instead_of_fix(self):
        """Самый соблазнительный способ схитрить — заглушить правило."""
        sneaky = VULNERABLE.replace(
            'os.system("ping -c 1 " + host)',
            'os.system("ping -c 1 " + host)  # aegis: ignore',
        )
        self.assertIn("подавление", self._reject_reason(sneaky))

    def test_noqa_is_also_caught(self):
        sneaky = VULNERABLE.replace(
            'os.system("ping -c 1 " + host)',
            'os.system("ping -c 1 " + host)  # noqa',
        )
        self.assertIn("подавление", self._reject_reason(sneaky))

    def test_gutted_function(self):
        """Удалить опасный код вместе с функциональностью — не исправление."""
        gutted = VULNERABLE.replace(
            '    host = input("host: ")\n    os.system("ping -c 1 " + host)\n',
            "    pass\n",
        )
        self.assertIn("сохранность кода", self._reject_reason(gutted))

    def test_deleted_function(self):
        deleted = 'import os\n\n\ndef greet(name):\n    print("hello " + name)\n'
        self.assertIn("структура", self._reject_reason(deleted))

    def test_finding_not_resolved(self):
        cosmetic = VULNERABLE.replace('print("hello " + name)', 'print(f"hello {name}")')
        self.assertIn("находка устранена", self._reject_reason(cosmetic))

    def test_new_vulnerability_introduced(self):
        risky = CORRECT_FIX + '\n\ndef debug():\n    eval(input("expr: "))\n'
        self.assertIn("новые проблемы", self._reject_reason(risky))

    def test_whole_file_rewrite(self):
        padding = "\n".join(f"CONSTANT_{n} = {n}" for n in range(80))
        rewritten = CORRECT_FIX + "\n" + padding + "\n"
        self.assertIn("локальность", self._reject_reason(rewritten))

    def test_empty_patch(self):
        result = self.verifier.verify(VULNERABLE, VULNERABLE, self.finding, "app.py")
        self.assertFalse(result.accepted)


class TestAutoFixLoop(unittest.TestCase):
    def setUp(self):
        self.finding = target_finding()

    def test_good_answer_accepted_on_first_attempt(self):
        provider = ScriptedProvider(responses=[fenced(CORRECT_FIX)])
        outcome = AutoFixer(provider, ANALYZER).fix(VULNERABLE, self.finding)
        self.assertTrue(outcome.success)
        self.assertEqual(len(outcome.attempts), 1)
        self.assertEqual(outcome.patch, CORRECT_FIX)

    def test_retry_after_rejection(self):
        """Первый ответ отклонён, причина ушла модели, вторая попытка удалась."""
        cheating = VULNERABLE.replace(
            'os.system("ping -c 1 " + host)',
            'os.system("ping -c 1 " + host)  # aegis: ignore',
        )
        provider = ScriptedProvider(responses=[fenced(cheating), fenced(CORRECT_FIX)])
        outcome = AutoFixer(provider, ANALYZER).fix(VULNERABLE, self.finding)
        self.assertTrue(outcome.success)
        self.assertEqual(len(outcome.attempts), 2)
        self.assertFalse(outcome.attempts[0].accepted)

    def test_rejection_reason_is_sent_back(self):
        cheating = VULNERABLE.replace(
            'os.system("ping -c 1 " + host)',
            'os.system("ping -c 1 " + host)  # aegis: ignore',
        )
        provider = ScriptedProvider(responses=[fenced(cheating), fenced(CORRECT_FIX)])
        AutoFixer(provider, ANALYZER).fix(VULNERABLE, self.finding)
        second_request = provider.calls[1][1]
        self.assertIn("ОТКЛОНЕНА", second_request)
        self.assertIn("подавление", second_request)

    def test_gives_up_after_max_attempts(self):
        provider = ScriptedProvider(default=fenced("def broken(:\n    pass\n"))
        outcome = AutoFixer(provider, ANALYZER, max_attempts=2).fix(VULNERABLE, self.finding)
        self.assertFalse(outcome.success)
        self.assertEqual(len(outcome.attempts), 2)

    def test_prose_response_does_not_crash(self):
        provider = ScriptedProvider(default="Извините, я не могу помочь с этим кодом.")
        outcome = AutoFixer(provider, ANALYZER, max_attempts=2).fix(VULNERABLE, self.finding)
        self.assertFalse(outcome.success)
        self.assertIn("не найден блок кода", outcome.explain())

    def test_unavailable_model_is_handled(self):
        provider = ScriptedProvider(responses=[])  # сразу бросит LLMUnavailable
        outcome = AutoFixer(provider, ANALYZER).fix(VULNERABLE, self.finding)
        self.assertFalse(outcome.success)
        self.assertEqual(len(outcome.attempts), 1)

    def test_request_contains_trace_and_advice(self):
        request = build_request(VULNERABLE, self.finding)
        self.assertIn("AEG-INJ-001", request)
        self.assertIn("путь данных", request)
        self.assertIn("shlex.quote", request)

    def test_fix_all_builds_on_accepted_patches(self):
        source = 'import os\nimport hashlib\n\n\ndef run():\n    os.system(input())\n'
        step_one = 'import os\nimport shlex\nimport hashlib\n\n\ndef run():\n    os.system(shlex.quote(input()))\n'
        findings = [f for f in ANALYZER.analyze_source(source, "a.py") if f.rule_id == "AEG-INJ-001"]
        provider = ScriptedProvider(responses=[fenced(step_one)])
        outcomes = AutoFixer(provider, ANALYZER).fix_all(source, findings)
        self.assertTrue(outcomes[0].success)
        self.assertEqual(AutoFixer.final_source(source, outcomes), step_one)

    def test_verified_patch_really_is_clean(self):
        """Сквозная проверка: принятый патч действительно свободен от находки."""
        provider = ScriptedProvider(responses=[fenced(CORRECT_FIX)])
        outcome = AutoFixer(provider, ANALYZER).fix(VULNERABLE, self.finding)
        rules = {f.rule_id for f in ANALYZER.analyze_source(outcome.patch, "app.py")}
        self.assertNotIn("AEG-INJ-001", rules)


class TestTriage(unittest.TestCase):
    def test_note_is_parsed(self):
        note = parse_note('{"verdict": "confirmed", "reason": "данные из input()", "impact": "RCE"}')
        self.assertEqual(note.verdict, "подтверждено")
        self.assertEqual(note.impact, "RCE")

    def test_garbage_gives_no_note(self):
        self.assertIsNone(parse_note("не могу разобрать"))

    def test_unknown_verdict_is_rejected(self):
        self.assertIsNone(parse_note('{"verdict": "safe", "reason": "всё хорошо"}'))

    def test_missing_reason_is_rejected(self):
        self.assertIsNone(parse_note('{"verdict": "confirmed"}'))

    def test_annotation_never_removes_findings(self):
        """Ключевая гарантия: модель не может отменить находку."""
        findings = ANALYZER.analyze_source(VULNERABLE, "app.py")
        provider = ScriptedProvider(
            default='{"verdict": "likely_false_positive", "reason": "мне кажется, это безопасно"}'
        )
        annotated = Triager(provider).annotate(VULNERABLE, findings)
        self.assertEqual(len(annotated), len(findings))
        self.assertIn("AEG-INJ-001", {f.rule_id for f in annotated})

    def test_verdict_does_not_change_severity(self):
        findings = ANALYZER.analyze_source(VULNERABLE, "app.py")
        before = {f.rule_id: f.severity for f in findings}
        provider = ScriptedProvider(
            default='{"verdict": "likely_false_positive", "reason": "безопасно"}'
        )
        Triager(provider).annotate(VULNERABLE, findings)
        self.assertEqual({f.rule_id: f.severity for f in findings}, before)

    def test_note_reaches_the_finding(self):
        findings = ANALYZER.analyze_source(VULNERABLE, "app.py")
        provider = ScriptedProvider(
            default='{"verdict": "confirmed", "reason": "ввод пользователя доходит до оболочки"}'
        )
        Triager(provider).annotate(VULNERABLE, findings)
        annotated = [f for f in findings if f.notes]
        self.assertTrue(annotated)
        self.assertEqual(annotated[0].notes["ai_verdict"], "подтверждено")

    def test_unavailable_model_leaves_findings_untouched(self):
        findings = ANALYZER.analyze_source(VULNERABLE, "app.py")
        Triager(ScriptedProvider(responses=[])).annotate(VULNERABLE, findings)
        self.assertTrue(all(not f.notes for f in findings))

    def test_notes_appear_in_json_output(self):
        findings = ANALYZER.analyze_source(VULNERABLE, "app.py")
        provider = ScriptedProvider(default='{"verdict": "confirmed", "reason": "да"}')
        Triager(provider).annotate(VULNERABLE, findings)
        payload = [f.to_dict() for f in findings if f.notes][0]
        self.assertEqual(payload["notes"]["ai_verdict"], "подтверждено")


class TestProvider(unittest.TestCase):
    def test_scripted_provider_records_calls(self):
        provider = ScriptedProvider(responses=["первый", "второй"])
        provider.complete("s", "a")
        provider.complete("s", "b")
        self.assertEqual([call[1] for call in provider.calls], ["a", "b"])

    def test_missing_sdk_is_reported_clearly(self):
        with self.assertRaises(LLMUnavailable) as caught:
            AnthropicProvider().complete("s", "u")
        self.assertIn("anthropic", str(caught.exception))

    def test_core_analyzer_works_without_ai(self):
        """Связка необязательна: без модели анализатор работает как прежде."""
        self.assertTrue(ANALYZER.analyze_source(VULNERABLE, "app.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
