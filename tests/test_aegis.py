"""Тесты анализатора.

Проверяется не только обнаружение проблем, но и молчание на безопасном
коде: для статического анализатора ложное срабатывание — такой же дефект,
как пропущенная уязвимость.
"""

from __future__ import annotations

import ast
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis import Analyzer, Severity, all_rules  # noqa: E402
from aegis.analyses.constants import ConstantEnv  # noqa: E402
from aegis.cli import EXIT_CLEAN, EXIT_FINDINGS, main  # noqa: E402
from aegis.core.cfg import CFGBuilder, build_all  # noqa: E402
from aegis.core.symbols import SymbolTable  # noqa: E402
from aegis.engine import Report  # noqa: E402
from aegis.report import render_json, render_sarif, render_text  # noqa: E402

ANALYZER = Analyzer()


def rules_for(source: str, path: str = "sample.py") -> set[str]:
    """Набор идентификаторов правил, сработавших на исходнике."""
    return {finding.rule_id for finding in ANALYZER.analyze_source(source, path)}


def findings_for(source: str, path: str = "sample.py"):
    return ANALYZER.analyze_source(source, path)


class TestSymbolTable(unittest.TestCase):
    def resolve(self, imports: str, expression: str):
        tree = ast.parse(imports)
        table = SymbolTable.from_module(tree)
        return table.qualify(ast.parse(expression, mode="eval").body)

    def test_alias_is_resolved(self):
        self.assertEqual(self.resolve("import subprocess as sp", "sp.run"), "subprocess.run")

    def test_from_import_is_resolved(self):
        self.assertEqual(self.resolve("from os import system", "system"), "os.system")

    def test_renamed_from_import(self):
        self.assertEqual(self.resolve("from os import system as go", "go"), "os.system")

    def test_unknown_name_is_not_invented(self):
        self.assertIsNone(self.resolve("import os", "helper.run"))

    def test_local_definition_shadows_builtin(self):
        tree = ast.parse("def open(path):\n    return path\n")
        table = SymbolTable.from_module(tree)
        table.shadow_module_definitions(tree)
        node = ast.parse("open", mode="eval").body
        self.assertIsNone(table.matches(node, {"open"}))


class TestControlFlowGraph(unittest.TestCase):
    def test_branches_produce_two_paths(self):
        cfg = build_all(ast.parse("def f(x):\n    if x:\n        a = 1\n    else:\n        a = 2\n    return a\n"))[1]
        entry = cfg.blocks[cfg.entry]
        self.assertEqual(len(entry.succs), 2)
        self.assertEqual({edge.branch for edge in entry.succs}, {True, False})

    def test_loop_has_back_edge(self):
        cfg = build_all(ast.parse("def f(items):\n    for i in items:\n        print(i)\n"))[1]
        headers = [b for b in cfg.blocks.values() if b.label == "for-head"]
        self.assertTrue(headers)
        self.assertGreaterEqual(len(headers[0].preds), 2, "должно быть обратное ребро из тела цикла")

    def test_code_after_return_is_unreachable(self):
        tree = ast.parse("def f():\n    return 1\n    x = 2\n    return x\n")
        cfg = CFGBuilder.build("f", tree.body[0], tree.body[0].body)
        self.assertLess(len(cfg.reachable()), len(cfg.blocks))

    def test_every_scope_gets_its_own_graph(self):
        cfgs = build_all(ast.parse("def a():\n    pass\ndef b():\n    pass\n"))
        self.assertEqual([cfg.name for cfg in cfgs], ["<module>", "a", "b"])


class TestConstantEnv(unittest.TestCase):
    def test_single_assignment_is_known(self):
        env = ConstantEnv.from_scope(ast.parse("FLAG = True").body)
        self.assertIs(env.get(ast.parse("FLAG", mode="eval").body), True)

    def test_reassigned_name_is_unknown(self):
        env = ConstantEnv.from_scope(ast.parse("x = 1\nx = 2").body)
        self.assertFalse(env.is_true(ast.parse("x", mode="eval").body))


class TestTaintCommandInjection(unittest.TestCase):
    def test_user_input_reaches_os_system(self):
        source = "import os\nos.system('ping ' + input())\n"
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_shlex_quote_neutralises_command(self):
        source = "import os, shlex\nos.system('ping ' + shlex.quote(input()))\n"
        self.assertNotIn("AEG-INJ-001", rules_for(source))

    def test_html_escape_does_not_neutralise_command(self):
        """Санитайзер обезвреживает свою категорию, а не всё подряд."""
        source = "import os, html\nos.system('echo ' + html.escape(input()))\n"
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_shell_true_is_critical(self):
        source = "import subprocess\nsubprocess.run('ls ' + input(), shell=True)\n"
        findings = [f for f in findings_for(source) if f.rule_id == "AEG-INJ-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_argument_list_is_lower_severity(self):
        source = "import subprocess\nsubprocess.run(['ls', input()])\n"
        findings = [f for f in findings_for(source) if f.rule_id == "AEG-INJ-003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_constant_command_is_not_reported(self):
        source = "import subprocess\nsubprocess.run(['ls', '-la'])\n"
        self.assertEqual(rules_for(source), set())

    def test_flag_variable_counts_as_shell_true(self):
        source = "import subprocess\nUSE_SHELL = True\nsubprocess.run(input(), shell=USE_SHELL)\n"
        self.assertIn("AEG-INJ-002", rules_for(source))


class TestTaintFlow(unittest.TestCase):
    def test_taint_survives_variable_chain(self):
        source = (
            "import os\n"
            "raw = input()\n"
            "middle = raw.strip()\n"
            "final = f'echo {middle}'\n"
            "os.system(final)\n"
        )
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_taint_crosses_function_boundary(self):
        source = (
            "import os\n"
            "def run(cmd):\n"
            "    os.system(cmd)\n"
            "def main():\n"
            "    run(input())\n"
        )
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_flask_handler_parameters_are_tainted(self):
        source = (
            "import os\n"
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/x/<name>')\n"
            "def show(name):\n"
            "    os.system('cat ' + name)\n"
        )
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_partial_sanitisation_is_still_reported(self):
        source = (
            "import os, shlex\n"
            "def f(flag):\n"
            "    raw = input()\n"
            "    value = shlex.quote(raw) if flag else raw\n"
            "    os.system('echo ' + value)\n"
        )
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_int_conversion_removes_all_taint(self):
        source = "import os\nos.system('sleep ' + str(int(input())))\n"
        self.assertNotIn("AEG-INJ-001", rules_for(source))

    def test_trace_explains_the_path(self):
        source = "import os\ncmd = input()\nos.system(cmd)\n"
        finding = [f for f in findings_for(source) if f.rule_id == "AEG-INJ-001"][0]
        descriptions = " ".join(step.description for step in finding.trace)
        self.assertIn("источник", descriptions)
        self.assertIn("os.system", descriptions)
        self.assertGreaterEqual(len(finding.trace), 3)

    def test_environment_source_is_lower_confidence(self):
        source = "import os\nos.system(os.environ['CMD'])\n"
        findings = [f for f in findings_for(source) if f.category == "command"]
        self.assertTrue(findings)
        self.assertEqual(str(findings[0].confidence), "low")


class TestTaintOtherSinks(unittest.TestCase):
    def test_sql_injection_via_fstring(self):
        source = "def q(conn):\n    conn.execute(f\"SELECT * FROM t WHERE a={input()}\")\n"
        self.assertIn("AEG-SQL-001", rules_for(source))

    def test_parameterised_query_is_clean(self):
        source = "def q(conn):\n    conn.execute('SELECT * FROM t WHERE a=?', (input(),))\n"
        self.assertNotIn("AEG-SQL-001", rules_for(source))

    def test_path_traversal(self):
        self.assertIn("AEG-PATH-001", rules_for("data = open(input()).read()\n"))

    def test_basename_neutralises_path(self):
        source = "import os.path\ndata = open(os.path.basename(input())).read()\n"
        self.assertNotIn("AEG-PATH-001", rules_for(source))

    def test_code_execution(self):
        self.assertIn("AEG-INJ-010", rules_for("eval(input())\n"))

    def test_unsafe_deserialisation(self):
        source = "import pickle\nobj = pickle.loads(input().encode())\n"
        self.assertIn("AEG-DESER-001", rules_for(source))

    def test_yaml_load_without_loader(self):
        source = "import yaml\ncfg = yaml.load(open('c.yml').read())\n"
        self.assertIn("AEG-DESER-002", rules_for(source))

    def test_yaml_safe_load_is_clean(self):
        source = "import yaml\ncfg = yaml.safe_load(open('c.yml').read())\n"
        self.assertNotIn("AEG-DESER-002", rules_for(source))

    def test_ssrf(self):
        source = "import requests\nrequests.get(input())\n"
        self.assertIn("AEG-SSRF-001", rules_for(source))

    def test_xxe(self):
        source = "import xml.etree.ElementTree as ET\nET.fromstring(input())\n"
        self.assertIn("AEG-XXE-001", rules_for(source))


class TestNullness(unittest.TestCase):
    def test_unchecked_match_result(self):
        source = "import re\ndef f(t):\n    m = re.match('a', t)\n    return m.group()\n"
        self.assertIn("AEG-BUG-001", rules_for(source))

    def test_guarded_by_is_none(self):
        source = (
            "import re\n"
            "def f(t):\n"
            "    m = re.match('a', t)\n"
            "    if m is None:\n"
            "        return ''\n"
            "    return m.group()\n"
        )
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_guarded_by_truthiness(self):
        source = (
            "import re\n"
            "def f(t):\n"
            "    m = re.search('a', t)\n"
            "    if m:\n"
            "        return m.group()\n"
            "    return ''\n"
        )
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_chained_call_on_optional(self):
        source = "import re\ndef f(t):\n    return re.match('a', t).group()\n"
        self.assertIn("AEG-BUG-001", rules_for(source))

    def test_none_default_parameter(self):
        self.assertIn("AEG-BUG-001", rules_for("def f(v=None):\n    return v.upper()\n"))

    def test_or_default_clears_suspicion(self):
        source = "def f(v=None):\n    v = v or ''\n    return v.upper()\n"
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_isinstance_is_a_guard(self):
        """isinstance(x, str) исключает None — частая идиома Python."""
        source = "def f(v=None):\n    if isinstance(v, str):\n        return v.upper()\n    return ''\n"
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_isinstance_inside_ternary(self):
        source = "def f(v=None):\n    return v.strip() if isinstance(v, str) else ''\n"
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_and_chain_guard(self):
        source = "def f(v=None):\n    return v is not None and v.upper()\n"
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_truthiness_and_chain(self):
        source = "def f(v=None):\n    return bool(v and v.strip())\n"
        self.assertNotIn("AEG-BUG-001", rules_for(source))

    def test_unrelated_ternary_condition_still_reported(self):
        """Условие, не проверяющее значение, защитой не является."""
        source = "def f(flag, v=None):\n    return v.upper() if flag else ''\n"
        self.assertIn("AEG-BUG-001", rules_for(source))

    def test_isinstance_with_none_type_is_not_a_guard(self):
        source = "def f(v=None):\n    if isinstance(v, type(None)):\n        return v.upper()\n    return ''\n"
        self.assertIn("AEG-BUG-001", rules_for(source))

    def test_assert_clears_suspicion(self):
        source = (
            "import re\n"
            "def f(t):\n"
            "    m = re.match('a', t)\n"
            "    assert m is not None\n"
            "    return m.group()\n"
        )
        self.assertNotIn("AEG-BUG-001", rules_for(source))


class TestSecretRules(unittest.TestCase):
    def test_hardcoded_password(self):
        self.assertIn("AEG-SECRET-001", rules_for('PASSWORD = "s3cr3t-value-42"\n'))

    def test_high_entropy_is_high_severity(self):
        finding = [f for f in findings_for('API_KEY = "a8Kd93Lm2qXzPw41"\n') if f.rule_id == "AEG-SECRET-001"][0]
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_prose_is_not_a_secret(self):
        self.assertNotIn("AEG-SECRET-001", rules_for('password_prompt = "Введите ваш пароль"\n'))

    def test_env_lookup_is_not_a_secret(self):
        source = "import os\nPASSWORD = os.environ['PASSWORD']\n"
        self.assertNotIn("AEG-SECRET-001", rules_for(source))

    def test_keyword_argument_secret(self):
        source = "def connect(**kw): pass\nconnect(password='qwerty-123456')\n"
        self.assertIn("AEG-SECRET-001", rules_for(source))

    def test_tests_are_exempt(self):
        self.assertNotIn("AEG-SECRET-001", rules_for('PASSWORD = "abc12345"\n', "tests/test_x.py"))


class TestCryptoRules(unittest.TestCase):
    def test_md5_flagged(self):
        self.assertIn("AEG-CRYPTO-001", rules_for("import hashlib\nhashlib.md5(b'x')\n"))

    def test_md5_marked_non_security_is_allowed(self):
        source = "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"
        self.assertNotIn("AEG-CRYPTO-001", rules_for(source))

    def test_sha256_is_fine(self):
        self.assertNotIn("AEG-CRYPTO-001", rules_for("import hashlib\nhashlib.sha256(b'x')\n"))

    def test_password_context_raises_severity(self):
        source = "import hashlib\ndef hash_password(p):\n    return hashlib.md5(p).hexdigest()\n"
        finding = [f for f in findings_for(source) if f.rule_id == "AEG-CRYPTO-001"][0]
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_verify_false(self):
        source = "import requests\nrequests.get('https://x', verify=False)\n"
        self.assertIn("AEG-CRYPTO-003", rules_for(source))

    def test_random_for_token(self):
        source = "import random\ndef make():\n    session_token = random.choice('abc')\n    return session_token\n"
        self.assertIn("AEG-CRYPTO-004", rules_for(source))

    def test_random_for_ordinary_value_is_allowed(self):
        source = "import random\ndef pick():\n    colour = random.choice(['red', 'blue'])\n    return colour\n"
        self.assertNotIn("AEG-CRYPTO-004", rules_for(source))


class TestConfigAndBugRules(unittest.TestCase):
    def test_debug_true(self):
        source = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
        self.assertIn("AEG-CONF-001", rules_for(source))

    def test_world_writable_chmod(self):
        self.assertIn("AEG-CONF-003", rules_for("import os\nos.chmod('/tmp/f', 0o777)\n"))

    def test_safe_chmod(self):
        self.assertNotIn("AEG-CONF-003", rules_for("import os\nos.chmod('/tmp/f', 0o600)\n"))

    def test_mktemp(self):
        self.assertIn("AEG-CONF-004", rules_for("import tempfile\np = tempfile.mktemp()\n"))

    def test_extractall_without_filter(self):
        source = "import tarfile\ntarfile.open('a.tar').extractall('/tmp')\n"
        self.assertIn("AEG-CONF-005", rules_for(source))

    def test_mutable_default(self):
        self.assertIn("AEG-BUG-002", rules_for("def f(items=[]):\n    return items\n"))

    def test_none_default_is_fine(self):
        self.assertNotIn("AEG-BUG-002", rules_for("def f(items=None):\n    return items or []\n"))

    def test_swallowed_exception(self):
        self.assertIn("AEG-BUG-003", rules_for("try:\n    x = 1\nexcept Exception:\n    pass\n"))

    def test_handled_exception_is_fine(self):
        source = "import logging\ntry:\n    x = 1\nexcept ValueError:\n    logging.exception('fail')\n"
        self.assertNotIn("AEG-BUG-003", rules_for(source))

    def test_unreachable_code(self):
        self.assertIn("AEG-BUG-004", rules_for("def f():\n    return 1\n    print('never')\n"))

    def test_identity_with_literal(self):
        self.assertIn("AEG-BUG-005", rules_for("def f(x):\n    return x is 'abc'\n"))

    def test_identity_with_none_is_correct(self):
        self.assertNotIn("AEG-BUG-005", rules_for("def f(x):\n    return x is None\n"))

    def test_timing_attack(self):
        source = "def check(given, stored_password):\n    return given == stored_password\n"
        self.assertIn("AEG-BUG-006", rules_for(source))

    def test_duplicate_dict_key(self):
        self.assertIn("AEG-BUG-007", rules_for("d = {'a': 1, 'b': 2, 'a': 3}\n"))


class TestEngineBehaviour(unittest.TestCase):
    def test_syntax_error_is_reported_not_raised(self):
        findings = findings_for("def broken(:\n    pass\n")
        self.assertEqual([f.rule_id for f in findings], ["AEG-PARSE-001"])

    def test_suppression_comment(self):
        source = "import os\nos.system(input())  # aegis: ignore\n"
        self.assertEqual(rules_for(source), set())

    def test_targeted_suppression(self):
        source = "import os\nos.system(input())  # aegis: ignore=AEG-BUG-001\n"
        self.assertIn("AEG-INJ-001", rules_for(source))

    def test_severity_filter(self):
        analyzer = Analyzer(min_severity=Severity.CRITICAL)
        findings = analyzer.analyze_source("def f(items=[]):\n    return items\n", "s.py")
        self.assertEqual(findings, [])

    def test_rule_filter(self):
        analyzer = Analyzer(enabled_rules={"AEG-BUG-002"})
        source = "import os\nos.system(input())\ndef f(items=[]):\n    return items\n"
        self.assertEqual({f.rule_id for f in analyzer.analyze_source(source, "s.py")}, {"AEG-BUG-002"})

    def test_disable_rule(self):
        analyzer = Analyzer(disabled_rules={"AEG-INJ-001"})
        findings = analyzer.analyze_source("import os\nos.system(input())\n", "s.py")
        self.assertEqual(findings, [])

    def test_findings_are_sorted_by_severity(self):
        source = (
            "import os\n"
            "def f(items=[]):\n"
            "    return items\n"
            "os.system(input())\n"
        )
        report = Report(findings=sorted(findings_for(source), key=lambda f: f.sort_key()))
        self.assertEqual(report.findings[0].severity, Severity.CRITICAL)

    def test_snippet_is_attached(self):
        finding = findings_for("import os\nos.system(input())\n")[0]
        self.assertIn("os.system", finding.snippet)

    def test_analysis_is_deterministic(self):
        source = "import os\nfor i in range(3):\n    os.system(input())\n"
        first = [f.location for f in findings_for(source)]
        second = [f.location for f in findings_for(source)]
        self.assertEqual(first, second)

    def test_empty_file_is_clean(self):
        self.assertEqual(findings_for(""), [])

    def test_catalog_ids_are_unique(self):
        ids = [rule["id"] for rule in all_rules()]
        self.assertEqual(len(ids), len(set(ids)))


class TestReporters(unittest.TestCase):
    def setUp(self):
        source = "import os\ncmd = input()\nos.system(cmd)\n"
        self.report = Report(findings=findings_for(source), files_scanned=1, duration=0.01)

    def test_json_is_valid(self):
        payload = json.loads(render_json(self.report))
        self.assertEqual(payload["summary"]["total"], len(self.report.findings))
        self.assertTrue(payload["findings"][0]["trace"])

    def test_sarif_structure(self):
        payload = json.loads(render_sarif(self.report))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "aegis")
        self.assertTrue(run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"])

    def test_text_contains_trace_and_fix(self):
        text = render_text(self.report, color=False)
        self.assertIn("путь данных", text)
        self.assertIn("как исправить", text)

    def test_text_without_findings(self):
        self.assertIn("Проблем не найдено", render_text(Report(), color=False))


class TestCommandLine(unittest.TestCase):
    def _run(self, source: str, *extra: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "module.py")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(source)
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([target, "--no-color", *extra])
            return code, buffer.getvalue()

    def test_exit_code_on_findings(self):
        code, output = self._run("import os\nos.system(input())\n")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("AEG-INJ-001", output)

    def test_exit_code_when_clean(self):
        code, _ = self._run("value = 1 + 1\n")
        self.assertEqual(code, EXIT_CLEAN)

    def test_fail_on_threshold_respected(self):
        code, _ = self._run("def f(items=[]):\n    return items\n", "--fail-on", "critical")
        self.assertEqual(code, EXIT_CLEAN)

    def test_json_output_format(self):
        code, output = self._run("import os\nos.system(input())\n", "--format", "json")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(json.loads(output)["tool"], "aegis")

    def test_list_rules(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--list-rules"])
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("AEG-INJ-001", buffer.getvalue())


class TestSelfScan(unittest.TestCase):
    """Анализатор должен без падений разбирать собственный исходный код."""

    def test_analyzer_scans_itself(self):
        package = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aegis")
        report = Analyzer().analyze_paths([package])
        self.assertGreater(report.files_scanned, 8)
        critical = [f for f in report.findings if f.severity >= Severity.HIGH]
        self.assertEqual(critical, [], f"в самом анализаторе найдены серьёзные проблемы: {critical}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
