"""Набор проверок, не требующих анализа потока данных."""

from __future__ import annotations

import ast
import math
import re

from ..core.findings import Confidence, Severity, TraceStep
from ..core.symbols import attribute_tail, dotted_name
from .engine import RuleContext, define, keyword_of, on

# --- общие вспомогательные средства ---------------------------------------

SECRET_NAME = re.compile(
    r"(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|auth[_-]?key|session[_-]?key)",
    re.IGNORECASE,
)

# Значения, которые выглядят как заглушка, а не как настоящий секрет.
PLACEHOLDERS = frozenset({
    "changeme", "change_me", "password", "secret", "token", "xxx", "todo",
    "none", "null", "example", "test", "dummy", "placeholder", "your_key_here",
})


def shannon_entropy(text: str) -> float:
    """Энтропия строки: случайный ключ имеет высокую, слово — низкую."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_secret(value: str) -> bool:
    """Отсеять подсказки, сообщения и шаблоны — это не секреты."""
    if len(value) < 4 or len(value) > 256:
        return False
    if " " in value or "\n" in value:
        return False  # почти наверняка текст сообщения, а не пароль
    if "{" in value or "%s" in value or "%(" in value:
        return False  # шаблон подстановки
    if value.startswith(("http://", "https://", "/", "./", "$")):
        return False
    if len(set(value)) == 1:
        return False
    return True


def is_test_path(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    return "/test" in lowered or lowered.startswith("test") or "/tests/" in lowered


# --- секреты в исходном коде ----------------------------------------------

HARDCODED_SECRET = define(
    id="AEG-SECRET-001",
    title="Секрет в исходном коде",
    message="пароль или ключ записан прямо в коде",
    severity=Severity.HIGH,
    cwe="CWE-798",
    category="secrets",
    remediation="Вынесите значение в переменную окружения или хранилище секретов "
                "и удалите его из истории репозитория — файл уже скомпрометирован.",
)


def _report_secret(context: RuleContext, node: ast.AST, name: str, value: str) -> None:
    if not looks_like_secret(value):
        return
    entropy = shannon_entropy(value)
    if value.lower() in PLACEHOLDERS:
        severity, confidence = Severity.LOW, Confidence.MEDIUM
        note = "значение похоже на заглушку, но проверка по нему всё равно работает"
    elif entropy >= 3.0 or len(value) >= 12:
        severity, confidence = Severity.HIGH, Confidence.HIGH
        note = f"энтропия {entropy:.1f} — строка похожа на настоящий ключ"
    else:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        note = "короткое значение, но имя переменной указывает на секрет"
    context.emit(
        HARDCODED_SECRET,
        node,
        message=f"{name} содержит записанное в коде значение",
        severity=severity,
        confidence=confidence,
        trace=[TraceStep(getattr(node, "lineno", 0), note)],
    )


@on(ast.Assign)
def check_secret_assignment(node: ast.Assign, context: RuleContext) -> None:
    if is_test_path(context.path):
        return
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
        return
    for target in node.targets:
        name = target.id if isinstance(target, ast.Name) else attribute_tail(target)
        if name and SECRET_NAME.search(name):
            _report_secret(context, node, name, node.value.value)


@on(ast.Call)
def check_secret_keyword(node: ast.Call, context: RuleContext) -> None:
    if is_test_path(context.path):
        return
    for keyword in node.keywords:
        if not keyword.arg or not SECRET_NAME.search(keyword.arg):
            continue
        if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            _report_secret(context, keyword.value, keyword.arg, keyword.value.value)


# --- криптография ----------------------------------------------------------

WEAK_HASH = define(
    id="AEG-CRYPTO-001",
    title="Устаревшая хеш-функция",
    message="MD5 и SHA-1 считаются взломанными и не годятся для защиты",
    severity=Severity.MEDIUM,
    cwe="CWE-327",
    category="crypto",
    remediation="Для контроля целостности возьмите SHA-256, для паролей — "
                "bcrypt, scrypt или argon2 из passlib.",
)

WEAK_CIPHER = define(
    id="AEG-CRYPTO-002",
    title="Слабый алгоритм шифрования",
    message="алгоритм или режим шифрования признан небезопасным",
    severity=Severity.HIGH,
    cwe="CWE-327",
    category="crypto",
    remediation="Используйте AES в режиме GCM либо готовую обёртку cryptography.fernet.",
)

TLS_DISABLED = define(
    id="AEG-CRYPTO-003",
    title="Отключена проверка сертификата TLS",
    message="соединение не проверяет подлинность сервера и уязвимо к перехвату",
    severity=Severity.HIGH,
    cwe="CWE-295",
    category="crypto",
    remediation="Включите проверку сертификата; для внутренних служб добавьте "
                "свой корневой сертификат через параметр verify.",
)

WEAK_RANDOM = define(
    id="AEG-CRYPTO-004",
    title="Предсказуемый генератор случайных чисел",
    message="модуль random предсказуем и не подходит для секретов",
    severity=Severity.HIGH,
    cwe="CWE-338",
    category="crypto",
    remediation="Используйте модуль secrets: secrets.token_urlsafe() или secrets.choice().",
)

_WEAK_HASHES = frozenset({"hashlib.md5", "hashlib.sha1"})
_WEAK_ALGO_NAMES = frozenset({"md5", "sha1", "md4"})
_WEAK_CIPHERS = ("Crypto.Cipher.DES", "Crypto.Cipher.ARC4", "Crypto.Cipher.XOR",
                 "Cryptodome.Cipher.DES", "Cryptodome.Cipher.ARC4")
_RANDOM_CALLS = frozenset({
    "random.random", "random.randint", "random.randrange", "random.choice",
    "random.choices", "random.sample", "random.shuffle", "random.uniform",
    "random.getrandbits",
})


@on(ast.Call)
def check_weak_hash(node: ast.Call, context: RuleContext) -> None:
    qualified = context.qualified(node.func)
    if qualified is None:
        return
    keyword = keyword_of(node, "usedforsecurity")
    if keyword is not None and context.env.get(keyword.value) is False:
        return  # автор явно отметил, что защита тут ни при чём
    algorithm = None
    if qualified in _WEAK_HASHES:
        algorithm = qualified.rsplit(".", 1)[-1]
    elif qualified == "hashlib.new" and node.args:
        name = context.env.as_text(node.args[0])
        if name and name.lower() in _WEAK_ALGO_NAMES:
            algorithm = name.lower()
    if algorithm is None:
        return
    function = context.enclosing_function(node)
    context_name = getattr(function, "name", "") or ""
    password_context = bool(SECRET_NAME.search(context_name))
    context.emit(
        WEAK_HASH,
        node,
        message=f"{algorithm.upper()} не обеспечивает стойкости к подбору и коллизиям",
        severity=Severity.HIGH if password_context else Severity.MEDIUM,
        confidence=Confidence.HIGH if password_context else Confidence.MEDIUM,
    )


@on(ast.Call, ast.Attribute)
def check_weak_cipher(node: ast.AST, context: RuleContext) -> None:
    target = node.func if isinstance(node, ast.Call) else node
    qualified = context.qualified(target) or (dotted_name(target) or "")
    if any(qualified.startswith(prefix) for prefix in _WEAK_CIPHERS):
        context.emit(WEAK_CIPHER, node, message=f"{qualified} — устаревший шифр")
        return
    if qualified.endswith("MODE_ECB"):
        context.emit(
            WEAK_CIPHER,
            node,
            message="режим ECB не скрывает повторяющиеся блоки открытого текста",
        )


@on(ast.Call)
def check_tls_verification(node: ast.Call, context: RuleContext) -> None:
    qualified = context.qualified(node.func)
    if qualified == "ssl._create_unverified_context":
        context.emit(TLS_DISABLED, node, message="создаётся контекст TLS без проверки сертификата")
        return
    keyword = keyword_of(node, "verify")
    if keyword is not None and context.env.get(keyword.value) is False:
        context.emit(TLS_DISABLED, node, message="передан verify=False — сертификат не проверяется")


@on(ast.Assign)
def check_tls_attributes(node: ast.Assign, context: RuleContext) -> None:
    value = context.env.get(node.value)
    qualified_value = context.qualified(node.value) or ""
    for target in node.targets:
        name = attribute_tail(target)
        if name == "check_hostname" and value is False:
            context.emit(TLS_DISABLED, node, message="проверка имени хоста отключена")
        elif name == "verify_mode" and qualified_value.endswith("CERT_NONE"):
            context.emit(TLS_DISABLED, node, message="режим проверки сертификата — CERT_NONE")


@on(ast.Call)
def check_weak_random(node: ast.Call, context: RuleContext) -> None:
    qualified = context.qualified(node.func)
    if qualified not in _RANDOM_CALLS:
        return
    # Обычный random опасен только там, где результат используется как секрет.
    function = context.enclosing_function(node)
    haystack = getattr(function, "name", "") or ""
    parent = context.parent(node)
    if isinstance(parent, ast.Assign):
        for target in parent.targets:
            haystack += " " + (target.id if isinstance(target, ast.Name) else (attribute_tail(target) or ""))
    if not SECRET_NAME.search(haystack):
        return
    context.emit(
        WEAK_RANDOM,
        node,
        message=f"{qualified} предсказуем, а результат используется как секрет",
    )


# --- небезопасные настройки ------------------------------------------------

DEBUG_ENABLED = define(
    id="AEG-CONF-001",
    title="Включён режим отладки",
    message="режим отладки открывает доступ к интерактивной консоли на сервере",
    severity=Severity.HIGH,
    cwe="CWE-489",
    category="config",
    remediation="Управляйте флагом через переменную окружения и держите его выключенным "
                "в рабочей среде.",
)

BIND_ALL = define(
    id="AEG-CONF-002",
    title="Служба слушает все интерфейсы",
    message="привязка к 0.0.0.0 делает службу доступной из внешней сети",
    severity=Severity.MEDIUM,
    cwe="CWE-1327",
    category="config",
    remediation="Слушайте 127.0.0.1, если доступ нужен только локально.",
)

WORLD_WRITABLE = define(
    id="AEG-CONF-003",
    title="Слишком широкие права на файл",
    message="файл становится доступным для записи всем пользователям системы",
    severity=Severity.HIGH,
    cwe="CWE-732",
    category="config",
    remediation="Выдавайте минимальные права: 0o600 для секретов, 0o644 для обычных файлов.",
)

INSECURE_TEMP = define(
    id="AEG-CONF-004",
    title="Небезопасное создание временного файла",
    message="между получением имени и созданием файла его может подменить другой процесс",
    severity=Severity.MEDIUM,
    cwe="CWE-377",
    category="config",
    remediation="Используйте tempfile.mkstemp() или NamedTemporaryFile.",
)

UNSAFE_EXTRACT = define(
    id="AEG-CONF-005",
    title="Распаковка архива без проверки путей",
    message="запись файла может выйти за пределы каталога назначения",
    severity=Severity.HIGH,
    cwe="CWE-22",
    category="config",
    remediation="Передайте filter=\"data\" (Python 3.12+) либо проверяйте каждый путь вручную.",
)

AUTOESCAPE_OFF = define(
    id="AEG-CONF-006",
    title="Шаблонизатор без автоэкранирования",
    message="без автоэкранирования любые данные в шаблоне превращаются в HTML",
    severity=Severity.HIGH,
    cwe="CWE-79",
    category="config",
    remediation="Создавайте окружение с autoescape=True.",
)

ASSERT_VALIDATION = define(
    id="AEG-CONF-007",
    title="Проверка через assert",
    message="при запуске с флагом -O инструкции assert удаляются, и проверка исчезает",
    severity=Severity.LOW,
    cwe="CWE-617",
    category="config",
    remediation="Замените явной проверкой с возбуждением исключения.",
)


@on(ast.Call)
def check_debug_flag(node: ast.Call, context: RuleContext) -> None:
    if attribute_tail(node.func) not in ("run", "run_server"):
        return
    keyword = keyword_of(node, "debug")
    if keyword is not None and context.env.get(keyword.value) is True:
        context.emit(DEBUG_ENABLED, node)


@on(ast.Call)
def check_bind_all(node: ast.Call, context: RuleContext) -> None:
    candidates = [keyword.value for keyword in node.keywords if keyword.arg == "host"]
    candidates += list(node.args)
    for candidate in candidates:
        text = context.env.as_text(candidate)
        if text in ("0.0.0.0", "::"):
            context.emit(BIND_ALL, node, confidence=Confidence.MEDIUM)
            return
        if isinstance(candidate, ast.Tuple) and candidate.elts:
            inner = context.env.as_text(candidate.elts[0])
            if inner in ("0.0.0.0", "::"):
                context.emit(BIND_ALL, node, confidence=Confidence.MEDIUM)
                return


@on(ast.Call)
def check_permissions(node: ast.Call, context: RuleContext) -> None:
    qualified = context.qualified(node.func)
    if qualified not in ("os.chmod", "os.fchmod", "os.lchmod") or len(node.args) < 2:
        return
    mode = context.env.get(node.args[1])
    if not isinstance(mode, int):
        return
    if mode & 0o002:
        context.emit(
            WORLD_WRITABLE,
            node,
            message=f"права {oct(mode)} разрешают запись любому пользователю",
        )
    elif mode & 0o004 and mode & 0o070 == 0o070:
        context.emit(
            WORLD_WRITABLE,
            node,
            message=f"права {oct(mode)} шире необходимого",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
        )


@on(ast.Call)
def check_insecure_temp(node: ast.Call, context: RuleContext) -> None:
    if context.qualified(node.func) == "tempfile.mktemp":
        context.emit(INSECURE_TEMP, node)


@on(ast.Call)
def check_archive_extract(node: ast.Call, context: RuleContext) -> None:
    if attribute_tail(node.func) != "extractall":
        return
    if keyword_of(node, "filter") is not None or keyword_of(node, "members") is not None:
        return
    context.emit(UNSAFE_EXTRACT, node, confidence=Confidence.MEDIUM)


@on(ast.Call)
def check_autoescape(node: ast.Call, context: RuleContext) -> None:
    qualified = context.qualified(node.func) or ""
    if not qualified.endswith("jinja2.Environment") and qualified != "jinja2.Environment":
        return
    keyword = keyword_of(node, "autoescape")
    if keyword is None:
        context.emit(AUTOESCAPE_OFF, node, message="autoescape не задан, а по умолчанию он выключен")
    elif context.env.get(keyword.value) is False:
        context.emit(AUTOESCAPE_OFF, node, message="autoescape явно выключен")


@on(ast.Assert)
def check_assert(node: ast.Assert, context: RuleContext) -> None:
    if is_test_path(context.path):
        return
    context.emit(ASSERT_VALIDATION, node, confidence=Confidence.MEDIUM)


# --- типовые ошибки --------------------------------------------------------

MUTABLE_DEFAULT = define(
    id="AEG-BUG-002",
    title="Изменяемое значение по умолчанию",
    message="значение по умолчанию создаётся один раз и сохраняется между вызовами",
    severity=Severity.MEDIUM,
    cwe="CWE-1188",
    category="reliability",
    remediation="Поставьте None по умолчанию и создавайте объект внутри функции.",
)

SWALLOWED_ERROR = define(
    id="AEG-BUG-003",
    title="Исключение подавляется без обработки",
    message="ошибка молча игнорируется, поэтому сбой останется незамеченным",
    severity=Severity.LOW,
    cwe="CWE-390",
    category="reliability",
    remediation="Запишите ошибку в журнал или обработайте её явно; "
                "для намеренного пропуска используйте contextlib.suppress.",
)

UNREACHABLE = define(
    id="AEG-BUG-004",
    title="Недостижимый код",
    message="управление никогда не доходит до этой строки",
    severity=Severity.LOW,
    cwe="CWE-561",
    category="reliability",
    remediation="Удалите мёртвый код или исправьте условие выше.",
)

IDENTITY_LITERAL = define(
    id="AEG-BUG-005",
    title="Сравнение литерала через is",
    message="is сравнивает объекты по адресу, и для литералов результат не гарантирован",
    severity=Severity.MEDIUM,
    cwe="CWE-595",
    category="reliability",
    remediation="Используйте == для сравнения значений.",
)

TIMING_ATTACK = define(
    id="AEG-BUG-006",
    title="Сравнение секрета обычным оператором",
    message="обычное сравнение прекращается на первом различии, что позволяет "
            "подобрать значение по времени ответа",
    severity=Severity.MEDIUM,
    cwe="CWE-208",
    category="crypto",
    remediation="Сравнивайте через secrets.compare_digest() — оно работает за постоянное время.",
)

DUPLICATE_KEY = define(
    id="AEG-BUG-007",
    title="Повторяющийся ключ в словаре",
    message="более раннее значение будет молча затёрто",
    severity=Severity.MEDIUM,
    cwe="CWE-561",
    category="reliability",
    remediation="Уберите дубликат или переименуйте ключ.",
)

_TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


@on(ast.FunctionDef, ast.AsyncFunctionDef)
def check_mutable_default(node: ast.AST, context: RuleContext) -> None:
    defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
    for default in defaults:
        if isinstance(default, (ast.List, ast.Dict, ast.Set)):
            context.emit(MUTABLE_DEFAULT, default)
        elif isinstance(default, ast.Call):
            name = context.qualified(default.func) or dotted_name(default.func)
            if name in ("list", "dict", "set", "collections.defaultdict"):
                context.emit(MUTABLE_DEFAULT, default)


@on(ast.ExceptHandler)
def check_swallowed_error(node: ast.ExceptHandler, context: RuleContext) -> None:
    body = [stmt for stmt in node.body if not isinstance(stmt, ast.Expr) or
            not isinstance(stmt.value, ast.Constant) or not isinstance(stmt.value.value, str)]
    silent = all(
        isinstance(stmt, ast.Pass)
        or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis)
        for stmt in body
    ) and bool(body)
    if silent:
        scope = "любое исключение" if node.type is None else "исключение"
        context.emit(SWALLOWED_ERROR, node, message=f"{scope} перехвачено и отброшено без действий")
    elif node.type is None:
        context.emit(
            SWALLOWED_ERROR,
            node,
            message="голый except перехватывает в том числе KeyboardInterrupt и SystemExit",
            confidence=Confidence.MEDIUM,
        )


def _scan_block(statements: list[ast.stmt], context: RuleContext) -> None:
    for index, stmt in enumerate(statements[:-1]):
        if isinstance(stmt, _TERMINATORS):
            follower = statements[index + 1]
            context.emit(
                UNREACHABLE,
                follower,
                message=f"строка недостижима: выше стоит {type(stmt).__name__.lower()}",
            )
            return


@on(ast.FunctionDef, ast.AsyncFunctionDef, ast.If, ast.For, ast.While, ast.With, ast.Try)
def check_unreachable(node: ast.AST, context: RuleContext) -> None:
    for field_name in ("body", "orelse", "finalbody"):
        block = getattr(node, field_name, None)
        if isinstance(block, list) and len(block) > 1:
            _scan_block(block, context)


@on(ast.Compare)
def check_identity_literal(node: ast.Compare, context: RuleContext) -> None:
    for operator, comparator in zip(node.ops, node.comparators):
        if not isinstance(operator, (ast.Is, ast.IsNot)):
            continue
        for side in (node.left, comparator):
            if isinstance(side, ast.Constant) and isinstance(side.value, (str, int, float, bytes)) \
                    and not isinstance(side.value, bool):
                context.emit(IDENTITY_LITERAL, node)
                return


@on(ast.Compare)
def check_timing_attack(node: ast.Compare, context: RuleContext) -> None:
    if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
        return
    for side in (node.left, node.comparators[0]):
        name = side.id if isinstance(side, ast.Name) else attribute_tail(side)
        if not name or not SECRET_NAME.search(name):
            continue
        other = node.comparators[0] if side is node.left else node.left
        if isinstance(other, ast.Constant) and other.value is None:
            return
        context.emit(TIMING_ATTACK, node, message=f"значение {name} сравнивается оператором ==")
        return


@on(ast.Dict)
def check_duplicate_keys(node: ast.Dict, context: RuleContext) -> None:
    seen: dict[object, int] = {}
    for key_node in node.keys:
        if key_node is None or not isinstance(key_node, ast.Constant):
            continue
        value = key_node.value
        try:
            hash(value)
        except TypeError:
            continue
        if value in seen:
            context.emit(
                DUPLICATE_KEY,
                key_node,
                message=f"ключ {value!r} уже задан в строке {seen[value]}",
            )
        else:
            seen[value] = key_node.lineno
