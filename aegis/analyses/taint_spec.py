"""Каталог источников, стоков и санитайзеров для анализа помеченных данных.

Модель простая: данные из *источника* считаются непроверенными. Если они
доходят до *стока*, не пройдя через *санитайзер*, это уязвимость.

Санитайзер нейтрализует не всё подряд, а конкретные категории: после
``html.escape`` строка безопасна для HTML, но по-прежнему опасна в
командной строке. Поэтому метка помнит, какие категории уже обезврежены.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..core.findings import Severity


@dataclass(frozen=True)
class SourceSpec:
    names: frozenset[str]
    label: str
    description: str
    prefix: bool = False


@dataclass(frozen=True)
class SinkSpec:
    names: frozenset[str]
    rule_id: str
    title: str
    message: str
    severity: Severity
    cwe: str
    category: str
    remediation: str
    positions: tuple[int, ...] = (0,)
    keywords: tuple[str, ...] = ()
    match: str = "qualified"  # qualified — полное имя, tail — только метод
    guard: Callable | None = field(default=None, compare=False)


# --- источники ------------------------------------------------------------

# Насколько данные из источника опасны: определяет итоговую уверенность.
TRUST: dict[str, str] = {
    "http": "high",
    "cli": "high",
    "user": "high",
    "network": "medium",
    "file": "medium",
    "env": "low",
}

SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec(frozenset({"flask.request"}), "http", "HTTP-запрос (Flask)", prefix=True),
    SourceSpec(frozenset({"bottle.request", "starlette.requests.Request"}), "http", "HTTP-запрос", prefix=True),
    SourceSpec(frozenset({"input", "builtins.input"}), "user", "ввод пользователя через input()"),
    SourceSpec(frozenset({"sys.argv"}), "cli", "аргументы командной строки", prefix=True),
    SourceSpec(frozenset({"os.environ"}), "env", "переменная окружения", prefix=True),
    SourceSpec(frozenset({"os.getenv", "os.environ.get"}), "env", "переменная окружения"),
    SourceSpec(
        frozenset({"requests.get", "requests.post", "requests.put", "requests.request",
                   "requests.patch", "requests.delete", "httpx.get", "httpx.post",
                   "urllib.request.urlopen"}),
        "network",
        "ответ внешнего сервиса",
    ),
)

# Атрибуты объекта с именем `request`: покрывает Django и Flask без импорта.
HTTP_REQUEST_ATTRS: frozenset[str] = frozenset({
    "GET", "POST", "args", "form", "json", "data", "body", "values",
    "cookies", "headers", "files", "query_params", "path_params", "stream",
})

# Методы, читающие данные извне, у объекта неизвестного типа.
NETWORK_READ_METHODS: frozenset[str] = frozenset({"recv", "recvfrom", "recv_into"})
FILE_READ_METHODS: frozenset[str] = frozenset({"read", "readline", "readlines"})

# Декораторы веб-фреймворков: их аргументы приходят прямо от пользователя.
HANDLER_DECORATOR_HINTS: frozenset[str] = frozenset({
    "route", "get", "post", "put", "delete", "patch", "websocket",
    "api_route", "endpoint", "command", "middleware",
})


# --- санитайзеры ----------------------------------------------------------

# None означает «снимает пометку полностью», иначе — набор категорий.
SANITIZERS: dict[str, frozenset[str] | None] = {
    "int": None,
    "float": None,
    "bool": None,
    "len": None,
    "hash": None,
    "uuid.UUID": None,
    "shlex.quote": frozenset({"command"}),
    "pipes.quote": frozenset({"command"}),
    "html.escape": frozenset({"xss"}),
    "markupsafe.escape": frozenset({"xss"}),
    "flask.escape": frozenset({"xss"}),
    "re.escape": frozenset({"regex"}),
    "os.path.basename": frozenset({"path"}),
    "werkzeug.utils.secure_filename": frozenset({"path"}),
    "urllib.parse.quote": frozenset({"path", "ssrf"}),
    "urllib.parse.quote_plus": frozenset({"path", "ssrf"}),
}


# --- вспомогательные проверки для стоков ----------------------------------

def _shell_enabled(node, env) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "shell":
            return env.is_true(keyword.value)
    return False


def _shell_disabled(node, env) -> bool:
    return not _shell_enabled(node, env)


def _yaml_unsafe(node, env) -> bool:
    """yaml.load опасен, если загрузчик не указан или не безопасный."""
    for keyword in node.keywords:
        if keyword.arg == "Loader":
            name = getattr(keyword.value, "attr", None) or getattr(keyword.value, "id", "")
            return "Safe" not in str(name)
    return len(node.args) < 2


# --- стоки ----------------------------------------------------------------

SINKS: tuple[SinkSpec, ...] = (
    SinkSpec(
        names=frozenset({"os.system", "os.popen", "os.execv", "os.execl", "os.spawnl", "os.spawnv"}),
        rule_id="AEG-INJ-001",
        title="Внедрение команд ОС",
        message="непроверенные данные попадают в командную строку операционной системы",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        category="command",
        remediation="Используйте subprocess со списком аргументов и shell=False; "
                    "если строка неизбежна, экранируйте её через shlex.quote().",
    ),
    SinkSpec(
        names=frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call",
                         "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput"}),
        rule_id="AEG-INJ-002",
        title="Внедрение команд через shell=True",
        message="непроверенные данные передаются в оболочку, потому что включён shell=True",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        category="command",
        remediation="Уберите shell=True и передайте команду списком: subprocess.run([\"cmd\", arg]).",
        guard=_shell_enabled,
    ),
    SinkSpec(
        names=frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call",
                         "subprocess.check_output", "subprocess.Popen"}),
        rule_id="AEG-INJ-003",
        title="Непроверенные данные в аргументах процесса",
        message="непроверенные данные попадают в аргументы запускаемого процесса",
        severity=Severity.MEDIUM,
        cwe="CWE-88",
        category="command",
        remediation="Проверьте значение по списку разрешённых или убедитесь, "
                    "что программа не трактует аргумент как опцию.",
        guard=_shell_disabled,
    ),
    SinkSpec(
        names=frozenset({"eval", "exec", "builtins.eval", "builtins.exec"}),
        rule_id="AEG-INJ-010",
        title="Выполнение произвольного кода",
        message="непроверенные данные исполняются как код Python",
        severity=Severity.CRITICAL,
        cwe="CWE-95",
        category="code",
        remediation="Замените eval/exec разбором данных: ast.literal_eval(), json.loads() "
                    "или явным отображением допустимых операций.",
    ),
    SinkSpec(
        names=frozenset({"pickle.loads", "pickle.load", "cPickle.loads", "dill.loads",
                         "marshal.loads", "shelve.open"}),
        rule_id="AEG-DESER-001",
        title="Небезопасная десериализация",
        message="непроверенные данные десериализуются, что позволяет выполнить произвольный код",
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        category="deserialization",
        remediation="Для данных извне используйте json, а целостность подтверждайте HMAC-подписью.",
    ),
    SinkSpec(
        names=frozenset({"yaml.load"}),
        rule_id="AEG-DESER-002",
        title="yaml.load без безопасного загрузчика",
        message="YAML разбирается загрузчиком, способным создавать произвольные объекты",
        severity=Severity.HIGH,
        cwe="CWE-502",
        category="deserialization",
        remediation="Используйте yaml.safe_load() или явно передайте Loader=yaml.SafeLoader.",
        guard=_yaml_unsafe,
    ),
    SinkSpec(
        names=frozenset({"execute", "executemany", "executescript", "raw"}),
        rule_id="AEG-SQL-001",
        title="SQL-инъекция",
        message="непроверенные данные подставляются в текст SQL-запроса",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        category="sql",
        remediation="Передавайте значения параметрами: cursor.execute(\"... WHERE id = ?\", (value,)).",
        match="tail",
    ),
    SinkSpec(
        names=frozenset({"open", "io.open", "os.remove", "os.unlink", "os.rmdir",
                         "shutil.rmtree", "shutil.copy", "shutil.move", "os.rename",
                         "pathlib.Path", "os.makedirs"}),
        rule_id="AEG-PATH-001",
        title="Обход каталога",
        message="путь к файлу строится из непроверенных данных",
        severity=Severity.HIGH,
        cwe="CWE-22",
        category="path",
        remediation="Возьмите только имя файла через os.path.basename() и проверьте, "
                    "что итоговый путь остался внутри разрешённого каталога.",
    ),
    SinkSpec(
        names=frozenset({"requests.get", "requests.post", "requests.put", "requests.delete",
                         "requests.head", "requests.request", "urllib.request.urlopen",
                         "httpx.get", "httpx.post"}),
        rule_id="AEG-SSRF-001",
        title="Подделка запроса со стороны сервера",
        message="адрес исходящего запроса задаётся непроверенными данными",
        severity=Severity.HIGH,
        cwe="CWE-918",
        category="ssrf",
        remediation="Разрешите только заранее известный список хостов и запретите "
                    "обращения к внутренним адресам.",
    ),
    SinkSpec(
        names=frozenset({"flask.render_template_string", "jinja2.Template",
                         "django.utils.safestring.mark_safe", "markupsafe.Markup"}),
        rule_id="AEG-XSS-001",
        title="Межсайтовый скриптинг",
        message="непроверенные данные попадают в HTML без экранирования",
        severity=Severity.HIGH,
        cwe="CWE-79",
        category="xss",
        remediation="Отдавайте данные через шаблон с автоэкранированием "
                    "или экранируйте вручную через html.escape().",
    ),
    SinkSpec(
        names=frozenset({"flask.redirect", "django.shortcuts.redirect"}),
        rule_id="AEG-REDIR-001",
        title="Открытое перенаправление",
        message="адрес перенаправления задаётся непроверенными данными",
        severity=Severity.MEDIUM,
        cwe="CWE-601",
        category="redirect",
        remediation="Разрешайте только относительные пути или список известных адресов.",
    ),
    SinkSpec(
        names=frozenset({"xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.parse",
                         "xml.dom.minidom.parseString", "xml.sax.parseString",
                         "lxml.etree.fromstring", "lxml.etree.parse"}),
        rule_id="AEG-XXE-001",
        title="Разбор XML из недоверенного источника",
        message="XML из непроверенного источника разбирается парсером, уязвимым к внешним сущностям",
        severity=Severity.HIGH,
        cwe="CWE-611",
        category="xxe",
        remediation="Используйте defusedxml — он отключает внешние сущности и защищает "
                    "от разрастания сущностей.",
    ),
    SinkSpec(
        names=frozenset({"getattr", "setattr", "delattr"}),
        rule_id="AEG-REFL-001",
        title="Обращение к атрибуту по непроверенному имени",
        message="имя атрибута берётся из непроверенных данных",
        severity=Severity.MEDIUM,
        cwe="CWE-470",
        category="reflection",
        remediation="Сверяйте имя со списком разрешённых атрибутов.",
        positions=(1,),
    ),
    SinkSpec(
        names=frozenset({"re.compile", "re.match", "re.search", "re.sub", "re.findall"}),
        rule_id="AEG-DOS-001",
        title="Регулярное выражение из непроверенных данных",
        message="шаблон регулярного выражения задаётся извне, что позволяет вызвать отказ в обслуживании",
        severity=Severity.MEDIUM,
        cwe="CWE-1333",
        category="regex",
        remediation="Не собирайте шаблон из пользовательских данных; экранируйте их через re.escape().",
    ),
)
