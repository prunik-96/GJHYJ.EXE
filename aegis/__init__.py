"""aegis — статический анализатор кода на Python.

Ищет уязвимости и ошибки без обращения к нейросетям: разбор в синтаксическое
дерево, построение графа потока управления, анализ потока данных и набор
правил по образцу. Результат воспроизводим и объясним — каждая находка
сопровождается путём данных от источника до опасной операции.
"""

__version__ = "1.0.0"

from .core.findings import Confidence, Finding, Severity  # noqa: F401
from .engine import Analyzer, Report, all_rules  # noqa: F401

__all__ = ["Analyzer", "Report", "Finding", "Severity", "Confidence", "all_rules", "__version__"]
