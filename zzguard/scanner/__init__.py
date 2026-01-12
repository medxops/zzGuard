"""Scanner module for detecting detection patterns in AI responses.

Provides multiple scanner implementations:
- RegexScanner: Fast pattern matching (default)
- ASTScanner: Python-specific semantic analysis
- SemgrepScanner: Production-grade static analysis
- CombinedScanner: Uses multiple scanners together
- MultiScanner: Configurable multi-scanner
"""

from zzguard.scanner.interface import ScannerInterface
from zzguard.scanner.regex_scanner import RegexScanner
from zzguard.scanner.analyzer import Analyzer, get_scanner
from zzguard.scanner.ast_scanner import (
    ASTScanner,
    CombinedScanner,
    create_combined_scanner,
)
from zzguard.scanner.semgrep_scanner import (
    SemgrepScanner,
    MultiScanner,
)

__all__ = [
    # Interface
    "ScannerInterface",
    # Implementations
    "RegexScanner",
    "ASTScanner",
    "SemgrepScanner",
    # Combined scanners
    "CombinedScanner",
    "MultiScanner",
    "create_combined_scanner",
    # Analyzer
    "Analyzer",
    "get_scanner",
]
