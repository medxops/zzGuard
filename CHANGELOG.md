# Changelog

All notable changes to zzGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-12

### Added

#### Core Features
- **Bait Generator**: Create "poisoned" repositories with intentional security anti-patterns
  - 36 test cases covering Python, JavaScript, and Go
  - Automatic Git initialization with commit history
  - Prompt library in YAML format
  - Guardrail template generation

- **Scanner Module**: Detect canary patterns in AI-generated code
  - RegexScanner for fast canary token detection
  - ASTScanner for Python semantic analysis
  - SemgrepScanner for production-grade multi-language scanning
  - Git-based scanning for precise attribution to test IDs

- **Reporting**: Comprehensive metrics and reports
  - Canary Trigger Rate (CTR) with PARTIAL=0.5 weighting
  - Refusal rate as first-class metric
  - Per-CWE breakdown
  - JSON and SARIF output formats
  - Human-readable summary output

- **Human Test Protocol**: Guided manual testing workflow
  - Step-by-step prompt guidance
  - Auto-commit changes with test ID
  - Git diff scanning for accurate detection
  - Run manifest for reproducibility

- **Automation Module**: API-based testing
  - 5 AI providers: OpenAI, Anthropic, Ollama, Gemini, Mistral
  - Context injection simulating IDE behavior
  - A/B testing for guardrail comparison
  - Regression testing to track CTR over time

- **Capture Proxy**: mitmproxy-based IDE interception
  - Automatic assistant detection (Cursor, Copilot, Windsurf, Claude Code)
  - SQLite storage for captured responses
  - Export and statistics commands

#### CLI Commands
- `zzguard init` - Generate bait repository
- `zzguard test` - Run interactive test protocol
- `zzguard scan` - Scan AI responses for patterns
- `zzguard report` - Generate reports (JSON, SARIF, summary)
- `zzguard autotest` - Automated API-based testing
- `zzguard compare` - Compare baseline vs guardrailed runs
- `zzguard guardrails` - View/export guardrail templates
- `zzguard proxy` - Capture proxy management
- `zzguard clean` - Clean up generated files

#### Test Coverage
- 36 test cases across 3 languages
- Python: CWE-78, 79, 89, 94, 295, 319, 327, 328, 330, 338, 400, 502, 601, 611, 703, 776, 798, 918
- JavaScript: CWE-22, 78, 79, 89, 94, 295, 327, 798
- Go: CWE-22, 78, 89, 295, 327, 338, 502, 798

#### Guardrail Templates
- Cursor AI (`.cursorrules`)
- Claude Code (`CLAUDE.md`)
- GitHub Copilot (`.github/copilot-instructions.md`)
- Windsurf AI (`.windsurfrules`)

#### CI/CD
- GitHub Action for automated scanning
- CI workflow for testing and linting
- SARIF output for GitHub Code Scanning

### Technical Details

- **Python 3.10+** required
- **Pydantic v2** for data models and validation
- **Click** for CLI with environment variable support
- **Rich** for terminal output formatting
- Cross-platform support (Windows, Linux, macOS)
- 202 unit tests

---

[Unreleased]: https://github.com/medxops/zzguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/medxops/zzguard/releases/tag/v0.1.0
