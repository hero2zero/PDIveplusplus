# PDIve++ Project Guidelines

## Project Overview
PDIve++ is an automated network reconnaissance and discovery tool designed for authorized security testing. It combines multiple discovery techniques (Amass, ping, port scanning, service enumeration) into a single workflow.

## Tech Stack
- **Language:** Python 3.9+
- **Core Libraries:** `argparse`, `ipaddress`, `logging`, `concurrent.futures`, `json`, `socket`
- **External Dependencies:** `requests`, `python-nmap`, `python-whois`, `colorama`
- **External Tools:** `amass`, `masscan`, `nmap`

## Coding Standards
- **Style:** Follow PEP 8 guidelines.
- **Typing:** Use type hints for all function signatures and variable declarations.
- **Documentation:** Use Google-style docstrings for all classes and functions.
- **Error Handling:** Use specific exception handling and logging instead of generic `try-except` blocks where possible.
- **Modularity:** Avoid large, monolithic files. Separate logic into cohesive modules.

## Architectural Patterns
- **CLI-First:** The primary interface is the command line.
- **Modular Design:** Functionality should be broken down into discovery, scanning, and reporting modules.
- **Asynchronous/Concurrent:** Utilize concurrency for network-bound tasks. Transitioning from threads to `asyncio` is a long-term goal.
- **Checkpointing:** Long-running scans should support checkpointing and resumption.

## Roadmap
### Phase 1: Modularization & Refactoring
- [ ] Break down `pdive++.py` into a proper Python package (`pdive/`).
- [ ] Add comprehensive type hints.
- [ ] Implement unit tests for core logic.

### Phase 2: Enhanced Functionality
- [ ] Add a configuration file (YAML/JSON) for persistent settings.
- [ ] Integrate additional scanning engines (e.g., ZMap, RustScan).
- [ ] Support for SOCKS/HTTP proxies.

### Phase 3: Reporting & UI
- [ ] Add HTML and PDF report generation.
- [ ] Improve console output with richer progress indicators.
- [ ] (Optional) Develop a simple web-based dashboard for scan results.

## Development Workflow
1. **Research:** Understand the target feature or bug.
2. **Strategy:** Plan the implementation, considering modularity and testing.
3. **Execution:** Implement changes, adhering to coding standards.
4. **Validation:** Run tests and verify the functionality.
