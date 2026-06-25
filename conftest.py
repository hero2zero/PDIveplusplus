"""Pytest bootstrap.

Ensures the repository root is on sys.path so tests can `import lib.*`
regardless of how/where pytest is invoked. `lib` is a PEP 420 namespace
package (no __init__.py), so it only needs the repo root on the path.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
