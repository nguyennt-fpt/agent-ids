"""Offline tests: agent/ and benchmark/ modules import by bare name (as they do
inside their containers / scripts), so put both directories on sys.path."""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "agent"))
sys.path.insert(0, os.path.join(ROOT, "benchmark"))
