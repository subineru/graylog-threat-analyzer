import sys
from pathlib import Path

# Ensure project root is on sys.path so `from src.xxx import ...` works in tests
sys.path.insert(0, str(Path(__file__).parent.parent))
