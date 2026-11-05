"""
Command-line script: (re)create the WebShield database.

Usage (from the project root):
    python -m database.init_db
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config  # noqa: E402
from database.db import init_db  # noqa: E402

if __name__ == "__main__":
    init_db(Config.DATABASE)
    print(f"Database created at {Config.DATABASE}")
    print("Fictional demo account: demo_student / DemoPass123")
