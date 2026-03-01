from pathlib import Path
import runpy
import sys


ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / 'backend' / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from gntl.main import *  # noqa: F401,F403


if __name__ == '__main__':
    runpy.run_module('gntl.main', run_name='__main__')
