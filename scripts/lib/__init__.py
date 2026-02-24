# scripts/lib package
# Import resolution: each script adds its own directory to sys.path so this
# package is importable regardless of the working directory:
#
#   import sys
#   from pathlib import Path
#   sys.path.insert(0, str(Path(__file__).resolve().parent))
#   from lib.netbox_helpers import init, NetboxConfig, ...
