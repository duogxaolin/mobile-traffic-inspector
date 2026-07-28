from pathlib import Path
import sys

state = Path("/var/lib/traffic-inspector/state/heartbeat")
if not state.exists():
    raise SystemExit(1)
if __import__("time").time() - state.stat().st_mtime > 45:
    raise SystemExit(1)
sys.exit(0)

