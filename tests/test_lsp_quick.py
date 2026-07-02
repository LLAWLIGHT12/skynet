"""Quick LSP startup test."""
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Ensure jedi-language-server on PATH (Windows conda)
scripts = Path(sys.executable).parent / "Scripts"
if scripts.is_dir():
    os.environ["PATH"] = str(scripts) + os.pathsep + os.environ.get("PATH", "")


async def main():
    from multilspy import LanguageServer
    from multilspy.multilspy_config import MultilspyConfig
    from multilspy.multilspy_logger import MultilspyLogger

    fixture = ROOT / "tests" / "fixtures"
    cfg = MultilspyConfig.from_dict({"code_language": "python"})
    lsp = LanguageServer.create(cfg, MultilspyLogger(), str(fixture))
    print("created", type(lsp).__name__)
    try:
        async with asyncio.timeout(30):
            async with lsp.start_server():
                print("server started")
                locs = await lsp.request_definition("vuln_sample.py", 21, 4)
                print("defs", len(locs), locs[0].get("relativePath") if locs else None)
    except TimeoutError:
        print("TIMEOUT")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
