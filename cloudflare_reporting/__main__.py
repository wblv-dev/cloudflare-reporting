"""Entry point for python -m cloudflare_reporting."""

import sys

from cloudflare_reporting.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
