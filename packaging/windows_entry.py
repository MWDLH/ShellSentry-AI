"""Windows packaged application entry point."""

from shellsentry.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["serve", "--port", "8765"]))
