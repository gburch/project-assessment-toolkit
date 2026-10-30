"""Run the canonical PAT helper with this Python environment."""

import sys
from pathlib import Path


def main():
    source = Path(__file__).resolve().parents[4]
    if (source / "src" / "project_assess").is_dir():
        source = source / "src"
    elif source.name == "project_assess" and (source / "__init__.py").is_file():
        source = source.parent
    sys.path.insert(0, str(source))
    from project_assess.test_value.collectors import main as execute

    return execute()


if __name__ == "__main__":
    raise SystemExit(main())
