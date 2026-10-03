from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "custom_components" / "xiaomi_s400_local"


def _read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _translation_paths(
    value: dict, prefix: tuple[str, ...] = ()
) -> set[tuple[str, ...]]:
    paths: set[tuple[str, ...]] = set()
    for key, child in value.items():
        path = (*prefix, key)
        if isinstance(child, dict):
            paths.update(_translation_paths(child, path))
        else:
            paths.add(path)
    return paths


def test_hacs_and_manifest_structure() -> None:
    hacs = _read_json(ROOT / "hacs.json")
    manifest = _read_json(INTEGRATION / "manifest.json")

    assert hacs["name"] == manifest["name"]
    assert manifest["domain"] == INTEGRATION.name
    assert manifest["config_flow"] is True
    assert manifest["version"]
    assert manifest["codeowners"]
    assert (INTEGRATION / "config_flow.py").is_file()
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)
    assert manifest["version"] == project["project"]["version"]


def test_translation_shapes_match_strings() -> None:
    strings = _read_json(INTEGRATION / "strings.json")
    for language in ("en", "pl"):
        translation = _read_json(INTEGRATION / "translations" / f"{language}.json")
        assert _translation_paths(translation) == _translation_paths(strings)


def test_repair_translations_belong_to_issue() -> None:
    for file in (
        INTEGRATION / "strings.json",
        INTEGRATION / "translations" / "en.json",
        INTEGRATION / "translations" / "pl.json",
    ):
        strings = _read_json(file)
        assert "fix_flow" not in strings
        repair = strings["issues"]["invalid_bindkey"]
        assert "description" not in repair
        assert "fix_flow" in repair
