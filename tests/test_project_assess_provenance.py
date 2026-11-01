from project_assess import provenance


def test_source_and_wheel_layouts_attest_the_same_skill_code(tmp_path, monkeypatch):
    source = tmp_path / "checkout/src/project_assess"
    installed = tmp_path / "installed/site-packages/project_assess"
    locations = [
        (source, tmp_path / "checkout/.agents/skills"),
        (installed, installed / ".agents/skills"),
    ]
    for package, skills in locations:
        package.mkdir(parents=True)
        (package / "provenance.py").write_text("# Same package bytes\n")
        (skills / "sample/scripts").mkdir(parents=True)
        (skills / "sample/SKILL.md").write_text("# Guidance\n")
        (skills / "sample/scripts/check.py").write_text("raise RuntimeError('never execute')\n")

    def info(package):
        monkeypatch.setattr(provenance, "__file__", str(package / "provenance.py"))
        return provenance.tool_info()

    original = info(source)
    assert original["code_digest"] == info(installed)["code_digest"]
    assert len(original["available_instructions"]) == 1
    (locations[0][1] / "sample/scripts/check.py").write_text("# Changed executable resource\n")
    assert info(source)["code_digest"] != info(installed)["code_digest"]
