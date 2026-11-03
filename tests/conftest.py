"""Keep the default offline suite independent of operator-installed external tools."""

import pytest


@pytest.fixture(autouse=True)
def isolated_joern_environment(monkeypatch):
    # Tests qualify synthetic runtimes explicitly. A developer's configured
    # Joern must not turn every small Deep fixture into a real JVM analysis.
    monkeypatch.delenv("PAT_JOERN_HOME", raising=False)
    monkeypatch.delenv("PAT_JOERN_JAVA_HOME", raising=False)
    monkeypatch.delenv("PAT_JOERN_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("PAT_JOERN_HEAP_GIB", raising=False)
