"""Explicit optional analyzers, never project-discovered plugins or command runners."""

from __future__ import annotations

from types import MappingProxyType

from .vulture_analysis import analyze_vulture, vulture_info

_BUILTINS = MappingProxyType({"vulture": (vulture_info, analyze_vulture)})


def registered_analyzer_names():
    return tuple(sorted(_BUILTINS))


def validate_analyzers(names):
    if names is None:
        return ()
    if not isinstance(names, (list, tuple)) or any(not isinstance(name, str) for name in names):
        raise ValueError("Optional analyzers must be a list or tuple of registered names")
    if len(names) != len(set(names)) or set(names) - _BUILTINS.keys():
        raise ValueError("Optional analyzer names must be unique and registered")
    return tuple(sorted(names))


def list_analyzers():
    """Native collection remains automatic; this list contains opt-in providers only."""
    return [_BUILTINS[name][0]() for name in registered_analyzer_names()]


def run_analyzer(
    name,
    sources,
    *,
    snapshot=None,
    config=None,
    redact=None,
    analysis_profile="standard",
    deadline=None,
):
    if name not in _BUILTINS:
        raise ValueError("Unknown optional analyzer; choose a registered analyzer name")
    return _BUILTINS[name][1](
        sources,
        snapshot=snapshot,
        config=config,
        redact=redact,
        analysis_profile=analysis_profile,
        deadline=deadline,
    )
