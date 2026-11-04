"""Fixed optional analyzers, never project-discovered plugins or arbitrary commands."""

from __future__ import annotations

from types import MappingProxyType

from .joern_analysis import analyze_joern, joern_info, joern_limits
from .vulture_analysis import analyze_vulture, vulture_info, vulture_limits

_BUILTINS = MappingProxyType(
    {"joern": (joern_info, analyze_joern), "vulture": (vulture_info, analyze_vulture)}
)
DEEP_ANALYZERS = ("joern", "vulture")
SELECTION_VERSION = "1"


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


def resolve_analyzers(names, analysis_profile):
    """Deep requests fixed trusted providers; unavailable tools stay explicit gaps."""
    requested = validate_analyzers(names)
    if analysis_profile not in {"standard", "deep"}:
        raise ValueError("Unknown analysis profile")
    return (
        tuple(sorted(set(requested) | set(DEEP_ANALYZERS)))
        if analysis_profile == "deep"
        else requested
    )


def list_analyzers():
    """Installation is optional; Deep requests these fixed providers automatically."""
    return [analyzer_info(name) for name in registered_analyzer_names()]


def analyzer_info(name):
    """Inspect one trusted provider without probing unrelated installations."""
    if name not in _BUILTINS:
        raise ValueError("Unknown optional analyzer")
    return {**_BUILTINS[name][0](), "default_profiles": ["deep"] if name in DEEP_ANALYZERS else []}


def dedicated_phase_limits(name, analysis_profile):
    """Required Deep work cannot consume documentation or another provider's budget."""
    if name == "joern":
        return joern_limits(analysis_profile)
    return (
        vulture_limits(analysis_profile)
        if name == "vulture" and analysis_profile == "deep"
        else None
    )


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
