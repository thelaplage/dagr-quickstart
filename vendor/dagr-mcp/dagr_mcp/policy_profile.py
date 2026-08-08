from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

from dagr_mcp.lint.matter_scope import MatterScopeProfile, matter_scope_profile_from_profile

_HEALTH_CHECK_MODES = frozenset(
    {"startup", "per_operation", "scheduled", "explicit", "none_for_advisory"}
)
_FAILURE_BEHAVIORS = frozenset({"fail_closed", "degraded", "pending", "advisory"})


class PolicyProfileError(ValueError):
    """Raised when profile projection cannot parse known posture fields."""


@dataclass(frozen=True, slots=True)
class SinkRequirements:
    event_sink_required: bool = False
    receipt_sink_required: bool = False
    artifact_sink_required: bool = False
    review_object_sink_required: bool = False
    lint_finding_sink_required: bool = False
    health_check_mode: str = "explicit"
    required_sink_failure_behavior: str = "fail_closed"

    def requires_event_sink(self) -> bool:
        return self.event_sink_required

    def requires_receipt_sink(self) -> bool:
        return self.receipt_sink_required

    def requires_review_object_sink(self) -> bool:
        return self.review_object_sink_required


@dataclass(frozen=True, slots=True)
class HarnessPolicyProjection:
    tool_policy_group: str | None = None
    read_write_class: str | None = None
    review_required: bool = False
    retention: str | None = None
    emit_receipt: bool = False
    required_receipt_variant: str | None = None
    gate_timeout_seconds: int | None = None
    sink_requirements: SinkRequirements = field(default_factory=SinkRequirements)


@dataclass(frozen=True, slots=True)
class PolicyProfileProjection:
    profile_id: str | None
    profile_version: str | None
    source_schema_version: str | None
    harness: HarnessPolicyProjection
    matter_scope: MatterScopeProfile = field(default_factory=MatterScopeProfile)
    warnings: tuple[str, ...] = ()


def project_policy_profile(profile: Mapping[str, Any]) -> PolicyProfileProjection:
    if not isinstance(profile, Mapping):
        raise PolicyProfileError("profile must be a mapping")

    warnings: list[str] = []
    harness_raw = profile.get("harness")
    if harness_raw is None:
        warnings.append("missing_harness_group")

    sinks, nested_over_top = _resolve_sink_requirements(profile)
    if nested_over_top:
        warnings.append("sink_requirements_nested_overrides_top_level")

    harness = _build_harness_projection(profile, sinks)

    return PolicyProfileProjection(
        profile_id=_meta_optional_str(profile, "profile_id"),
        profile_version=_meta_optional_str(profile, "profile_version"),
        source_schema_version=_meta_optional_str(profile, "schema_version"),
        harness=harness,
        matter_scope=matter_scope_profile_from_profile(profile),
        warnings=tuple(warnings),
    )


def load_policy_profile(path: str | Path) -> PolicyProfileProjection:
    raw_path = Path(path)
    try:
        text = raw_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyProfileError(f"cannot read profile path: {raw_path}") from exc

    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyProfileError(f"profile JSON is invalid: {raw_path}") from exc

    if not isinstance(decoded, Mapping):
        raise PolicyProfileError("profile JSON must decode to an object")

    return project_policy_profile(decoded)


def sink_requirements_from_profile(profile: Mapping[str, Any]) -> SinkRequirements:
    if not isinstance(profile, Mapping):
        raise PolicyProfileError("profile must be a mapping")
    sinks, _ = _resolve_sink_requirements(profile)
    return sinks


def harness_projection_from_profile(profile: Mapping[str, Any]) -> HarnessPolicyProjection:
    if not isinstance(profile, Mapping):
        raise PolicyProfileError("profile must be a mapping")
    sinks, _ = _resolve_sink_requirements(profile)
    return _build_harness_projection(profile, sinks)


def matter_scope_projection_from_profile(profile: Mapping[str, Any]) -> MatterScopeProfile:
    if not isinstance(profile, Mapping):
        raise PolicyProfileError("profile must be a mapping")
    return matter_scope_profile_from_profile(profile)


def _resolve_sink_requirements(
    profile: Mapping[str, Any],
) -> tuple[SinkRequirements, bool]:
    top_block = profile.get("sink_requirements")
    if top_block is not None and not isinstance(top_block, Mapping):
        raise PolicyProfileError("sink_requirements must be a mapping when present")

    harness_block = profile.get("harness")
    nested_block = None
    if isinstance(harness_block, Mapping):
        nested_block = harness_block.get("sink_requirements")
        if nested_block is not None and not isinstance(nested_block, Mapping):
            raise PolicyProfileError(
                "harness.sink_requirements must be a mapping when present"
            )

    merged = SinkRequirements()
    if isinstance(top_block, Mapping):
        merged = _parse_sink_requirements_mapping(top_block, merged)
    if isinstance(nested_block, Mapping):
        merged = _parse_sink_requirements_mapping(nested_block, merged)

    nested_over_top = isinstance(top_block, Mapping) and isinstance(nested_block, Mapping)
    return merged, nested_over_top


def _build_harness_projection(
    profile: Mapping[str, Any],
    sinks: SinkRequirements,
) -> HarnessPolicyProjection:
    raw = profile.get("harness")
    if raw is None:
        return HarnessPolicyProjection(sink_requirements=sinks)

    if not isinstance(raw, Mapping):
        raise PolicyProfileError("harness must be a mapping when present")

    tool_policy_group = (
        _optional_str(raw["tool_policy_group"])
        if "tool_policy_group" in raw
        else None
    )
    read_write_class = (
        _optional_str(raw["read_write_class"])
        if "read_write_class" in raw
        else None
    )
    retention = _optional_str(raw["retention"]) if "retention" in raw else None
    required_receipt_variant = (
        _optional_str(raw["required_receipt_variant"])
        if "required_receipt_variant" in raw
        else None
    )

    review_required = (
        _require_bool(raw["review_required"], "review_required")
        if "review_required" in raw
        else False
    )
    emit_receipt = (
        _require_bool(raw["emit_receipt"], "emit_receipt")
        if "emit_receipt" in raw
        else False
    )

    gate_timeout_seconds = None
    if "gate_timeout_seconds" in raw:
        gate_timeout_seconds = _parse_gate_timeout_seconds(
            raw.get("gate_timeout_seconds")
        )

    return HarnessPolicyProjection(
        tool_policy_group=tool_policy_group,
        read_write_class=read_write_class,
        review_required=review_required,
        retention=retention,
        emit_receipt=emit_receipt,
        required_receipt_variant=required_receipt_variant,
        gate_timeout_seconds=gate_timeout_seconds,
        sink_requirements=sinks,
    )


def _parse_sink_requirements_mapping(
    data: Mapping[str, Any],
    base: SinkRequirements,
) -> SinkRequirements:
    kwargs: dict[str, Any] = {}

    if "event_sink_required" in data:
        kwargs["event_sink_required"] = _require_bool(
            data["event_sink_required"], "event_sink_required"
        )
    if "receipt_sink_required" in data:
        kwargs["receipt_sink_required"] = _require_bool(
            data["receipt_sink_required"], "receipt_sink_required"
        )
    if "artifact_sink_required" in data:
        kwargs["artifact_sink_required"] = _require_bool(
            data["artifact_sink_required"], "artifact_sink_required"
        )
    if "review_object_sink_required" in data:
        kwargs["review_object_sink_required"] = _require_bool(
            data["review_object_sink_required"], "review_object_sink_required"
        )
    if "lint_finding_sink_required" in data:
        kwargs["lint_finding_sink_required"] = _require_bool(
            data["lint_finding_sink_required"], "lint_finding_sink_required"
        )

    if "health_check_mode" in data:
        mode = data["health_check_mode"]
        if not isinstance(mode, str):
            raise PolicyProfileError("health_check_mode must be a string")
        if mode not in _HEALTH_CHECK_MODES:
            raise PolicyProfileError(f"invalid health_check_mode: {mode!r}")
        kwargs["health_check_mode"] = mode

    if "required_sink_failure_behavior" in data:
        behavior = data["required_sink_failure_behavior"]
        if not isinstance(behavior, str):
            raise PolicyProfileError(
                "required_sink_failure_behavior must be a string"
            )
        if behavior not in _FAILURE_BEHAVIORS:
            raise PolicyProfileError(
                f"invalid required_sink_failure_behavior: {behavior!r}"
            )
        kwargs["required_sink_failure_behavior"] = behavior

    return replace(base, **kwargs) if kwargs else base


def _meta_optional_str(profile: Mapping[str, Any], key: str) -> str | None:
    if key not in profile:
        return None
    return _optional_str(profile[key])


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyProfileError(
            f"expected string or null, got {type(value).__name__}"
        )
    return value


def _require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyProfileError(f"{field_name} must be a boolean")
    return value


def _parse_gate_timeout_seconds(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyProfileError("gate_timeout_seconds must be a positive integer")
    if value < 1:
        raise PolicyProfileError("gate_timeout_seconds must be a positive integer")
    return value


__all__ = [
    "HarnessPolicyProjection",
    "PolicyProfileError",
    "PolicyProfileProjection",
    "SinkRequirements",
    "harness_projection_from_profile",
    "load_policy_profile",
    "matter_scope_projection_from_profile",
    "project_policy_profile",
    "sink_requirements_from_profile",
]
