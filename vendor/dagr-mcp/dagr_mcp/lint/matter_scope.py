from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class MatterScopeRule:
    rule_id: str
    severity: str
    phrase: str
    canonical_replacement: str | None = None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class MatterScopeProfile:
    banned_phrase: tuple[MatterScopeRule, ...] = ()
    canonical_figure_lock_forbidden: tuple[MatterScopeRule, ...] = ()
    canonical_figure_lock_allowed: tuple[MatterScopeRule, ...] = ()
    exhibit_tag_format_pattern: str | None = None
    exhibit_tag_format_severity: str = "warning"
    exhibit_tag_format_note: str | None = None
    cross_filing_scope: Mapping[str, Any] | None = None
    phase_marker: Mapping[str, Any] | None = None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _rule_from_mapping(default_rule_id: str, default_severity: str, raw: Any) -> MatterScopeRule | None:
    if not isinstance(raw, Mapping):
        return None
    phrase = str(raw.get("phrase") or raw.get("match") or "").strip()
    if not phrase:
        return None
    rule_id = str(raw.get("rule_id") or default_rule_id).strip() or default_rule_id
    severity = str(raw.get("severity") or default_severity).strip().lower() or default_severity
    replacement_raw = raw.get("canonical_replacement")
    note_raw = raw.get("note")
    replacement = str(replacement_raw).strip() if replacement_raw is not None else None
    note = str(note_raw).strip() if note_raw is not None else None
    return MatterScopeRule(
        rule_id=rule_id,
        severity=severity,
        phrase=phrase,
        canonical_replacement=replacement or None,
        note=note or None,
    )


def matter_scope_profile_from_profile(profile: Mapping[str, Any]) -> MatterScopeProfile:
    scope = _as_mapping(profile.get("matter_scope"))

    banned_rules: list[MatterScopeRule] = []
    for item in _as_sequence(scope.get("banned_phrase")):
        rule = _rule_from_mapping("MS.banned_phrase", "error", item)
        if rule is not None:
            banned_rules.append(rule)

    figure_lock = _as_mapping(scope.get("canonical_figure_lock"))
    forbidden_rules: list[MatterScopeRule] = []
    for item in _as_sequence(figure_lock.get("forbidden_near_misses")):
        rule = _rule_from_mapping("MS.canonical_figure_lock", "error", item)
        if rule is not None:
            forbidden_rules.append(rule)

    allowed_rules: list[MatterScopeRule] = []
    for item in _as_sequence(figure_lock.get("allowed_alternates")):
        rule = _rule_from_mapping("MS.canonical_figure_lock", "warning", item)
        if rule is not None:
            allowed_rules.append(rule)

    exhibit = _as_mapping(scope.get("exhibit_tag_format"))
    pattern = str(exhibit.get("tag_pattern") or exhibit.get("pattern") or "").strip() or None
    severity = str(exhibit.get("severity") or "warning").strip().lower() or "warning"
    note_raw = exhibit.get("note")
    note = str(note_raw).strip() if note_raw is not None else None

    cross_filing_scope = _as_mapping(scope.get("cross_filing_scope")) or None
    phase_marker = _as_mapping(scope.get("phase_marker")) or None

    return MatterScopeProfile(
        banned_phrase=tuple(banned_rules),
        canonical_figure_lock_forbidden=tuple(forbidden_rules),
        canonical_figure_lock_allowed=tuple(allowed_rules),
        exhibit_tag_format_pattern=pattern,
        exhibit_tag_format_severity=severity,
        exhibit_tag_format_note=note or None,
        cross_filing_scope=cross_filing_scope,
        phase_marker=phase_marker,
    )


def _paragraph_index_for_line(line_number: int, paragraph_starts: Sequence[int]) -> int | None:
    if line_number < 1:
        return None
    current = None
    for idx, start in enumerate(paragraph_starts, start=1):
        if line_number >= start:
            current = idx
        else:
            break
    return current


def _paragraph_starts(text: str) -> list[int]:
    starts: list[int] = []
    in_paragraph = False
    for i, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            if not in_paragraph:
                starts.append(i)
            in_paragraph = True
        else:
            in_paragraph = False
    return starts


def _finding(
    *,
    rule: MatterScopeRule,
    matched_text: str,
    line_number: int,
    paragraph_number: int | None,
    description: str,
) -> dict[str, Any]:
    locator: dict[str, Any] = {"line": line_number}
    if paragraph_number is not None:
        locator["paragraph"] = paragraph_number
    out: dict[str, Any] = {
        "rule_id": rule.rule_id,
        "rule_family": "MS",
        "severity": rule.severity,
        "matched_text": matched_text,
        "locator": locator,
        "rule": rule.rule_id,
        "object_ref": f"line:{line_number}",
        "description": description,
        "suggested_action": rule.note or "Apply the configured matter-scope canonical form.",
    }
    if rule.canonical_replacement:
        out["canonical_replacement"] = rule.canonical_replacement
    if rule.note:
        out["note"] = rule.note
    return out


def lint_matter_scope_text(
    *,
    text: str,
    matter_scope_profile: MatterScopeProfile,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = text.splitlines()
    paragraph_starts = _paragraph_starts(text)

    for i, line in enumerate(lines, start=1):
        para = _paragraph_index_for_line(i, paragraph_starts)
        for rule in matter_scope_profile.banned_phrase:
            if rule.phrase.lower() in line.lower():
                findings.append(
                    _finding(
                        rule=rule,
                        matched_text=rule.phrase,
                        line_number=i,
                        paragraph_number=para,
                        description=f"Banned matter-scope phrase detected: '{rule.phrase}'.",
                    )
                )
        for rule in matter_scope_profile.canonical_figure_lock_forbidden:
            if rule.phrase.lower() in line.lower():
                findings.append(
                    _finding(
                        rule=rule,
                        matched_text=rule.phrase,
                        line_number=i,
                        paragraph_number=para,
                        description=f"Forbidden canonical figure near-miss detected: '{rule.phrase}'.",
                    )
                )
        for rule in matter_scope_profile.canonical_figure_lock_allowed:
            if rule.phrase.lower() in line.lower():
                findings.append(
                    _finding(
                        rule=rule,
                        matched_text=rule.phrase,
                        line_number=i,
                        paragraph_number=para,
                        description=f"Configured alternate figure label detected: '{rule.phrase}'.",
                    )
                )

    if matter_scope_profile.exhibit_tag_format_pattern:
        try:
            pattern = re.compile(matter_scope_profile.exhibit_tag_format_pattern)
        except re.error:
            pattern = None
        if pattern is not None:
            tag_rule = MatterScopeRule(
                rule_id="MS.exhibit_tag_format",
                severity=matter_scope_profile.exhibit_tag_format_severity,
                phrase="Exhibit",
                canonical_replacement=None,
                note=matter_scope_profile.exhibit_tag_format_note,
            )
            for i, line in enumerate(lines, start=1):
                para = _paragraph_index_for_line(i, paragraph_starts)
                for match in re.finditer(r"\bExhibit\s+([A-Za-z0-9.\-]+)\b", line):
                    tag = str(match.group(1) or "")
                    if not pattern.fullmatch(tag):
                        findings.append(
                            _finding(
                                rule=tag_rule,
                                matched_text=f"Exhibit {tag}",
                                line_number=i,
                                paragraph_number=para,
                                description=f"Exhibit tag does not match configured format: '{tag}'.",
                            )
                        )

    return findings


def lint_matter_scope_authoring_version_text(
    authoring_draft_version: Mapping[str, Any],
    *,
    matter_scope_profile: MatterScopeProfile,
) -> list[dict[str, Any]]:
    text = str(
        authoring_draft_version.get("draft_text")
        or authoring_draft_version.get("draft_content")
        or authoring_draft_version.get("module_text")
        or ""
    )
    return lint_matter_scope_text(text=text, matter_scope_profile=matter_scope_profile)

