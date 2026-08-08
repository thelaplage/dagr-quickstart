"""Reader for the SRS envelope v0.2.1 ``subject_ref_origin`` field.

This module reads one optional field out of already-validated receipt bytes and
renders it for disclosure. It is deliberately tiny and deliberately incurious:

* It never infers an origin. ``subject_ref``, request identifiers, session
  identifiers, correlation shape, and emitter identity are all ignored; the
  only input that can produce a declared token is the declared token itself.
* It imports no emitter package. The verifier recomputes everything it reports
  from the receipt bytes it was handed.
* It renders absence as ``not_declared`` and nothing else. Absence means the
  field was not declared, full stop. It is not evidence of emitter vintage, of
  a v0.2.0-era producer, or of any supplied class.
* It refuses to launder a malformed present value into absence. A receipt that
  carries ``subject_ref_origin`` with a value outside the closed five-member
  vocabulary -- or with a non-string JSON type -- is invalid input, and reading
  it raises :class:`MalformedSubjectRefOrigin`.

``not_declared`` is a reader-and-report rendering. It is not a member of the
envelope enum, it never appears in the SRS envelope schema, and it is never an
emitted receipt value.
"""

from __future__ import annotations

from typing import Any, Final

#: The closed five-member vocabulary declared by SRS envelope v0.2.1. One
#: supplied class, three derived classes, one minted class.
DECLARED_ORIGINS: Final[tuple[str, ...]] = (
    "supplied_subject",
    "derived_from_session",
    "derived_from_request",
    "derived_from_supplied_correlation",
    "binding_minted",
)

#: The rendering for a genuinely absent field. Never an enum member, never an
#: emitted receipt value.
NOT_DECLARED: Final[str] = "not_declared"

#: Everything an origin disclosure field may carry: the five declared tokens
#: plus the absence rendering.
ORIGIN_DISCLOSURE_VALUES: Final[tuple[str, ...]] = DECLARED_ORIGINS + (
    NOT_DECLARED,
)

FIELD_NAME: Final[str] = "subject_ref_origin"


class MalformedSubjectRefOrigin(ValueError):
    """A present ``subject_ref_origin`` that is not a declared token.

    Raised rather than returning ``not_declared``: a malformed present value is
    invalid input, and collapsing it into absence would let an out-of-enum or
    wrong-typed value be reported as a clean, unremarkable non-declaration.
    """


def read_subject_ref_origin(receipt: dict[str, Any]) -> str:
    """Return the origin disclosure token for ``receipt``.

    ``receipt`` must be the validated receipt object. Returns one of the five
    declared tokens when the field is present and well formed, and
    :data:`NOT_DECLARED` when the field is genuinely absent.

    Raises :class:`MalformedSubjectRefOrigin` when the field is present but
    carries a value outside :data:`DECLARED_ORIGINS`, including a present
    ``null``, a non-string JSON type, or a string outside the vocabulary.
    """

    if FIELD_NAME not in receipt:
        return NOT_DECLARED

    value = receipt[FIELD_NAME]

    # bool is a subclass of int, not str, so a JSON true/false lands here too.
    if not isinstance(value, str) or value not in DECLARED_ORIGINS:
        raise MalformedSubjectRefOrigin(
            f"{FIELD_NAME} is present but not a declared origin: {value!r}"
        )

    return value


def is_declared_origin(value: Any) -> bool:
    """True only for the five declared tokens. ``not_declared`` is not one."""

    return isinstance(value, str) and value in DECLARED_ORIGINS
