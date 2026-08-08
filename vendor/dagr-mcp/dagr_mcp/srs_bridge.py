"""Bridge between the synchronous harness and signed SRS admission receipts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .srs_receipts import ReceiptContext, SignedReceiptEmitter, fastmcp_tool_result_digest


@dataclass(frozen=True, slots=True)
class BridgeConfig:
    runtime_instance_id: str
    boundary_id: str
    policy_pack_id: str
    policy_pack_version: str
    binding_version: str = "direct-harness.v0.1"
    parent_receipt_ref: str | None = None


class HarnessSRSBridge:
    def __init__(self, *, emitter: SignedReceiptEmitter, config: BridgeConfig):
        self.emitter = emitter
        self.config = config

    def _context(
        self,
        harness_context: Any,
        *,
        binding_version: str | None = None,
        parent_receipt_ref: str | None = None,
    ) -> ReceiptContext:
        logical = harness_context.request_ref or f"call-{uuid.uuid4()}"
        # The subject reference is obtained at exactly one of three branches
        # here, and each declares its own origin. The bridge takes no operator
        # subject or correlation override, so the `supplied_subject` and
        # `derived_from_supplied_correlation` classes do not arise on this path.
        if harness_context.session_ref:
            subject = harness_context.session_ref
            subject_ref_origin = "derived_from_session"
        elif harness_context.request_ref:
            subject = harness_context.request_ref
            subject_ref_origin = "derived_from_request"
        else:
            # Neither reference exists, so `logical` above is the uuid4 this
            # bridge just minted and the subject is built from it.
            subject = f"tool-call:{logical}"
            subject_ref_origin = "binding_minted"
        return ReceiptContext(
            runtime_instance_id=self.config.runtime_instance_id,
            boundary_id=self.config.boundary_id,
            policy_pack_id=self.config.policy_pack_id,
            policy_pack_version=self.config.policy_pack_version,
            subject_ref=subject,
            subject_ref_origin=subject_ref_origin,
            logical_call_id=logical,
            actor_ref=harness_context.actor_ref,
            binding_version=(
                self.config.binding_version
                if binding_version is None
                else binding_version
            ),
            parent_receipt_ref=(
                self.config.parent_receipt_ref
                if parent_receipt_ref is None
                else parent_receipt_ref
            ),
        )

    def emit_admission(
        self,
        *,
        harness_context: Any,
        tool_name: str,
        disposition: str,
        review_object_ref: str | None = None,
        retry_contract: str | None = None,
        reason_code: str | None = None,
        additional_attestation_limits: Sequence[str] = (),
        binding_version: str | None = None,
        parent_receipt_ref: str | None = None,
    ) -> str:
        return self.emitter.emit_admission(
            context=self._context(
                harness_context,
                binding_version=binding_version,
                parent_receipt_ref=parent_receipt_ref,
            ),
            requested_tool_name=tool_name,
            argument_digest=harness_context.arguments_hash,
            disposition=disposition,
            review_object_ref=review_object_ref,
            retry_contract=retry_contract,
            reason_code=reason_code,
            additional_attestation_limits=additional_attestation_limits,
        )

    def emit_outcome(
        self,
        *,
        harness_context: Any,
        admission_receipt_ref: str,
        outcome: str,
        result_digest: str | None = None,
        result_value: Any | None = None,
        exception_class: str | None = None,
        additional_attestation_limits: Sequence[str] = (),
        binding_owned_fields: Mapping[str, bool] | None = None,
        binding_version: str | None = None,
        parent_receipt_ref: str | None = None,
    ) -> str:
        if result_digest is None and outcome in {"result_returned", "error_returned"}:
            result_digest = fastmcp_tool_result_digest(
                content=None, structured_content=result_value, meta=None,
                is_error=outcome == "error_returned")
        return self.emitter.emit_outcome(
            context=self._context(
                harness_context,
                binding_version=binding_version,
                parent_receipt_ref=parent_receipt_ref,
            ),
            admission_receipt_ref=admission_receipt_ref,
            outcome=outcome,
            result_digest=result_digest,
            exception_class=exception_class,
            additional_attestation_limits=additional_attestation_limits,
            binding_owned_fields=binding_owned_fields,
        )
