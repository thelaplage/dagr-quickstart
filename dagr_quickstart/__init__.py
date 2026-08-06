"""dagr-quickstart — the smallest governed action, end to end.

One read-classed tool is admitted; one write-classed tool is refused. Both cross
the real ``dagr-mcp`` DAGRMiddleware, which emits signed SRS receipts that
``arcs-verify`` recomputes as an independent subprocess. This is the minimal,
provider-neutral shape of a governed action — swap the two tool bodies for your
own and you have a governed integration that emits verifiable receipts.
"""

__all__ = ["run_governed_action"]

from .governed_action import run_governed_action
