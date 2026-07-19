"""Vendored protoc-generated modules for the normative Pakeles schemas.

Regenerate inside the dev container (see py/README.md); a test guards
against drift from proto/.
"""

from pakeles._pb import ir_pb2, testvec_pb2

__all__ = ["ir_pb2", "testvec_pb2"]
