"""Display-format constants (aliases of the IR's DisplayFormat enum)."""

from pakeles._pb import ir_pb2

DEC = ir_pb2.DISPLAY_FORMAT_DEC
HEX = ir_pb2.DISPLAY_FORMAT_HEX
BIN = ir_pb2.DISPLAY_FORMAT_BIN
IPV4 = ir_pb2.DISPLAY_FORMAT_IPV4
IPV6 = ir_pb2.DISPLAY_FORMAT_IPV6
ETHER = ir_pb2.DISPLAY_FORMAT_ETHER

__all__ = ["DEC", "HEX", "BIN", "IPV4", "IPV6", "ETHER"]
