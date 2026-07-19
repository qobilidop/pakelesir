from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

CATEGORY_ACCEPT: Category
CATEGORY_REJECT: Category
CATEGORY_TRUNCATION: Category
CATEGORY_UNSPECIFIED: Category
DESCRIPTOR: _descriptor.FileDescriptor

class Accepted(_message.Message):
    __slots__ = ["headers"]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    headers: _containers.RepeatedCompositeFieldContainer[ExpectedHeader]
    def __init__(self, headers: _Optional[_Iterable[_Union[ExpectedHeader, _Mapping]]] = ...) -> None: ...

class BitString(_message.Message):
    __slots__ = ["bit_len", "data_hex"]
    BIT_LEN_FIELD_NUMBER: _ClassVar[int]
    DATA_HEX_FIELD_NUMBER: _ClassVar[int]
    bit_len: int
    data_hex: str
    def __init__(self, data_hex: _Optional[str] = ..., bit_len: _Optional[int] = ...) -> None: ...

class Expected(_message.Message):
    __slots__ = ["accept", "reject"]
    ACCEPT_FIELD_NUMBER: _ClassVar[int]
    REJECT_FIELD_NUMBER: _ClassVar[int]
    accept: Accepted
    reject: Rejected
    def __init__(self, accept: _Optional[_Union[Accepted, _Mapping]] = ..., reject: _Optional[_Union[Rejected, _Mapping]] = ...) -> None: ...

class ExpectedField(_message.Message):
    __slots__ = ["bytes_hex", "name", "uint"]
    BYTES_HEX_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    UINT_FIELD_NUMBER: _ClassVar[int]
    bytes_hex: str
    name: str
    uint: int
    def __init__(self, name: _Optional[str] = ..., uint: _Optional[int] = ..., bytes_hex: _Optional[str] = ...) -> None: ...

class ExpectedHeader(_message.Message):
    __slots__ = ["fields", "instance"]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_FIELD_NUMBER: _ClassVar[int]
    fields: _containers.RepeatedCompositeFieldContainer[ExpectedField]
    instance: str
    def __init__(self, instance: _Optional[str] = ..., fields: _Optional[_Iterable[_Union[ExpectedField, _Mapping]]] = ...) -> None: ...

class Rejected(_message.Message):
    __slots__ = ["reason"]
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: str
    def __init__(self, reason: _Optional[str] = ...) -> None: ...

class TestSuite(_message.Message):
    __slots__ = ["ir_version", "parser_name", "vectors"]
    IR_VERSION_FIELD_NUMBER: _ClassVar[int]
    PARSER_NAME_FIELD_NUMBER: _ClassVar[int]
    VECTORS_FIELD_NUMBER: _ClassVar[int]
    ir_version: str
    parser_name: str
    vectors: _containers.RepeatedCompositeFieldContainer[TestVector]
    def __init__(self, parser_name: _Optional[str] = ..., ir_version: _Optional[str] = ..., vectors: _Optional[_Iterable[_Union[TestVector, _Mapping]]] = ...) -> None: ...

class TestVector(_message.Message):
    __slots__ = ["category", "expected", "id", "packet"]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    PACKET_FIELD_NUMBER: _ClassVar[int]
    category: Category
    expected: Expected
    id: str
    packet: BitString
    def __init__(self, id: _Optional[str] = ..., category: _Optional[_Union[Category, str]] = ..., packet: _Optional[_Union[BitString, _Mapping]] = ..., expected: _Optional[_Union[Expected, _Mapping]] = ...) -> None: ...

class Category(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
