from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

BIN_OP_KIND_ADD: BinOpKind
BIN_OP_KIND_AND: BinOpKind
BIN_OP_KIND_MUL: BinOpKind
BIN_OP_KIND_OR: BinOpKind
BIN_OP_KIND_SHL: BinOpKind
BIN_OP_KIND_SHR: BinOpKind
BIN_OP_KIND_SUB: BinOpKind
BIN_OP_KIND_UNSPECIFIED: BinOpKind
DESCRIPTOR: _descriptor.FileDescriptor
DISPLAY_FORMAT_BIN: DisplayFormat
DISPLAY_FORMAT_DEC: DisplayFormat
DISPLAY_FORMAT_ETHER: DisplayFormat
DISPLAY_FORMAT_HEX: DisplayFormat
DISPLAY_FORMAT_IPV4: DisplayFormat
DISPLAY_FORMAT_IPV6: DisplayFormat
DISPLAY_FORMAT_UNSPECIFIED: DisplayFormat

class Accept(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class BinOp(_message.Message):
    __slots__ = ["lhs", "op", "rhs"]
    LHS_FIELD_NUMBER: _ClassVar[int]
    OP_FIELD_NUMBER: _ClassVar[int]
    RHS_FIELD_NUMBER: _ClassVar[int]
    lhs: Expr
    op: BinOpKind
    rhs: Expr
    def __init__(self, op: _Optional[_Union[BinOpKind, str]] = ..., lhs: _Optional[_Union[Expr, _Mapping]] = ..., rhs: _Optional[_Union[Expr, _Mapping]] = ...) -> None: ...

class Display(_message.Message):
    __slots__ = ["doc", "format", "name", "value_labels"]
    DOC_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_LABELS_FIELD_NUMBER: _ClassVar[int]
    doc: str
    format: DisplayFormat
    name: str
    value_labels: _containers.RepeatedCompositeFieldContainer[ValueLabel]
    def __init__(self, name: _Optional[str] = ..., format: _Optional[_Union[DisplayFormat, str]] = ..., value_labels: _Optional[_Iterable[_Union[ValueLabel, _Mapping]]] = ..., doc: _Optional[str] = ...) -> None: ...

class Expr(_message.Message):
    __slots__ = ["bin", "constant", "field"]
    BIN_FIELD_NUMBER: _ClassVar[int]
    CONSTANT_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    bin: BinOp
    constant: int
    field: FieldRef
    def __init__(self, constant: _Optional[int] = ..., field: _Optional[_Union[FieldRef, _Mapping]] = ..., bin: _Optional[_Union[BinOp, _Mapping]] = ...) -> None: ...

class Extract(_message.Message):
    __slots__ = ["header_type", "instance"]
    HEADER_TYPE_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_FIELD_NUMBER: _ClassVar[int]
    header_type: str
    instance: str
    def __init__(self, header_type: _Optional[str] = ..., instance: _Optional[str] = ...) -> None: ...

class Field(_message.Message):
    __slots__ = ["annotations", "display", "name", "width"]
    class AnnotationsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    annotations: _containers.ScalarMap[str, str]
    display: Display
    name: str
    width: FieldWidth
    def __init__(self, name: _Optional[str] = ..., width: _Optional[_Union[FieldWidth, _Mapping]] = ..., display: _Optional[_Union[Display, _Mapping]] = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class FieldRef(_message.Message):
    __slots__ = ["field", "header"]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    field: str
    header: str
    def __init__(self, header: _Optional[str] = ..., field: _Optional[str] = ...) -> None: ...

class FieldWidth(_message.Message):
    __slots__ = ["bits", "byte_len"]
    BITS_FIELD_NUMBER: _ClassVar[int]
    BYTE_LEN_FIELD_NUMBER: _ClassVar[int]
    bits: int
    byte_len: Expr
    def __init__(self, bits: _Optional[int] = ..., byte_len: _Optional[_Union[Expr, _Mapping]] = ...) -> None: ...

class HeaderType(_message.Message):
    __slots__ = ["annotations", "fields", "name"]
    class AnnotationsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    annotations: _containers.ScalarMap[str, str]
    fields: _containers.RepeatedCompositeFieldContainer[Field]
    name: str
    def __init__(self, name: _Optional[str] = ..., fields: _Optional[_Iterable[_Union[Field, _Mapping]]] = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class Ir(_message.Message):
    __slots__ = ["ir_version", "parser"]
    IR_VERSION_FIELD_NUMBER: _ClassVar[int]
    PARSER_FIELD_NUMBER: _ClassVar[int]
    ir_version: str
    parser: Parser
    def __init__(self, ir_version: _Optional[str] = ..., parser: _Optional[_Union[Parser, _Mapping]] = ...) -> None: ...

class KeysetEntry(_message.Message):
    __slots__ = ["masked", "range", "value"]
    MASKED_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    masked: Masked
    range: Range
    value: int
    def __init__(self, value: _Optional[int] = ..., masked: _Optional[_Union[Masked, _Mapping]] = ..., range: _Optional[_Union[Range, _Mapping]] = ...) -> None: ...

class Masked(_message.Message):
    __slots__ = ["mask", "value"]
    MASK_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    mask: int
    value: int
    def __init__(self, value: _Optional[int] = ..., mask: _Optional[int] = ...) -> None: ...

class Parser(_message.Message):
    __slots__ = ["annotations", "header_types", "max_depth", "name", "start_state", "states"]
    class AnnotationsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    HEADER_TYPES_FIELD_NUMBER: _ClassVar[int]
    MAX_DEPTH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    START_STATE_FIELD_NUMBER: _ClassVar[int]
    STATES_FIELD_NUMBER: _ClassVar[int]
    annotations: _containers.ScalarMap[str, str]
    header_types: _containers.RepeatedCompositeFieldContainer[HeaderType]
    max_depth: int
    name: str
    start_state: str
    states: _containers.RepeatedCompositeFieldContainer[State]
    def __init__(self, name: _Optional[str] = ..., header_types: _Optional[_Iterable[_Union[HeaderType, _Mapping]]] = ..., states: _Optional[_Iterable[_Union[State, _Mapping]]] = ..., start_state: _Optional[str] = ..., max_depth: _Optional[int] = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class Range(_message.Message):
    __slots__ = ["hi", "lo"]
    HI_FIELD_NUMBER: _ClassVar[int]
    LO_FIELD_NUMBER: _ClassVar[int]
    hi: int
    lo: int
    def __init__(self, lo: _Optional[int] = ..., hi: _Optional[int] = ...) -> None: ...

class Reject(_message.Message):
    __slots__ = ["annotations", "reason"]
    class AnnotationsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    annotations: _containers.ScalarMap[str, str]
    reason: str
    def __init__(self, reason: _Optional[str] = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class Select(_message.Message):
    __slots__ = ["arms", "default_target", "keys"]
    ARMS_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TARGET_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    arms: _containers.RepeatedCompositeFieldContainer[SelectArm]
    default_target: Target
    keys: _containers.RepeatedCompositeFieldContainer[Expr]
    def __init__(self, keys: _Optional[_Iterable[_Union[Expr, _Mapping]]] = ..., arms: _Optional[_Iterable[_Union[SelectArm, _Mapping]]] = ..., default_target: _Optional[_Union[Target, _Mapping]] = ...) -> None: ...

class SelectArm(_message.Message):
    __slots__ = ["entries", "next"]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    NEXT_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[KeysetEntry]
    next: Target
    def __init__(self, entries: _Optional[_Iterable[_Union[KeysetEntry, _Mapping]]] = ..., next: _Optional[_Union[Target, _Mapping]] = ...) -> None: ...

class State(_message.Message):
    __slots__ = ["annotations", "extracts", "name", "transition"]
    class AnnotationsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    EXTRACTS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TRANSITION_FIELD_NUMBER: _ClassVar[int]
    annotations: _containers.ScalarMap[str, str]
    extracts: _containers.RepeatedCompositeFieldContainer[Extract]
    name: str
    transition: Transition
    def __init__(self, name: _Optional[str] = ..., extracts: _Optional[_Iterable[_Union[Extract, _Mapping]]] = ..., transition: _Optional[_Union[Transition, _Mapping]] = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class Target(_message.Message):
    __slots__ = ["accept", "reject", "state"]
    ACCEPT_FIELD_NUMBER: _ClassVar[int]
    REJECT_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    accept: Accept
    reject: Reject
    state: str
    def __init__(self, state: _Optional[str] = ..., accept: _Optional[_Union[Accept, _Mapping]] = ..., reject: _Optional[_Union[Reject, _Mapping]] = ...) -> None: ...

class Transition(_message.Message):
    __slots__ = ["direct", "select"]
    DIRECT_FIELD_NUMBER: _ClassVar[int]
    SELECT_FIELD_NUMBER: _ClassVar[int]
    direct: Target
    select: Select
    def __init__(self, direct: _Optional[_Union[Target, _Mapping]] = ..., select: _Optional[_Union[Select, _Mapping]] = ...) -> None: ...

class ValueLabel(_message.Message):
    __slots__ = ["label", "value"]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    label: str
    value: int
    def __init__(self, value: _Optional[int] = ..., label: _Optional[str] = ...) -> None: ...

class DisplayFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class BinOpKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
