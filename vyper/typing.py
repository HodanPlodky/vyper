from typing import (
    Dict,
    Optional,
    Sequence,
    Tuple,
    Union,
)

# Parser
ClassTypes = Dict[str, str]
ParserPosition = Tuple[int, int]

# Compiler
ContractPath = str
SourceCode = str
ContractCodes = Dict[ContractPath, SourceCode]
OutputFormats = Sequence[str]
OutputDict = Dict[ContractPath, OutputFormats]

# Interfaces
InterfaceAsName = str
InterfaceImportPath = str
InterfaceImports = Dict[InterfaceAsName, InterfaceImportPath]
InterfaceDict = Dict[ContractPath, InterfaceImports]

# Opcodes
OpcodeValue = Tuple[Optional[int], int, int, Union[int, Tuple]]
OpcodeMap = Dict[str, OpcodeValue]
OpcodeRulesetValue = Tuple[Optional[int], int, int, int]
OpcodeRulesetMap = Dict[str, OpcodeRulesetValue]
