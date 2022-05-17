# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------
"""A name bound to a unique location."""

from typing import cast, Dict, List, Optional, Set, TYPE_CHECKING, Union

import chb.ast.ASTNode as AST


class ASTIVarInfo:
    """Represents a name bound to a unique location.

    The location may be a register or a memory location, or possibly a flag.

    It may or may not have a unique type. Typically registers can have many
    different types within the span of a function.
    Types are updated as more precise types become available (meet of the
    new type with the old type), or multiple types are entered if updates
    with incompatible types are encountered (in this case the type could be
    considered to be bottom) and the vtype field itself is set to None.

    It may be a parameter of the function. The value of the parameter field
    is this index (zero-based) of the parameter as considered by the C function
    prototype (which may be different from the binary parameter index).

    The location may be in global memory with a known virtual address.

    The size (in bytes) of the location may or may not be known.

    This object is immutable.
    """

    def __init__(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            size: Optional[int] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            conflicting_types: List[AST.ASTTyp] = [],
            notes: Set[str] = set()) -> None:
        self._vname = vname
        self._size = size
        self._vtype = vtype
        self._parameter = parameter
        self._globaladdress = globaladdress
        self._conflicting_types = conflicting_types
        self._notes = notes

    @property
    def vname(self) -> str:
        return self._vname

    @property
    def vtype(self) -> Optional[AST.ASTTyp]:
        return self._vtype

    @property
    def size(self) -> Optional[int]:
        return self._size

    @property
    def conflicting_types(self) -> List[AST.ASTTyp]:
        return self._conflicting_types

    @property
    def notes(self) -> Set[str]:
        return self._notes

    def serialize(self) -> Dict[str, Union[int, str, List[str]]]:
        result: Dict[str, Union[int, str, List[str]]] = {}
        result["name"] = self.vname
        if self.vtype:
            result["type"] = str(self.vtype)
        if self.size:
            result["size"] = str(self.size)
        if self.is_parameter:
            result["parameter"] = self.parameter
        if self.global_address is not None:
            result["global-address"] = hex(self.global_address)
        if len(self.conflicting_types) > 0:
            result["multiple-types"] = [str(t) for t in self.conflicting_types]
        notes = self.notes
        if self.is_function:
            notes.add("function")
        if len(notes) > 0:
            result["notes"] = list(notes)
        return result

    @property
    def is_function(self) -> bool:
        if self.vtype:
            return self.vtype.is_function
        else:
            return False

    @property
    def returns_void(self) -> bool:
        if self.is_function:
            vtype = cast(AST.ASTTypFun, self.vtype)
            return vtype.returntyp.is_void
        else:
            return False

    @property
    def is_struct(self) -> bool:
        if self.vtype:
            return self.vtype.is_compound
        else:
            return False

    @property
    def is_global(self) -> bool:
        return self._globaladdress is not None

    @property
    def is_parameter(self) -> bool:
        return self._parameter is not None

    def has_global_address(self) -> bool:
        return self._globaladdress is not None

    @property
    def global_address(self) -> Optional[int]:
        return self._globaladdress

    @property
    def parameter(self) -> int:
        if self._parameter is not None:
            return self._parameter
        else:
            raise Exception("VarInfo " + self.vname + " is not a parameter")

    def to_c_like(self, sp: int = 0) -> str:
        if self.is_function:
            vty = cast(AST.ASTTypFun, self.vtype)
            return (
                str(vty.returntyp)
                + " "
                + self.vname
                + str(vty.argtypes))
        else:
            if self.vtype:
                return str(self.vtype) + " " + self.vname
            else:
                return self.vname

    def __str__(self) -> str:
        return self.vname
