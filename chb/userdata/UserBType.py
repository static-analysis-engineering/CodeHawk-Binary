# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Representation of a type in json."""

import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import chb.util.fileutil as UF


class UserBTypeStore:

    def __init__(self, namedtypes: Dict[str, int]) -> None:
        self._basetypes: Dict[str, "UserBType"] = {}
        self._typedefs: Dict[str, "UserBType"] = {}
        self._initialize(namedtypes)

    def add_typedef(self, name: str, t: "UserBType") -> None:
        self._typedefs[name] = t

    def has_named_type(self, name: str) -> bool:
        return name in self._basetypes or name in self._typedefs

    def has_size_of(self, name: str) -> bool:
        if name in self._basetypes:
            return True
        else:
            return name in self._typedefs and self._typedefs[name].has_size()

    def size_of(self, name: str) -> int:
        if self.has_size_of(name):
            if name in self._basetypes:
                return self._basetypes[name].size
            else:
                return self._typedefs[name].size
        else:
            raise UF.CHBError("Size of named type: " + name + " not found")

    def _initialize(self, namedtypes: Dict[str, int]) -> None:
        for (name, size) in namedtypes.items():
            self._basetypes[name] = UserNamedBType(name, size=size)


class UserBType(ABC):

    def __init__(self) -> None:
        pass

    @property
    def is_named_type(self) -> bool:
        return False

    @property
    def is_pointer_type(self) -> bool:
        return False

    @property
    def is_array_type(self) -> bool:
        return False

    @property
    def is_struct_type(self) -> bool:
        return False

    @property
    @abstractmethod
    def size(self) -> int:
        ...

    def has_size(self) -> bool:
        return False

    def to_xml(self, node: ET.Element) -> None:
        raise UF.CHBError("No implementation for to_xml: " + str(self))

    def __str__(self) -> str:
        return "btype"


class UserNamedBType(UserBType):

    def __init__(self, name: str, size: Optional[int] = None) -> None:
        self._name = name
        self._size = size

    @property
    def name(self) -> str:
        return self._name

    def has_size(self) -> bool:
        return self._size is not None

    @property
    def size(self) -> int:
        if self._size is not None:
            return self._size
        else:
            raise UF.CHBError("Size not available for " + self.name)

    @property
    def is_named_type(self) -> bool:
        return True

    def to_xml(self, node: ET.Element) -> None:
        node.text = self.name

    def __str__(self) -> str:
        return self.name


class UserPointerBType(UserBType):

    def __init__(self, tgt: UserBType) -> None:
        self._tgt = tgt

    @property
    def target_type(self) -> UserBType:
        return self._tgt

    @property
    def is_pointer_type(self) -> bool:
        return True

    def has_size(self) -> bool:
        return True

    @property
    def size(self) -> int:
        return 4

    def to_xml(self, node: ET.Element) -> None:
        ptrnode = ET.Element("ptr")
        node.append(ptrnode)
        self.target_type.to_xml(ptrnode)

    def __str__(self) -> str:
        return "*" + str(self.target_type)


class UserArrayBType(UserBType):

    def __init__(self, tgt: UserBType, num_elements: int) -> None:
        self._tgt = tgt
        self._num_elements = num_elements

    @property
    def element_type(self) -> UserBType:
        return self._tgt

    @property
    def num_elements(self) -> int:
        return self._num_elements

    @property
    def is_array_type(self) -> bool:
        return True

    def has_size(self) -> bool:
        return self.element_type.has_size()

    @property
    def size(self) -> int:
        return self.element_type.size * self.num_elements

    def to_xml(self, node: ET.Element) -> None:
        anode = ET.Element("array")
        node.append(anode)
        self.element_type.to_xml(anode)
        anode.set("size", str(self.num_elements))

    def __str__(self) -> str:
        return str(self.element_type) + "[" + str(self.num_elements) + "]"


class UserStructBType(UserBType):

    def __init__(self, fields: List["UserStructBFieldInfo"]) -> None:
        self._fields = fields

    @property
    def fields(self) -> List["UserStructBFieldInfo"]:
        return self._fields

    @property
    def is_struct_type(self) -> bool:
        return True

    def has_size(self) -> bool:
        return True

    @property
    def size(self) -> int:
        return self.fields[-1].offset + self.fields[-1].size

    def to_xml(self, node: ET.Element) -> None:
        ffnode = ET.Element("fields")
        node.append(ffnode)
        for fld in self.fields:
            fnode = ET.Element("field")
            ffnode.append(fnode)
            fld.to_xml(fnode)

    def __str__(self) -> str:
        lines: List[str] = []
        for f in self.fields:
            lines.append(str(f))
        return "\n".join(lines)


class UserStructBFieldInfo:

    def __init__(
            self,
            name: str,
            btype: UserBType,
            offset: int,
            size: int) -> None:
        self._name = name
        self._btype = btype
        self._offset = offset
        self._size = size

    @property
    def name(self) -> str:
        return self._name

    @property
    def field_type(self) -> "UserBType":
        return self._btype

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> int:
        return self._size

    def to_xml(self, node: ET.Element) -> None:
        node.set("name", self.name)
        node.set("size", str(self.size))
        node.set("offset", str(self.offset))
        tnode = ET.Element("type")
        node.append(tnode)
        self.field_type.to_xml(tnode)

    def __str__(self) -> str:
        return str(self.offset).rjust(3) + "  " + self.name + ": " + str(self.field_type)
