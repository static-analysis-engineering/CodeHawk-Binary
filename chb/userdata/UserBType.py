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

from typing import Any, Dict, List

import chb.util.fileutil as UF


class UserBType:

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

    def to_xml(self, node: ET.Element) -> None:
        raise UF.CHBError("No implementation for to_xml: " + str(self))

    def __str__(self) -> str:
        return "btype"


class UserNamedBType(UserBType):

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

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

    def to_xml(self, node: ET.Element) -> None:
        ptrnode = ET.Element("ptr")
        node.append(ptrnode)
        self.target_type.to_xml(ptrnode)

    def __str__(self) -> str:
        return "*" + str(self.target_type)


class UserArrayBType(UserBType):

    def __init__(self, tgt: UserBType, num_elements) -> None:
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
            offset: int) -> None:
        self._name = name
        self._btype = btype
        self._offset = offset
