# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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

import xml.etree.ElementTree as ET

from typing import Optional, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionSignature import FunctionSignature


class ModelsType:

    def __init__(
            self,
            signature: "FunctionSignature",
            xnode: Optional[ET.Element] = None) -> None:
        self._signature = signature
        self._xnode = xnode

    @property
    def function_signature(self) -> "FunctionSignature":
        return self._signature

    @property
    def xnode(self) -> ET.Element:
        if self._xnode is not None:
            return self._xnode
        raise UF.CHBError("Modelstype does not have an xml node")

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
    def kind(self) -> str:
        return "abstract"

    @property
    def is_string(self) -> bool:
        return False

    @property
    def name(self) -> str:
        raise UF.CHBError(
            "Method name only applicable to named type, not to "
            + self.kind)


def mk_type(signature: "FunctionSignature", xnode: ET.Element) -> ModelsType:
    xptr = xnode.find("ptr")
    if xptr is not None:
        return MPointerType(signature, xptr)
    xtext = xnode.text
    if xtext is not None:
        return MNamedType(signature, xnode)
    if xnode.tag == "btype":
        tname = xnode.get("tname")
        if tname is not None:
            return MNamedType(signature, typename="int")
    raise UF.CHBError(
        "Type with tag "
        + xnode.tag
        + " not recognized in function summary for "
        + signature.name)


class MNamedType(ModelsType):

    def __init__(
            self,
            signature: "FunctionSignature",
            xnode: Optional[ET.Element] = None,
            typename: Optional[str] = None) -> None:
        ModelsType.__init__(self, signature, xnode)
        self._typename = typename

    @property
    def is_named_type(self) -> bool:
        return True

    @property
    def kind(self) -> str:
        return "named type"

    @property
    def typename(self) -> str:
        if self._typename is None:
            xty = self.xnode.text
            if xty:
                self._typename = xty
            else:
                raise UF.CHBError(
                    "Named type in function signature for "
                    + self.function_signature.name
                    + " does not have a name")
        return self._typename

    @property
    def is_string(self) -> bool:
        return self.typename in [
            "LPCTSTR", "LPCSTR", "LPCWSTR"]

    def __str__(self) -> str:
        return self.typename


class MPointerType(ModelsType):

    def __init__(
            self,
            signature: "FunctionSignature",
            xnode: Optional[ET.Element] = None,
            pointsto: Optional[ModelsType] = None) -> None:
        ModelsType.__init__(self, signature, xnode)
        self._pointsto = pointsto

    @property
    def is_pointer_type(self) -> bool:
        return True

    @property
    def pointsto(self) -> ModelsType:
        if self._pointsto is None:
            self._pointsto = mk_type(self.function_signature, self.xnode)
        return self._pointsto

    @property
    def kind(self) -> str:
        return "pointer type"

    def __str__(self) -> str:
        return str(self.pointsto) + " *"
