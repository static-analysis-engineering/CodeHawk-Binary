# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.models.FunctionSignature


class ModelsType(ABC):

    def __init__(self,
                 signature: "chb.models.FunctionSignature.FunctionSignature",
                 xnode: ET.Element) -> None:
        self._signature = signature
        self.xnode = xnode

    @property
    def function_signature(self) -> "chb.models.FunctionSignature.FunctionSignature":
        return self._signature

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
    def name(self) -> str:
        raise UF.CHBError("Method name only applicable to named type, not to "
                          + self.kind)


def mk_type(signature: "chb.models.FunctionSignature.FunctionSignature",
            xnode: ET.Element) -> ModelsType:
    xptr = xnode.find("ptr")
    if xptr is not None:
        return MPointerType(signature, xptr)
    xtext = xnode.text
    if xtext is not None:
        return MNamedType(signature, xnode)
    raise UF.CHBError("Type with tag "
                      + xnode.tag
                      + " not recognized in function summary for "
                      + signature.name)


class MNamedType(ModelsType):

    def __init__(self,
                 signature: "chb.models.FunctionSignature.FunctionSignature",
                 xnode: ET.Element) -> None:
        ModelsType.__init__(self, signature, xnode)

    @property
    def is_named_type(self) -> bool:
        return True

    @property
    def kind(self) -> str:
        return "named type"

    @property
    def typename(self) -> str:
        xty = self.xnode.text
        if xty:
            return xty
        else:
            raise UF.CHBError("Named type in function signature for "
                              + self.function_signature.name
                              + " does not have a name")

    def __str__(self) -> str:
        return self.typename


class MPointerType(ModelsType):

    def __init__(
            self,
            signature: "chb.models.FunctionSignature.FunctionSignature",
            xnode: ET.Element) -> None:
        ModelsType.__init__(self, signature, xnode)

    @property
    def is_pointer_type(self) -> bool:
        return True

    @property
    def pointsto(self) -> ModelsType:
        return mk_type(self.function_signature, self.xnode)

    @property
    def kind(self) -> str:
        return "pointer type"

    def __str__(self) -> str:
        return str(self.pointsto) + " *"
