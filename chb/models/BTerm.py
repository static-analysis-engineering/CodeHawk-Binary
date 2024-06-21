# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import (
    Callable,
    cast,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TYPE_CHECKING,
    TypeVar)

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionSemantics import FunctionSemantics
    from chb.models.FunctionSummary import FunctionSummary


class BTerm:
    """Term used in function summary pre-, postconditions, and sideeffects."""

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None) -> None:
        self._fsem = fsem
        self._fsum = fsem.functionsummary
        self._tag = tag
        self._xnode = xnode

    @property
    def xnode(self) -> ET.Element:
        if self._xnode is not None:
            return self._xnode
        else:
            raise UF.CHBError("BTerm does not have xml node")

    @property
    def tag(self) -> str:
        return self._tag

    @property
    def semantics(self) -> "FunctionSemantics":
        return self._fsem

    @property
    def is_arithmetic_expr(self) -> bool:
        return False

    @property
    def xterms(self) -> Sequence[ET.Element]:
        return self.xnode[1:]

    def xterm(self, index: int) -> ET.Element:
        if index < len(self.xterms):
            return self.xterms[index]
        else:
            raise UF.CHBError(
                "Term index of out of bound: "
                + str(index)
                + ". Number of terms: "
                + str(len(self.xterms)))

    def refers_to_parameter(self, name: str) -> bool:
        return False

    def parameter_refs(self, name) -> List[str]:
        return []


BTdR = TypeVar("BTdR", bound=BTerm, covariant=True)


class BTermRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[BTerm]] = {}

    def register_tag(self, tag: str, anchor: type) -> Callable[[type], type]:
        def handler(t: type) -> type:
            self.register[(anchor, tag)] = t
            return t
        return handler

    def mk_instance(
            self,
            fsem: "FunctionSemantics",
            xnode: ET.Element,
            anchor: Type[BTdR]) -> BTdR:
        tag = xnode.tag
        if tag == "apply":
            tagnode = xnode[0]
            if tagnode is None:
                raise UF.CHBError(
                    "Xml node is not well-formed: bterm apply tag node missing")
            tag = tagnode.tag
        if (anchor, tag) not in self.register:
            raise UF.CHBError("Unknown bterm type: " + tag)
        instance = self.register[(anchor, tag)](fsem, tag, xnode)
        return cast(BTdR, instance)


btermregistry: BTermRegistry = BTermRegistry()


@btermregistry.register_tag("runtime-value", BTerm)
class BTermRuntimeValue(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)

    def __str__(self):
        return self.tag


@btermregistry.register_tag("cn", BTerm)
class BTermConstant(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            constant: Optional[int] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)
        self._constant = constant

    @property
    def constant(self) -> int:
        if self._constant is None:
            txt = self.xnode.text
            if txt is not None:
                return int(txt)
            else:
                raise UF.CHBError("BTerm cn node without text")
        return self._constant

    def __str__(self) -> str:
        return "cn:" + str(self.constant)


@btermregistry.register_tag("ci", BTerm)
class BTermNamed(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            name: Optional[str] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)
        self._name = name

    @property
    def name(self) -> str:
        if self._name is None:
            txt = self.xnode.text
            if txt is not None:
                return txt
            else:
                raise UF.CHBError("BTerm ci node without text")
        return self._name

    def refers_to_parameter(self, name: str) -> bool:
        return self.name == name

    def parameter_refs(self, name: str) -> List[str]:
        if self.name == name:
            return [""]
        else:
            return []

    def __str__(self) -> str:
        return "ci:" + self.name


@btermregistry.register_tag("indexsize", BTerm)
class BTermIndexSize(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            arg: Optional[BTerm] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)
        self._arg = arg

    @property
    def arg(self) -> BTerm:
        if self._arg is None:
            self._arg = (
                btermregistry.mk_instance(self.semantics, self.xterm(0), BTerm))
        return self._arg

    def refers_to_parameter(self, name: str) -> bool:
        return self.arg.refers_to_parameter(name)

    def parameter_refs(self, name: str) -> List[str]:
        result: List[str] = []
        if self.arg.refers_to_parameter(name):
            termrefs = self.arg.parameter_refs(name)
            for r in termrefs:
                result.append(":" + self.tag + ":arg" + r)
        return result

    def __str__(self) -> str:
        return self.tag + "(" + str(self.arg) + ")"


@btermregistry.register_tag("addressed-value", BTerm)
class BTermAddressedValue(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            arg1: Optional[BTerm] = None,
            arg2: Optional[BTerm] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)
        self._arg1 = arg1
        self._arg2 = arg2

    @property
    def arg1(self) -> BTerm:
        if self._arg1 is None:
            self._arg1 = (
                btermregistry.mk_instance(self.semantics, self.xterm(0), BTerm))
        return self._arg1

    @property
    def arg2(self) -> BTerm:
        if self._arg2 is None:
            self._arg2 = (
                btermregistry.mk_instance(self.semantics, self.xterm(1), BTerm))
        return self._arg2

    def refers_to_parameter(self, name: str) -> bool:
        return (
            self.arg1.refers_to_parameter(name)
            or self.arg2.refers_to_parameter(name))

    def parameter_refs(self, name: str) -> List[str]:
        result: List[str] = []
        if self.arg1.refers_to_parameter(name):
            termrefs = self.arg1.parameter_refs(name)
            for r in termrefs:
                result.append(":" + self.tag + ":arg1" + r)
        if self.arg2.refers_to_parameter(name):
            termrefs = self.arg2.parameter_refs(name)
            for r in termrefs:
                result.append(":" + self.tag + ":arg2" + r)
        return result
    
    def __str__(self) -> str:
        return self.tag + "(" + str(self.arg1) + ", " + str(self.arg2) + ")"
    


@btermregistry.register_tag("null-terminator-pos", BTerm)
class BTermNullTerminatorPos(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            ntstring: Optional[BTerm] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)
        self._ntstring = ntstring

    @property
    def ntstring(self) -> BTerm:
        if self._ntstring is None:
            self._ntstring = (
                btermregistry.mk_instance(self.semantics, self.xterm(0), BTerm))
        return self._ntstring

    def refers_to_parameter(self, name: str) -> bool:
        return self.ntstring.refers_to_parameter(name)

    def parameter_refs(self, name: str) -> List[str]:
        result: List[str] = []
        if self.ntstring.refers_to_parameter(name):
            termrefs = self.ntstring.parameter_refs(name)
            for r in termrefs:
                result.append(":" + self.tag + ":ntstring" + r)
        return result

    def __str__(self) -> str:
        return "null-terminator-pos(" + str(self.ntstring) + ")"


@btermregistry.register_tag("plus", BTerm)    
@btermregistry.register_tag("times", BTerm)
class BTermArithmetic(BTerm):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            arg1: Optional[BTerm] = None,
            arg2: Optional[BTerm] = None) -> None:
        BTerm.__init__(self, fsem, tag, xnode)
        self._arg1 = arg1
        self._arg2 = arg2

    @property
    def operation(self) -> str:
        return self.tag

    @property
    def is_arithmetic_expr(self) -> bool:
        return True

    @property
    def arg1(self) -> BTerm:
        if self._arg1 is None:
            self._arg1 = (
                btermregistry.mk_instance(self.semantics, self.xterm(0), BTerm))
        return self._arg1

    @property
    def arg2(self) -> BTerm:
        if self._arg2 is None:
            self._arg2 = (
                btermregistry.mk_instance(
                    self.semantics, self.xterm(1), BTerm))
        return self._arg2

    def refers_to_parameter(self, name: str) -> bool:
        return (
            self.arg1.refers_to_parameter(name)
            or self.arg2.refers_to_parameter(name))

    def parameter_refs(self, name: str) -> List[str]:
        result: List[str] = []
        if self.arg1.refers_to_parameter(name):
            termrefs = self.arg1.parameter_refs(name)
            for r in termrefs:
                result.append(":" + self.tag + ":arg1" + r)
        if self.arg2.refers_to_parameter(name):
            termrefs = self.arg2.parameter_refs(name)
            for r in termrefs:
                result.append(":" + self.tag + ":arg2" + r)
        return result

    def __str__(self) -> str:
        return (
            self.tag + "(" + str(self.arg1) + ", " + str(self.arg2) + ")")
