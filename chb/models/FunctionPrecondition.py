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

from chb.models.BTerm import BTerm, btermregistry
from chb.models.ModelsType import ModelsType, mk_type
    

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionSemantics import FunctionSemantics
    from chb.models.FunctionSignature import FunctionSignature
    from chb.models.FunctionSummary import FunctionSummary


class FunctionPrecondition:
    """Precondition on function arguments for call to be well-defined."""

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element]) -> None:
        self._fsem = fsem
        self._fsum = fsem.functionsummary
        self._tag = tag
        self._xnode = xnode

    @property
    def xnode(self) -> ET.Element:
        if self._xnode is not None:
            return self._xnode
        else:
            raise UF.CHBError("FunctionPrecondition does not have xnode")

    @property
    def semantics(self) -> "FunctionSemantics":
        return self._fsem

    @property
    def functionsummary(self) -> "FunctionSummary":
        return self._fsum

    @property
    def functionsignature(self) -> "FunctionSignature":
        return self.functionsummary.signature

    @property
    def tag(self) -> str:
        return self._tag

    @property
    def xterms(self) -> Sequence[ET.Element]:
        return self.xnode[1:]

    def xterm(self, index: int) -> ET.Element:
        if index < len(self.xterms):
            return self.xterms[index]
        else:
            raise UF.CHBError(
                "Term index out of bound: "
                + str(index)
                + ". Number of terms: "
                + str(len(self.xterms)))

    @property
    def is_deref_write(self) -> bool:
        return False

    @property
    def is_deref_read(self) -> bool:
        return False

    def refers_to_parameter(self, paramname: str) -> bool:
        return False

    def parameter_roles(self, paramname: str) -> List[str]:
        return []


FPdR = TypeVar("FPdR", bound=FunctionPrecondition, covariant=True)


class PreconditionRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[FunctionPrecondition]] = {}

    def register_tag(self, tag: str, anchor: type) -> Callable[[type], type]:
        def handler(t: type) -> type:
            self.register[(anchor, tag)] = t
            return t
        return handler

    def mk_instance(
            self,
            fsem: "FunctionSemantics",
            xnode: ET.Element,
            anchor: Type[FPdR]) -> FPdR:
        mnode = xnode.find("math")
        if mnode is None:
            raise UF.CHBError(
                "Xml node is not well-formed: math is missing")
        anode = mnode.find("apply")
        if anode is None:
            raise UF.CHBError(
                "Xml node is not well-formed: apply is missing")
        tagnode = anode[0]
        if tagnode is None:
            raise UF.CHBError(
                "Xml node is not well-formed: tag node is missing")
        tag = tagnode.tag
        if (anchor, tag) not in self.register:
            raise UF.CHBError(
                "Unknown precondition predicate type: " + tag)
        instance = self.register[(anchor, tag)](fsem, tag, anode)
        return cast(FPdR, instance)

preconditionregistry: PreconditionRegistry = PreconditionRegistry()


@preconditionregistry.register_tag("deref-read", FunctionPrecondition)
@preconditionregistry.register_tag("deref-read-null", FunctionPrecondition)
class PreDerefRead(FunctionPrecondition):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            type: Optional[ModelsType] = None,
            source: Optional[BTerm] = None,
            length: Optional[BTerm] = None) -> None:
        FunctionPrecondition.__init__(self, fsem, tag, xnode)
        self._type = type
        self._source = source
        self._length = length

    @property
    def type(self) -> ModelsType:
        if self._type is None:
            self._type = mk_type(self.functionsignature, self.xterm(0))
        return self._type

    @property
    def source(self) -> BTerm:
        if self._source is None:
            self._source = (
                btermregistry.mk_instance(self.semantics, self.xterm(1), BTerm))
        return self._source

    @property
    def length(self) -> BTerm:
        if self._length is None:
            self._length = (
                btermregistry.mk_instance(self.semantics, self.xterm(2), BTerm))
        return self._length

    @property
    def is_deref_read(self) -> bool:
        return True

    def refers_to_parameter(self, name: str) -> bool:
        return (
            self.source.refers_to_parameter(name)
            or self.length.refers_to_parameter(name))

    def parameter_roles(self, name: str) -> List[str]:
        result: List[str] = []
        if self.source.refers_to_parameter(name):
            termrefs = self.source.parameter_refs(name)
            for r in termrefs:
                result.append(self.tag + ":source" + r)
        if self.length.refers_to_parameter(name):
            termrefs = self.length.parameter_refs(name)
            for r in termrefs:
                result.append(self.tag + ":length" + r)
        return result

    def __str__(self) -> str:
        return (
            self.tag
            + "("
            + str(self.type)
            + ", "
            + str(self.source)
            + ", "
            + str(self.length)
            + ")")


@preconditionregistry.register_tag("deref-write", FunctionPrecondition)
@preconditionregistry.register_tag("deref-write-null", FunctionPrecondition)
class PreDerefWrite(FunctionPrecondition):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            type: Optional[ModelsType] = None,
            destination: Optional[BTerm] = None,
            length: Optional[BTerm] = None) -> None:
        FunctionPrecondition.__init__(self, fsem, tag, xnode)
        self._type = type
        self._destination = destination
        self._length = length

    @property
    def type(self) -> ModelsType:
        if self._type is None:
            self._type = mk_type(self.functionsignature, self.xterm(0))
        return self._type

    @property
    def destination(self) -> BTerm:
        if self._destination is None:
            self._destination = (
                btermregistry.mk_instance(self.semantics, self.xterm(1), BTerm))
        return self._destination

    @property
    def length(self) -> BTerm:
        if self._length is None:
            self._length = (
                btermregistry.mk_instance(self.semantics, self.xterm(2), BTerm))
        return self._length

    def refers_to_parameter(self, name: str) -> bool:
        return (
            self.destination.refers_to_parameter(name)
            or self.length.refers_to_parameter(name))

    def parameter_roles(self, name: str) -> List[str]:
        result: List[str] = []
        if self.destination.refers_to_parameter(name):
            termrefs = self.destination.parameter_refs(name)
            for r in termrefs:
                result.append(self.tag + ":destination" + r)
        if self.length.refers_to_parameter(name):
            termrefs = self.length.parameter_refs(name)
            for r in termrefs:
                result.append(self.tag + ":length" + r)
        return result

    @property
    def is_deref_write(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            self.tag
            + "("
            + str(self.type)
            + ", "
            + str(self.destination)
            + ", "
            + str(self.length)
            + ")")


@preconditionregistry.register_tag("geq", FunctionPrecondition)
@preconditionregistry.register_tag("gt", FunctionPrecondition)
class PreRelationalCondition(FunctionPrecondition):

    def __init__(
            self,
            fsem: "FunctionSemantics",
            tag: str,
            xnode: Optional[ET.Element] = None,
            arg1: Optional[BTerm] = None,
            arg2: Optional[BTerm] = None) -> None:
        FunctionPrecondition.__init__(self, fsem, tag, xnode)
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

    def parameter_roles(self, name: str) -> List[str]:
        result: List[str] = []
        if self.arg1.refers_to_parameter(name):
            result.append(self.tag + ":arg1")
        if self.arg2.refers_to_parameter(name):
            result.append(self.tag + ":arg2")
        return result

    def __str__(self) -> str:
        return (
            self.tag
            + "("
            + str(self.arg1)
            + ", "
            + str(self.arg2)
            + ")")
