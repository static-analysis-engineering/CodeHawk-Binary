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

from typing import cast, List, Sequence, TYPE_CHECKING

from chb.models.PEDataType import PEDataType
from chb.models.PEDataType import PEDataBType
from chb.models.ParameterRole import ParameterRole

import chb.models.BTerm as B
import chb.models.FunctionPrecondition as P
import chb.models.ModelsType as M
import chb.models.ParameterRepresentation as Rep
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionSemantics import FunctionSemantics
    from chb.models.FunctionSignature import FunctionSignature
    from chb.models.FunctionSummary import FunctionSummary
    from chb.models.SummaryCollection import SummaryCollection


class FunctionParameter(object):

    def __init__(
            self, fsignature: "FunctionSignature", xnode: ET.Element) -> None:
        self._fsignature = fsignature
        self._xnode = xnode

    @property
    def summarycollection(self) -> "SummaryCollection":
        return self.signature.summarycollection

    @property
    def signature(self) -> "FunctionSignature":
        return self._fsignature

    @property
    def functionsummary(self) -> "FunctionSummary":
        return self.signature.functionsummary

    @property
    def functionsemantics(self) -> "FunctionSemantics":
        return self.functionsummary.semantics

    @property
    def xnode(self) -> ET.Element:
        return self._xnode

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname:
            return xname
        else:
            raise UF.CHBError(
                "Name not found for FunctionParameter "
                + "belonging to "
                + self.signature.name)

    @property
    def size(self) -> int:
        xsize = self.xnode.get("size", "4")
        return int(xsize)

    @property
    def location(self) -> str:
        xloc = self.xnode.get("loc")
        if xloc:
            return xloc
        else:
            raise UF.CHBError(
                "Location not found for FunctionParameter "
                + "belonging to "
                + self.signature.name)

    @property
    def mode(self) -> str:
        return self.xnode.get("io", "rw")

    @property
    def has_representation(self) -> bool:
        return not (self.xnode.find("rep") is None)

    @property
    def representation(self) -> Rep.ParameterRepresentation:
        xrep = self.xnode.find("rep")
        if xrep:
            return Rep.ParameterRepresentation(self, xrep)
        else:
            raise UF.CHBError(
                "FunctionParameter for "
                + self.signature.name
                + " does not have a representation")

    def represent_value(self, v: int) -> str:
        if self.has_representation:
            return self.representation.represent(v)
        else:
            return str(v)

    @property
    def type(self) -> M.ModelsType:
        xtype = self.xnode.find("type")
        if xtype is not None:
            try:
                return M.mk_type(self.signature, xtype)
            except UF.CHBError as e:
                raise UF.CHBError(
                    "Error in parameter " + self.name + ": " + str(e))
        else:
            xtype = self.xnode.find("btype")
            if xtype is not None:
                return M.mk_type(self.signature, xtype)
            else:
                raise UF.CHBError(
                    "Summary for "
                    + self.signature.name
                    + " does not have a type for parameter "
                    + self.name)

    @property
    def is_stack_parameter(self) -> bool:
        return "nr" in self.xnode.attrib

    @property
    def is_register_parameter(self) -> bool:
        return "reg" in self.xnode.attrib

    @property
    def stack_nr(self) -> int:
        if self.is_stack_parameter:
            xnr = self.xnode.get("nr")
            if xnr:
                return int(xnr)
            else:
                raise UF.CHBError(
                    "Stack parameter for "
                    + self.signature.name
                    + " does not have a number")
        else:
            raise UF.CHBError("Not a stack parameter: " + str(self))

    @property
    def register_name(self) -> str:
        if self.is_register_parameter:
            xreg = self.xnode.get("reg")
            if xreg:
                return xreg
            else:
                raise UF.CHBError(
                    "Register parameter for "
                    + self.signature.name
                    + "does not have a name")
        else:
            raise UF.CHBError("Not a register parameter: " + str(self))

    @property
    def preconditions(self) -> List[P.FunctionPrecondition]:
        precs = self.xnode.findall("pre")
        result: List[P.FunctionPrecondition] = []
        for pre in precs:
            if pre[0].tag == "deref-read-nt":
                ptype = self.type
                if ptype.is_pointer_type:
                    ptype = cast(M.MPointerType, ptype).pointsto
                    arg = B.BTermNamed(self.functionsemantics, "ci", name=self.name)
                    length = B.BTermNullTerminatorPos(
                        self.functionsemantics, "null-terminator-pos", ntstring=arg)
                    result.append(P.PreDerefRead(
                        self.functionsemantics,
                        "deref-read",
                        type=ptype,
                        source=arg,
                        length=length))
        return result

    def roles(self) -> Sequence[ParameterRole]:
        if "roles" in self.xnode.attrib:
            xrolesattr = self.xnode.get("roles")
            if xrolesattr:
                if xrolesattr == "none":
                    return []
                else:
                    raise UF.CHBError(
                        "Roles attribute not recognized: "
                        + str(xrolesattr))
            else:
                return []
        xroles = self.xnode.find('roles')
        if xroles:
            return [ParameterRole(self, r) for r in xroles.findall("role")]
        else:
            return []

    def __str__(self) -> str:
        ploc = ""
        if self.is_stack_parameter:
            ploc = " (stack: " + str(self.stack_nr) + ")"
        elif self.is_register_parameter:
            ploc = " (register: " + self.register_name + ")"
        return str(self.type) + " " + self.name + ploc
