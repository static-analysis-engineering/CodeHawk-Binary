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
"""A formal parameter to a function (C-source code perspective)."""

from typing import cast, List, Optional, Tuple, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.astinterface.ASTIUtil import get_arg_loc
from chb.astinterface.ASTIVarInfo import ASTIVarInfo

if TYPE_CHECKING:
    import chb.bctypes.BCTyp as BCT


class ASTIFormalVarInfo(ASTIVarInfo):
    """Represents a formal parameter of a function in C source view.

    The parameter index refers to the source view index (zero-based).
    The arglocs field holds the locations where the argument to the
    function are stored upon function entry. In most cases this will
    be a single location (register or stack). C, however, allows struct
    arguments, which may be distributed over multiple argument locations.
    To adequately represent this case, offsets are added that represent
    which field is in which argument location. If the struct includes
    arrays (possibly packed arrays of e.g., chars), registers may be
    subdivided by byte (e.g., R0:0, R0:1, etc.)

    The argindex refers to the actual argument index in the binary
    (zero-based).

    The arglocs (argument locations) is a list of tuples consisting of:
    - the location (represented as a string, e.g., 'R0', R0:0 or 'stack:16')
    - the offset, if this argument is a field in a struct (default NoOffset)
    - the size of the location (can be 1, 2, or 4)
    """

    def __init__(
            self,
            vname: str,
            parameter: int,
            argindex: int,
            bctyp: Optional["BCT.BCTyp"] = None,
            vtype: Optional[AST.ASTTyp] = None,
            size: Optional[int] = None) -> None:
        ASTIVarInfo.__init__(
            self,
            vname,
            vtype,
            size=size,
            parameter=parameter,
            notes=set(["formal"]))
        self._bctyp = bctyp
        self._argindex = argindex
        self._arglocs: List[Tuple[str, AST.ASTOffset, int]] = []

    @property
    def bctyp(self) -> Optional["BCT.BCTyp"]:
        return self._bctyp

    @property
    def arglocs(self) -> List[Tuple[str, AST.ASTOffset, int]]:
        return self._arglocs

    def argloc(self, index: int) -> Tuple[str, AST.ASTOffset, int]:
        if len(self.arglocs) > index:
            return self.arglocs[index]
        else:
            raise Exception(
                "Formal "
                + self.vname
                + ": illegal index: "
                + str(index)
                + " (number of argument locations: "
                + str(len(self.arglocs)))

    @property
    def numargs(self) -> int:
        """Return the number of arguments in 4-byte equivalents."""

        return sum(argloc[2] for argloc in self.arglocs) // 4

    @property
    def argindex(self) -> int:
        """Return the index of the first (binary) argument for this formal."""

        return self._argindex

    def arglocs_for_argindex(self, argindex: int) -> List[int]:
        result: List[int] = []
        localargindex = argindex - self.argindex
        low = 4 * localargindex
        high = low + 4
        counter: int = 0
        offset: int = 0
        for l in self.arglocs:
            if offset >= low and offset < high:
                result.append(counter)
            counter += 1
            offset += l[2]
        return result

    def initialize(self, callingconvention: str) -> int:
        argtype = self.bctyp
        if argtype is not None:
            if callingconvention == "arm":
                return self._initialize_arm_arguments(argtype)
            elif callingconvention == "mips":
                return self._initialize_mips_arguments(argtype)
            else:
                raise Exception(
                    "Calling convention "
                    + str(callingconvention)
                    + " not recognized")
        else:
            raise Exception(
                "Formal parameter has no type")

    def _initialize_arm_arguments(self, argtype: "BCT.BCTyp") -> int:
        """Set up arguments according to the standard ARM ABI.

        The default calling convention for ARM:
        - the first four arguments are passed in R0, R1, R2, R3
        - subsequent arguments are passed on the stack starting at offset 0
        """

        if argtype.is_scalar:
            argloc = get_arg_loc("arm", self.argindex * 4, 4)
            self._arglocs.append((argloc, AST.ASTNoOffset(), 4))
            return self.argindex + 1
        elif argtype.is_struct:
            structtyp = cast("BCT.BCTypComp", argtype)
            fieldoffsets = structtyp.compinfo.fieldoffsets()
            argbytecounter = 4 * self.argindex
            for (offset, finfo) in fieldoffsets:
                if finfo.byte_size() <= 4:
                    fieldsize = finfo.byte_size()
                    argloc = get_arg_loc("arm", argbytecounter, fieldsize)
                    argbytecounter += fieldsize
                    fieldoffset = AST.ASTFieldOffset(
                        finfo.fieldname,
                        structtyp.compkey,
                        AST.ASTNoOffset())
                    self._arglocs.append((argloc, fieldoffset, fieldsize))
                else:
                    if finfo.fieldtype.is_array:
                        atype = cast("BCT.BCTypArray", finfo.fieldtype)
                        if (
                                atype.has_constant_size()
                                and atype.tgttyp.byte_size() == 1):
                            # assume array elements are packed
                            for i in range(0, atype.sizevalue):
                                argloc = get_arg_loc(
                                    "arm", argbytecounter, 1)
                                indexoffset = AST.ASTIndexOffset(
                                    AST.ASTIntegerConstant(i),
                                    AST.ASTNoOffset())
                                fieldoffset = AST.ASTFieldOffset(
                                    finfo.fieldname,
                                    structtyp.compkey,
                                    indexoffset)
                                argbytecounter += 1
                                self._arglocs.append((argloc, fieldoffset, 1))

            return argbytecounter // 4
        else:
            return 0

    def _initialize_mips_arguments(self, argtype: "BCT.BCTyp") -> int:
        if argtype.is_scalar or argtype.is_pointer:
            argloc = get_arg_loc("mips", self.argindex * 4, 4)
            self._arglocs.append((argloc, AST.ASTNoOffset(), 4))
            return self.argindex + 1
        else:
            print("Argument type is not a scalar: " + str(argtype))
            return 0

    def __str__(self) -> str:
        if len(self.arglocs) == 1:
            p_arglocs = self.arglocs[0][0]
        else:
            p_arglocs = ", ".join(
                str(loc) + ": " + str(offset) for (loc, offset, _) in self.arglocs)
        return ASTIVarInfo.__str__(self) + " (" + p_arglocs + ")"
