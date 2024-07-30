# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
"""Utilities for AST nodes."""

import copy

from typing import (
    cast, Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING)

import chb.ast.ASTNode as AST

import chb.util.fileutil as UF


if TYPE_CHECKING:
    from chb.astinterface.ASTInterface import ASTInterface


arm_registers = [
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8",
    "R9", "R10" "R11", "R12", "SP", "LR", "PC"]


def get_arm_arg_loc(bytecounter: int, size: int) -> str:
    index = bytecounter // 4
    rem = bytecounter % 4
    if index < 4:
        if size == 4:
            if rem == 0:
                return "R" + str(index)
            else:
                raise UF.CHBError(
                    "Unexpected alignment in arm argument location")
        else:
            return "R" + str(index) + ":" + str(rem)

    else:
        return "stack:" + str(bytecounter - 16)


def get_mips_arg_loc(bytecounter: int, size: int) -> str:
    index = bytecounter // 4
    rem = bytecounter % 4
    if index < 4:
        if size == 4:
            if rem == 0:
                return "a" + str(index)
            else:
                raise UF.CHBError(
                    "Unexpected alignment in mips argument location")
        else:
            return "a" + str(index) + ":" + str(rem)
    else:
        return "stack:" + str(bytecounter)


def get_power_arg_loc(bytecounter: int, size: int) -> str:
    index = bytecounter // 4
    rem = bytecounter % 4
    if index < 8:
        if size == 4:
            if rem == 0:
                return "r" + str(index + 3)
            else:
                raise UF.CHBError(
                    "Unexpected alignment in power argument location")
        else:
            return "r" + str(index + 3) + ":" + str(rem)
    else:
        raise UF.CHBError(
            "More than eight arguments not yet supported")


def get_arg_loc(callingconvention: str, bytecounter: int, size: int) -> str:
    """Return a string that denotes the location of a given function argument."""

    index = bytecounter // 4
    if index < 0:
        raise Exception(
            "Argument index cannot be smaller than zero: " + str(index))
    if callingconvention == "arm":
        return get_arm_arg_loc(bytecounter, size)
    elif callingconvention == "mips":
        return get_mips_arg_loc(bytecounter, size)
    elif callingconvention == "power":
        return get_power_arg_loc(bytecounter, size)
    else:
        return "?"


def assign_type_compatible(
        astree: "ASTInterface",
        actual: AST.ASTTyp,
        declared: AST.ASTTyp) -> bool:
    if actual == declared:
        return True

    if actual.is_array and declared.is_pointer:
        actual = cast(AST.ASTTypArray, actual)
        declared = cast(AST.ASTTypPtr, declared)
        if declared.tgttyp.is_void:
            return True
        else:
            return assign_type_compatible(astree, actual.tgttyp, declared.tgttyp)

    if actual.is_pointer and declared.is_pointer:
        declared = cast(AST.ASTTypPtr, declared)
        return declared.tgttyp.is_void

    return False
