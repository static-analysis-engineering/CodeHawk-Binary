# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from typing import List, Mapping, Optional, TYPE_CHECKING

import chb.util.fileutil as UF

from chb.app.Operand import Operand

if TYPE_CHECKING:
    from chb.app.Instruction import Instruction
    from chb.simulation.SimLocation import SimLocation
    from chb.simulation.SimulationState import SimulationState
    from chb.simulation.SimSymbolicValue import SimSymbolicValue
    from chb.simulation.SimValue import SimValue


max8 = 255
max7 = 127

max16 = 65535
max15 = 32767

max32 = 4294967295
max31 = 2147483648

max64 = 18446744073709551615
max63 = 9223372036854775807


def checkbit(v: int, msg: str) -> None:
    """Checks whether the given value is within [0; 1]."""

    if v < 0 or v > 1:
        raise UF.CHBError(msg + ": value is not a bit: " + str(v))
    else:
        return


def is_full_reg(reg: str) -> bool:
    return reg in ['eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi']


def is_half_reg(reg: str) -> bool:
    return reg in ['ax', 'bx', 'cx', 'dx', 'sp', 'bp', 'si', 'di']


def is_qlow_reg(reg: str) -> bool:
    return reg in ['al', 'bl', 'cl', 'dl']


def is_qhigh_reg(reg: str) -> bool:
    return reg in ['ah', 'bh', 'ch', 'dh']


mips_register_order = [
    'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
    't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']


fullregmap = {
    'al': 'eax',
    'ah': 'eax',
    'ax': 'eax',
    'bl': 'ebx',
    'bh': 'ebx',
    'bx': 'ebx',
    'cl': 'ecx',
    'ch': 'ecx',
    'cx': 'ecx',
    'dl': 'edx',
    'dh': 'edx',
    'dx': 'edx',
    'sp': 'esp',
    'bp': 'ebp',
    'si': 'esi',
    'di': 'edi'
    }


def get_full_reg(reg: str) -> str:
    if is_full_reg(reg):
        return reg
    elif reg in fullregmap:
        return fullregmap[reg]
    else:
        return reg


def compute_dw_value(byte1: int, byte2: int, byte3: int, byte4: int) -> int:
    return (byte1 + (byte2 << 8) + (byte3 << 16) + (byte4 << 24))


def compute_dw_value_eb(byte1: int, byte2: int, byte3: int, byte4: int) -> int:
    return (byte4 + (byte3 << 8) + (byte2 << 8) + (byte1 << 24))


def simassign(
        iaddr: str,
        simstate: "SimulationState",
        lhs: "SimLocation",
        rhs: "SimValue",
        intermediates: str = "") -> str:
    # lhs = simstate.get_lhs(iaddr,lhs)
    intermediates = ' ; ' + intermediates if intermediates else ''
    return str(lhs) + ' := ' + str(rhs) + intermediates


def simcall(
        iaddr: str,
        simstate: "SimulationState",
        tgtval: "SimSymbolicValue",
        returnaddr: "SimSymbolicValue",
        intermediates: str = "") -> str:
    return "call " + str(tgtval) + ", ra := " + str(returnaddr)


def simbranch(
        iaddr: str,
        simstate: "SimulationState",
        truetgt: "SimSymbolicValue",
        falsetgt: "SimSymbolicValue",
        expr: str,
        result: "SimValue") -> str:
    if result.is_defined():
        taken = 'T' if str(result) == '1' else 'F'
    else:
        taken = '?'
    return 'if ' + expr + ' then goto ' + str(truetgt) + ' (' + taken + ')'


class CHBSimError(UF.CHBError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            msg: str) -> None:
        UF.CHBError.__init__(self, msg)
        self.simstate = simstate
        self.iaddr = iaddr
        self.instrtxt: Optional[str] = None
        self.processed: List["Instruction"] = []

    def set_instructions_processed(self, p: List["Instruction"]) -> None:
        self.processed = p

    def __str__(self) -> str:
        lines: List[str] = []
        pinstr = ""
        if self.instrtxt is not None:
            pinstr = ": " + self.instrtxt
        lines.append(UF.CHBError.__str__(self))
        lines.append('-' * 80)
        lines.append('"Instruction" at address: ' + self.iaddr + pinstr)
        if len(self.processed) > 0:
            lines.append('-' * 80)
            lines.append(
                '"Instruction"s processed (' + str(len(self.processed)) + '):')
            for i in self.processed:
                lines.append(
                    '  ' + str(i.iaddr) + '  ' + i.to_string(opcodewidth=30))
            lines.append('-' * 80)
        return '\n'.join(lines)


class CHBSimOpError(UF.CHBError):

    def __init__(self, msg: str, ops: List["SimValue"]) -> None:
        UF.CHBError.__init__(self, msg)
        self.ops = ops

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(UF.CHBError.__str__(self))
        lines.append('-' * 80)
        lines.append('Operands:')
        for op in self.ops:
            lines.append('  ' + str(op))
        return '\n'.join(lines)


class CHBSimStaticLibFunction(UF.CHBError):

    def __init__(
            self,
            iaddr: str,
            startaddr: str,
            registers: Mapping[str, "SimValue"]) -> None:
        UF.CHBError.__init__(
            self, "enter static library with startaddr " + str(startaddr))
        self.iaddr = iaddr
        self.startaddr = startaddr
        self.registers = registers


class CHBSimBranchUnknownError(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            truetgt: "SimSymbolicValue",
            falsetgt: "SimSymbolicValue",
            msg: str) -> None:
        CHBSimError.__init__(self, simstate, iaddr, msg)
        self.truetgt = truetgt
        self.falsetgt = falsetgt


class CHBSimCallTargetUnknownError(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            calltgt: "SimSymbolicValue",
            msg: str) -> None:
        CHBSimError.__init__(self, simstate, iaddr, msg)
        self.calltgt = calltgt


class CHBSimCallbackException(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            pc: "SimSymbolicValue",
            msg: str) -> None:
        CHBSimError.__init__(self, simstate, iaddr, "callback: " + str(pc))
        self.msg = msg
        self.pc = pc


class CHBSimPopContextException(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            msg: str) -> None:
        CHBSimError.__init__(self, simstate, iaddr, "pop-context")
        self.msg = msg


class CHBSimSystemCallException(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            syscallindex: int) -> None:
        CHBSimError.__init__(
            self, simstate, iaddr, "system call: " + str(syscallindex))
        self.syscallindex = syscallindex


class CHBSimJumpTargetUnknownError(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            jumptgt: "SimSymbolicValue",
            msg: str) -> None:
        CHBSimError.__init__(self, simstate, iaddr, msg)
        self.jumptgt = jumptgt


class CHBSymbolicExpression(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            dstop: "Operand",
            msg: str) -> None:
        CHBSimError.__init__(self, simstate, iaddr, msg)
        self.dstop = dstop


class CHBSymbolicPointer(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            base: str,
            offset: str) -> None:
        CHBSimError.__init__(
            self,
            simstate,
            iaddr,
            "symbolic pointer with base " + base + " and offset " + offset)
        self.base = base
        self.offset = offset


class CHBSimExitException(CHBSimError):

    def __init__(
            self,
            simstate: "SimulationState",
            iaddr: str,
            exitvalue: str) -> None:
        CHBSimError.__init__(
            self,
            simstate,
            iaddr,
            "system exit with exit value " + exitvalue)
        self.exitvalue = exitvalue


class CHBSimValueUndefinedError(UF.CHBError):

    def __init__(self, msg: str) -> None:
        UF.CHBError.__init__(self, msg)


class CHBSimValueSymbolicError(UF.CHBError):

    def __init__(self, msg: str) -> None:
        UF.CHBError.__init__(self, msg)


class CHBSimFunctionReturn(UF.CHBError):

    def __init__(self, iaddr: str):
        UF.CHBError.__init__(self, "Function return at " + iaddr)
        self.iaddr = iaddr


class CHBSimJumpException(UF.CHBError):

    def __init__(self, iaddr: str, tgtaddr: str) -> None:
        UF.CHBError.__init__(self, "Jump from " + iaddr + " to " + tgtaddr)
        self.iaddr = iaddr
        self.tgtaddr = tgtaddr


class CHBSimFallthroughException(UF.CHBError):

    def __init__(self, iaddr: str, tgtaddr: str) -> None:
        UF.CHBError.__init__(self, "Fall through")
        self.iaddr = iaddr
        self.tgtaddr = tgtaddr
        self.blockaddr: Optional[str] = None
        self.processed: List["Instruction"] = []

    def set_block_address(self, baddr: str) -> None:
        self.blockaddr = baddr

    def set_instructions_processed(self, p: List["Instruction"]) -> None:
        self.processed = p
