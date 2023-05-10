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

from typing import List, Tuple


class ARMCodeGenerator:

    def __init__(self) -> None:
        pass

    def get_stack_adjustment(self, offset: int) -> Tuple[str, List[str]]:
        hexstring: str = ""
        assemblies: List[str] = []
        while offset > 0:
            if offset < 512:
                sp_offset = offset
            else:
                sp_offset = 508
            (instr, assembly) = self.add_sp_plus_immediate_t2(sp_offset)
            offset = offset - sp_offset
            hexstring = hexstring + instr
            assemblies.append(assembly)
        return (hexstring, assemblies)

    def add_sp_plus_immediate_t2(self, offset: int) -> Tuple[str, str]:
        if offset % 4 == 0:
            imm = offset // 4
            if imm < 128 and imm >= 0:
                hexval = hex(imm)
                if len(hexval) == 3:
                    hexval = "0" + hexval[2:]
                else:
                    hexval = hexval[2:]
                assembly = "ADD".ljust(8) + "SP, SP, #" + hex(offset)
                return (hexval + "b0", assembly)
            else:
                raise Exception(
                    "instruction not supported; offset is too large: " + str(offset))
        else:
            raise Exception("instruction not supported; offset not multiple of four")

    def pop_registers_t1(self, regs: List[int], pc: bool) -> Tuple[str, str]:
        byte2 = "bd" if pc else "bc"
        reglist = 0
        for i in regs:
            if i < 8:
                reglist += 2**i
        byte1 = hex(reglist)[2:]
        regstring = ",".join("R" + str(i) for i in sorted(regs))
        if pc:
            regstring += ",PC"
        assembly = "POP".ljust(8) + "{" + regstring + "}"
        return (byte1 + byte2, assembly)
