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

from typing import cast, Dict, List, Optional, Tuple, TYPE_CHECKING

from chb.simulation.SimulationState import SimulationState

from chb.simulation.SimLocation import (
    SimLocation,
    SimRegister,
    SimDoubleRegister,
    SimMemoryLocation)
from chb.simulation.SimMemory import SimGlobalMemory, SimStackMemory
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

from chb.x86.X86Operand import X86Operand
from chb.x86.X86OperandKind import (
    X86DoubleRegisterOp,
    X86FlagOp,
    X86ImmediateOp,
    X86IndirectRegisterOp,
    X86RegisterOp,
    X86ScaledIndirectRegisterOp
    )

if TYPE_CHECKING:
    from chb.x86.X86Function import X86Function


class X86SimulationState(SimulationState):

    def __init__(
            self,
            x86fn: "X86Function",
            imagebase: str) -> None:
        SimulationState.__init__(self)
        self._x86fn = x86fn
        self._imagebase = SSV.mk_global_address(int(imagebase, 16))
        self.uninitializedregion: Optional[
            Tuple[SSV.SimGlobalAddress, SSV.SimGlobalAddress]] = None
        self.flags: Dict[str, SV.SimBoolValue] = {}   # flagname -> SimBoolValue
        self.registers: Dict[str, SV.SimValue] = {}
        self._globalmem = SimGlobalMemory(self)
        self.stackmem = SimStackMemory(self)
        self.fnlog: Dict[str, List[str]] = {}             # iaddr -> msg list
        self.registers['esp'] = SSV.mk_stack_address(0)
        self.registers['ebp'] = SSV.mk_symbol('ebp-in')
        self.registers['eax'] = SSV.mk_symbol('eax-in')
        self.registers['ecx'] = SSV.mk_symbol('ecx-in')
        self.stackmem.set("0", SSV.mk_stack_address(0), SSV.SimReturnAddress())
        self.flags['DF'] = SV.simflagclr         # direction forward
        self.flags['CF'] = SV.simflagclr         # no carry
        self.flags['PF'] = SV.simflagclr         # even parity
        self.flags['ZF'] = SV.simflagclr         # no zero result
        self.flags['SF'] = SV.simflagclr         # unsigned result
        self.flags['OF'] = SV.simflagclr         # no overflow occurred

    @property
    def function(self) -> "X86Function":
        return self._x86fn

    @property
    def imagebase(self) -> SSV.SimGlobalAddress:
        return self._imagebase

    @property
    def globalmem(self) -> SimGlobalMemory:
        return self._globalmem

    def set_initial_register(self, reg: str, regval: SV.SimValue) -> None:
        if SU.is_full_reg(reg):
            self.registers[reg] = regval
        else:
            raise UF.CHBError('Register ' + reg + ' cannot be initialized')

    def set_uninitialized_region(self, low: str, high: str) -> None:
        self.uninitializedregion = (
            SSV.mk_global_address(int(low, 16)),
            SSV.mk_global_address(int(high, 16)))

    def is_uninitialized_global_mem(self, address: str) -> bool:
        if self.uninitializedregion is not None:
            (low, high) = self.uninitializedregion
            addr_i = int(address, 16)
            return low.offsetvalue <= addr_i and addr_i < high.offsetvalue
        return False

    def set_register(self, iaddr: str, reg: str, srcval: SV.SimValue) -> None:
        if SU.is_full_reg(reg):
            if srcval.is_doubleword:
                self.registers[reg] = srcval
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    'Cannot assign byte/word value to full register: ' + str(srcval)
                    + ' (width: ' + str(srcval.width) + ')')
        elif SU.is_half_reg(reg):
            fullreg = SU.fullregmap[reg]
            fullregval = self.get_regval(iaddr, fullreg)
            if fullregval.is_literal:
                fullregval = cast(SV.SimDoubleWordValue, fullregval)
                newval = fullregval.set_low_word(srcval)
                self.set_register(iaddr, fullreg, newval)
            else:
                self.set_register(iaddr, fullreg, SV.simUndefinedDW)
        elif SU.is_qlow_reg(reg):
            fullreg = SU.fullregmap[reg]
            fullregval = self.get_regval(iaddr, fullreg)
            if fullregval.is_literal:
                fullregval = cast(SV.SimDoubleWordValue, fullregval)
                if srcval.is_literal:
                    if srcval.is_doubleword:
                        srcval = cast(SV.SimDoubleWordValue, srcval)
                        newval = fullregval.set_byte1(srcval.simbyte1)
                    elif srcval.is_word:
                        srcval = cast(SV.SimWordValue, srcval)
                        newval = fullregval.set_byte1(srcval.lowbyte)
                    elif srcval.is_byte:
                        srcval = cast(SV.SimByteValue, srcval)
                        newval = fullregval.set_byte1(srcval)
                    else:
                        raise SU.CHBSimError(
                            self,
                            iaddr,
                            "Unable to set low byte with srcval " + str(srcval))
                self.set_register(iaddr, fullreg, newval)
            else:
                self.set_register(iaddr, fullreg, SV.simUndefinedDW)
        elif SU.is_qhigh_reg(reg):
            fullreg = SU.fullregmap[reg]
            fullregval = self.get_regval(iaddr, fullreg)
            if fullregval.is_literal:
                fullregval = cast(SV.SimDoubleWordValue, fullregval)
                if srcval.is_literal:
                    if srcval.is_doubleword:
                        srcval = cast(SV.SimDoubleWordValue, srcval)
                        newval = fullregval.set_byte2(srcval.simbyte1)
                    elif srcval.is_word:
                        srcval = cast(SV.SimWordValue, srcval)
                        newval = fullregval.set_byte2(srcval.lowbyte)
                    elif srcval.is_byte:
                        srcval = cast(SV.SimByteValue, srcval)
                        newval = fullregval.set_byte2(srcval)
                    else:
                        raise SU.CHBSimError(
                            self,
                            iaddr,
                            "Unable to set second byte with srcval " + str(srcval))
                self.set_register(iaddr, fullreg, newval)
            else:
                self.set_register(iaddr, fullreg, SV.simUndefinedDW)
        else:
            self.registers[reg] = srcval

    def set(self, iaddr: str, dstop: X86Operand, srcval: SV.SimValue) -> None:
        if not srcval.is_defined:
            self.add_logmsg(iaddr, 'Source value is undefined: ' + str(dstop))
        lhs = self.get_lhs(iaddr, dstop)
        if lhs.is_register:
            lhs = cast(SimRegister, lhs)
            self.set_register(iaddr, lhs.register, srcval)

        elif (lhs.is_double_register
              and srcval.is_literal
              and srcval.is_quadword):
            srcval = cast(SV.SimQuadWordValue, srcval)
            lhs = cast(SimDoubleRegister, lhs)
            self.set_register(iaddr, lhs.lowregister, srcval.lowhalf)
            self.set_register(iaddr, lhs.highregister, srcval.highhalf)

        elif lhs.is_memory_location:
            lhs = cast(SimMemoryLocation, lhs)
            if lhs.is_global:
                self.globalmem.set(iaddr, lhs.simaddress, srcval)
                self.add_logmsg(iaddr, str(lhs) + ' := ' + str(srcval))
            elif lhs.is_stack:
                self.stackmem.set(iaddr, lhs.simaddress, srcval)
            else:
                self.add_logmsg(
                    iaddr, 'Destination location not found: ' + str(dstop))
        else:
            self.add_logmsg(iaddr, 'Destination location not found: ' + str(dstop))

    def push_value(self, iaddr: str, simval: SV.SimValue) -> None:
        esp = self.get_regval(iaddr, "esp")
        if esp.is_stack_address:
            esp = cast(SSV.SimStackAddress, esp)
            newesp = esp.add_offset(-4)
            self.registers['esp'] = newesp
            self.stackmem.set(iaddr, newesp, simval)
        else:
            raise SU.CHBSimError(
                self, iaddr, "esp is not a stack address: " + str(esp))

    def pop_value(self, iaddr: str) -> SV.SimValue:
        esp = self.get_regval(iaddr, "esp")
        if esp.is_stack_address:
            esp = cast(SSV.SimStackAddress, esp)
            newesp = esp.add_offset(4)
            self.registers['esp'] = newesp
            return self.stackmem.get(iaddr, esp, 4)
        else:
            raise SU.CHBSimError(
                self, iaddr, "esp is not a stack address: " + str(esp))

    def set_flag(self, iaddr: str, flag: str) -> None:
        if flag in self.flags:
            self.flags[flag] = SV.simflagset
        else:
            raise SU.CHBSimError(
                self, iaddr, 'flag not recognized: ' + flag)

    def clear_flag(self, iaddr: str, flag: str) -> None:
        if flag in self.flags:
            self.flags[flag] = SV.simflagclr
        else:
            raise SU.CHBSimError(
                self, iaddr, 'flag not recognized: ' + flag)

    def undefine_flag(self, iaddr: str, flag: str) -> None:
        if flag in self.flags:
            self.flags[flag] = SV.simflagundef
        else:
            raise SU.CHBSimError(
                self, iaddr, 'flag not recognized: ' + flag)

    def update_flag(self, iaddr: str, flag: str, v: Optional[bool]) -> None:
        if v is None:
            self.undefine_flag(iaddr, flag)
        elif v:
            self.set_flag(iaddr, flag)
        else:
            self.clear_flag(iaddr, flag)

    def get_flag_value(self, iaddr: str, flag: str) -> Optional[int]:
        if flag in self.flags:
            if self.flags[flag].is_defined:
                return self.flags[flag].value
            else:
                return None
        else:
            raise SU.CHBSimError(
                self, iaddr, 'flag not recognized: ' + flag)

    def get_rhs(self, iaddr: str, op: X86Operand) -> SV.SimValue:
        opsize = op.size
        opkind = op.opkind
        if opkind.is_flag:
            opkind = cast(X86FlagOp, opkind)
            flag = opkind.flag
            if flag in self.flags:
                return self.flags[flag]
            else:
                raise SU.CHBSimError(
                    self, iaddr, 'flag value ' + flag + ' not found')

        elif opkind.is_register:
            opkind = cast(X86RegisterOp, opkind)
            reg = opkind.register
            return self.get_regval(iaddr, reg)

        elif opkind.is_double_register:
            opkind = cast(X86DoubleRegisterOp, opkind)
            lowval = self.get_regval(iaddr, opkind.register_low)
            highval = self.get_regval(iaddr, opkind.register_high)
            if lowval.is_doubleword and highval.is_doubleword:
                lowval = cast(SV.SimDoubleWordValue, lowval)
                highval = cast(SV.SimDoubleWordValue, highval)
                return lowval.to_double_size(highval)
            elif lowval.is_word and highval.is_word:
                lowval = cast(SV.SimWordValue, lowval)
                highval = cast(SV.SimWordValue, highval)
                return lowval.to_double_size(highval)
            else:
                raise SU.CHBSimError(
                    self, iaddr, "double register")

        elif opkind.is_immediate:
            opkind = cast(X86ImmediateOp, opkind)
            return SV.mk_simvalue(opkind.value, size=op.size)

        elif opkind.is_indirect_register:
            opkind = cast(X86IndirectRegisterOp, opkind)
            reg = opkind.register
            offset = opkind.offset
            regval = self.get_regval(iaddr, reg)
            if regval.is_address:
                regval = cast(SSV.SimAddress, regval)
                addr = regval.add_offset(offset)
                return self.get_memval(iaddr, addr, op.size)
            elif regval.is_literal and regval.is_defined:
                regval = cast(SV.SimLiteralValue, regval)
                if regval.value > self.imagebase.offsetvalue:
                    gaddr = SSV.mk_global_address(regval.value + offset)
                    return self.get_memval(iaddr, gaddr, op.size)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        'register used in indirect register operand has no base: '
                        + str(regval)
                        + ' ('
                        + str(self.imagebase)
                        + ')')
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    'register used in indirect register operand has no base: '
                    + str(regval)
                    + ' ('
                    + str(self.imagebase)
                    + ')')

        elif opkind.is_scaled_indirect_register:
            opkind = cast(X86ScaledIndirectRegisterOp, opkind)
            basereg = opkind.base_register
            indexreg = opkind.index_register
            offset = opkind.offset
            scale = opkind.scale
            if (basereg is not None) and indexreg is None and scale == 1:
                regval = self.get_regval(iaddr, basereg)
                if regval.is_address:
                    regval = cast(SSV.SimAddress, regval)
                    addr = regval.add_offset(offset)
                    return self.get_memval(iaddr, addr, op.size)
                else:
                    return SV.simUndefinedDW
            elif (basereg is not None) and (indexreg is not None) and scale == 1:
                baseval = self.get_regval(iaddr, basereg)
                indexval = self.get_regval(iaddr, indexreg)
                if indexval.is_address and baseval.is_literal:
                    baseval = cast(SV.SimLiteralValue, baseval)
                    indexval = cast(SSV.SimAddress, indexval)
                    memaddr = indexval.add_offset(offset)
                    memaddr = memaddr.add_offset(baseval.to_signed_int())
                    return self.get_memval(iaddr, memaddr, op.size)
                else:
                    raise SU.CHBSimError(
                        self, iaddr, 'rhs-op not recognized(A): ' + str(op))
            else:
                raise SU.CHBSimError(
                    self, iaddr, 'rhs-op not recognized(B): ' + str(op))
        else:
            raise SU.CHBSimError(
                self, iaddr, 'rhs-op not recognized(C): ' + str(op))

    def get_lhs(self, iaddr: str, op: X86Operand) -> SimLocation:
        opkind = op.opkind
        if opkind.is_register:
            opkind = cast(X86RegisterOp, opkind)
            return SimRegister(opkind.register)

        elif opkind.is_double_register:
            opkind = cast(X86DoubleRegisterOp, opkind)
            return SimDoubleRegister(opkind.register_low, opkind.register_high)

        elif opkind.is_indirect_register:
            opkind = cast(X86IndirectRegisterOp, opkind)
            reg = opkind.register
            offset = opkind.offset
            regval = self.get_regval(iaddr, reg)
            if regval.is_address:
                regval = cast(SSV.SimAddress, regval)
                return SimMemoryLocation(regval.add_offset(offset))
            elif regval.is_literal and regval.is_defined:
                regval = cast(SV.SimLiteralValue, regval)
                if regval.value > self.imagebase.offsetvalue:
                    addr = SSV.mk_global_address(regval.value + offset)
                    return SimMemoryLocation(addr)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ('get-lhs: operand not recognized: '
                         + str(op)
                         + ' (regval: '
                         + str(regval)
                         + ')'))
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ("get-lhs: operand not recognized: "
                     + str(op)
                     + " (regval: "
                     + str(regval)
                     + ")"))

        elif opkind.is_scaled_indirect_register:
            opkind = cast(X86ScaledIndirectRegisterOp, opkind)
            basereg = opkind.base_register
            indexreg = opkind.index_register
            offset = opkind.offset
            scale = opkind.scale
            if (basereg is not None) and indexreg is None and scale == 1:
                regval = self.get_regval(iaddr, basereg)
                if regval.is_address:
                    regval = cast(SSV.SimAddress, regval)
                    return SimMemoryLocation(regval.add_offset(offset))
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ("get-lhs: operand not recognized: "
                         + str(op)
                         + ' produces: '
                         + str(regval)))
            elif (basereg is not None) and (indexreg is not None) and scale == 1:
                baseregval = self.get_regval(iaddr, basereg)
                indexval = self.get_regval(iaddr, indexreg)
                if indexval.is_address and baseregval.is_literal:
                    baseregval = cast(SV.SimLiteralValue, baseregval)
                    indexval = cast(SSV.SimAddress, indexval)
                    memaddress = indexval.add_offset(baseregval.to_signed_int())
                    memaddress = memaddress.add_offset(offset)
                    return SimMemoryLocation(memaddress)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        'get-lhs: operand not recognized(A): ' + str(op))
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ('get-lhs: operand not recognized(B): '
                     + str(op)
                     + ' (scaled indirect)'))
        else:
            raise SU.CHBSimError(
                self, iaddr, 'get-lhs: operand not recognized(C): ' + str(op))

    def get_address_val(self, iaddr: str, op: X86Operand) -> SV.SimValue:
        opkind = op.opkind
        if opkind.is_indirect_register:
            opkind = cast(X86IndirectRegisterOp, opkind)
            reg = opkind.register
            offset = opkind.offset
            regval = self.get_regval(iaddr, reg)
            if regval.is_address and regval.is_defined:
                regval = cast(SSV.SimAddress, regval)
                return regval.add_offset(offset)
            elif regval.is_literal and regval.is_defined:
                regval = cast(SV.SimLiteralValue, regval)
                if regval.value > self.imagebase.offsetvalue:
                    return SSV.mk_global_address(regval.value + offset)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        "get-address-val: indirect register: " + str(op))
            else:
                return SV.simUndefinedDW

        elif opkind.is_scaled_indirect_register:
            opkind = cast(X86ScaledIndirectRegisterOp, opkind)
            basereg = opkind.base_register
            indexreg = opkind.index_register
            scale = opkind.scale
            if indexreg is None and scale == 1 and basereg is not None:
                offset = opkind.offset
                regval = self.get_regval(iaddr, basereg)
                if regval.is_address:
                    regval = cast(SSV.SimAddress, regval)
                    return regval.add_offset(offset)
                elif regval.is_literal and regval.is_defined:
                    regval = cast(SV.SimLiteralValue, regval)
                    if regval.value > self.imagebase.offsetvalue:
                        return SSV.mk_global_address(regval.value + offset)
                    else:
                        raise SU.CHBSimError(
                            self,
                            iaddr,
                            ('get-address-val: indirect-scaled-register: '
                             + str(basereg)))
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ('get-address-val: indirect-scaled-register: '
                         + str(basereg)
                         + ', '
                         + str(indexreg)))
            else:
                raise SU.CHBSimError(self, iaddr, "get-address-val: " + str(op))

        else:
            raise SU.CHBSimError(self, iaddr, "get-address-val: " + str(op))

    def get_regval(self, iaddr: str, reg: str) -> SV.SimValue:
        if SU.is_half_reg(reg):
            fullreg = SU.get_full_reg(reg)
            if fullreg in self.registers:
                regval = self.registers[fullreg]
                if regval.is_literal:
                    regval = cast(SV.SimDoubleWordValue, regval)
                    return regval.lowword
                else:
                    return SV.simUndefinedWord
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ('get_regval: no value found  for '
                     + reg
                     + ' ('
                     + fullreg
                     + ')'))

        elif SU.is_qlow_reg(reg):
            fullreg = SU.get_full_reg(reg)
            if fullreg in self.registers:
                regval = self.registers[fullreg]
                if regval.is_literal:
                    regval = cast(SV.SimDoubleWordValue, regval)
                    return regval.simbyte1
                else:
                    return SV.simUndefinedByte
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ('get_regval: no value found for '
                     + reg
                     + ' ('
                     + fullreg
                     + ')'))

        elif SU.is_qhigh_reg(reg):
            fullreg = SU.get_full_reg(reg)
            if fullreg in self.registers:
                regval = self.registers[fullreg]
                if regval.is_literal:
                    regval = cast(SV.SimDoubleWordValue, regval)
                    return regval.simbyte2
                else:
                    return SV.simUndefinedByte
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ('get_regval: no value found for '
                     + reg
                     + ' ('
                     + fullreg
                     + ')'))

        elif reg in self.registers:
            return self.registers[reg]
        else:
            self.add_logmsg(iaddr, 'no value for register ' + reg)
            return SV.simUndefinedDW

    def get_memval(
            self,
            iaddr: str,
            address: SV.SimValue,
            size: int,
            signextend: bool = False) -> SV.SimValue:
        if address.is_address:
            address = cast(SSV.SimAddress, address)
            if address.is_global_address:
                return self.globalmem.get(iaddr, address, size)
            elif address.is_stack_address:
                return self.stackmem.get(iaddr, address, size)
            else:
                self.add_logmsg(
                    iaddr, 'base ' + address.base + ' not yet supported')
                return SV.simZero
        else:
            self.add_logmsg(
                iaddr,
                'attempt to address memory with absolute value: '
                + str(address))
            return SV.simZero

    def add_logmsg(self, iaddr: str, msg: str) -> None:
        self.fnlog.setdefault(iaddr, [])
        self.fnlog[iaddr].append(msg)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append('\nFlags:')
        for f in sorted(self.flags):
            lines.append(f.ljust(10) + str(self.flags[f]))
        lines.append('\nRegisters:')
        for r in sorted(self.registers):
            lines.append(r.ljust(10) + str(self.registers[r]))
        lines.append(
            '\nGlobal memory: (size: '
            + str(self.globalmem.size)
            + ', extent: '
            + str(self.globalmem.extent())
            + ')')
        lines.append(str(self.globalmem))
        lines.append(self.globalmem.to_byte_string())
        lines.append('\nStack memory:')
        lines.append(str(self.stackmem))
        if len(self.fnlog) > 0:
            lines.append('\nLog messages:')
            for a in sorted(self.fnlog):
                lines.append(
                    str(a).ljust(14) + '; '.join([str(x) for x in self.fnlog[a]]))
        return '\n'.join(lines)
