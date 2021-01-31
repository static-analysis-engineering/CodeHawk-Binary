# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
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
#
# ------------------------------------------------------------------------------
"""MIPS assembly code."""

import chb.simulate.SimUtil as SU

class MIPSAssemblyInstruction(object):

    def __init__(self,app,xnode):
        self.app = app
        self.addr_hx = xnode.get('ia')
        self.addr_i = int(self.addr_hx,16)
        self.opcode = self.app.mipsdictionary.get_mips_opcode(int(xnode.get('iopc')))
        self.stat = xnode.get('stat','')

    def get_mnemonic(self): return self.opcode.get_mnemonic()

    def is_delay_slot(self): return 'D' in self.stat

    def is_block_entry(self): return 'B' in self.stat

    def is_function_entry(self): return 'F' in self.stat

    def is_return_instruction(self):
        return self.opcode.is_return_instruction()

    def get_operand_count(self): return len(self.opcode.get_operands())

    def get_operand(self,i):     # 1-based
        operands = self.opcode.get_operands()
        if len(operands) >= i:   
            return operands[i-1]

    def get_lw_stack_offset(self):
        if self.get_mnemonic() == 'lw':
            lwop = self.get_operand(2)
            if lwop.is_mips_indirect_register_with_reg('sp'):
                return lwop.get_mips_indirect_register_offset()
        return None

    def loads_program_address(self):
        return (self.get_mnemonic() == 'lw'
                and self.get_operand(2).is_mips_indirect_register_with_reg('gp'))

    def loads_stack_value(self):
        return (self.get_mnemonic() == 'lw'
                and self.get_operand(2).is_mips_indirect_register_with_reg('sp'))

    def assigns_stack_address(self):
        return (((len(self.opcode.get_operands()) == 3)
                 and not (str(self.get_operand(1)) == 'sp')                
                 and (str(self.get_operand(2)) == 'sp')
                 and (self.get_operand(3).is_mips_immediate()))
                or (self.get_mnemonic() == 'move'
                    and str(self.get_operand(2)) == 'sp'))

    def simulate(self,simstate):
        try:
            return self.opcode.simulate(self.addr_hx,simstate)
        except SU.CHBSimError as e:
            e.instrtxt = str(self)
            raise e

    def __str__(self):
        return (self.stat.rjust(2) + '  ' + self.addr_hx.rjust(8)
                    + '  ' + self.get_mnemonic().ljust(8)
                    + ','.join([ str(op) for op in self.opcode.get_operands()]))


class MIPSAssembly(object):

    def __init__(self,app,xnode):
        self.app =  app
        self.xnode = xnode
        self.sorted_instructions = []       # list of integer addresses
        self.revsorted_instructions = []    # list of integer addresses (reverse)
        self.instructions = {}
        self.instructions_initialized = False
        self._initialize()

    def __str__(self):
        self._initialize()
        lines = []
        lines.append('MIPS assembly code')
        for (ia,i) in sorted(self.instructions.items()):
            lines.append(str(i))
        return '\n'.join(lines)

    def _initialize(self):
        if self.instructions_initialized:
            return
        for b in self.xnode.findall('b'):
            for n in b.findall('i'):
                    self.instructions[n.get('ia')] = MIPSAssemblyInstruction(self.app,n)
        self.sorted_instructions = sorted(int(k,16) for k in self.instructions.keys())
        self.revsorted_instructions = sorted(self.sorted_instructions,reverse=True)
