# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

from chb.asm.AsmInstruction import AsmInstruction

class AsmBlock(object):

    def __init__(self,asmf,xnode):
        self.asmfunction = asmf
        self.xnode = xnode
        self.baddr = self.xnode.get('ba')
        self.instructions = {}           # hex-address -> AsmInstruction
        self._get_instructions()

    def has_instruction(self,iaddr): return iaddr in self.instructions

    def get_instruction(self,iaddr):
        if self.has_instruction(iaddr): return self.instructions[iaddr]

    def iter_instructions(self,f):
        for iaddr in sorted(self.instructions):
            f(iaddr,self.instructions[iaddr])

    def  get_call_instructions(self):
        result = []
        def f(_,i):
            if i.is_call_instruction():
                result.append(i)
        self.iter_instructions(f)
        return result

    def to_opcode_operations_string(self):
        lines = []
        for ia in sorted(self.instructions):
            lines.append(str(ia).rjust(10) + '  '
                             + self.instructions[ia].to_opcode_operations_string())
        return '\n'.join(lines)

    def to_string(self,bytestring=False,bytes=False,esp=False,opcodetxt=True):
        lines = []
        for ia in sorted(self.instructions):
            pinstr = self.instructions[ia].to_string(bytestring=bytestring,
                                                         bytes=bytes,
                                                         esp=esp,
                                                         opcodetxt=opcodetxt)
            lines.append(str(ia).rjust(10) + '  ' + pinstr)
        return '\n'.join(lines)

    def get_last_instruction(self):
        lastaddr = sorted(self.instructions.keys())[-1]
        return self.instructions[lastaddr]

    def has_return(self):
        return self.get_last_instruction().is_return_instruction()

    def get_return_expr(self):
        return self.get_last_instruction().get_return_expr()

    def as_dictionary(self):
        result = {}
        self._get_instructions()
        for iaddr in sorted(self.instructions):
            instr = {}
            i = self.instructions[iaddr]
            instr['iaddr'] = iaddr
            instr['opcode'] = i.get_opcode_text()
            instr['bytes'] = i.get_byte_string()
            instr['esp'] = str(i.get_esp_offset())
            instr['annotation'] = i.get_annotation()
            result[iaddr] = instr
        return result

    def __str__(self): return self.to_string()

    def _get_instructions(self):
        if len(self.instructions) > 0: return
        for n in self.xnode.findall('i'):
            self.instructions[ n.get('ia') ] = AsmInstruction(self,n)
