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

import hashlib

import chb.util.fileutil as UF
import chb.simulate.SimUtil as SU

from chb.mips.FnMIPSDictionary import FnMIPSDictionary
from chb.mips.MIPSBlock import MIPSBlock
from chb.mips.MIPSCfg import MIPSCfg

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnInvariants import FnInvariants

class MIPSFunction(object):

    def __init__(self,app,xnode):
        self.app = app    # AppAccess
        self.xnode = xnode
        self.blocks = {}      # baddr (hex-address) -> AsmBlock
        self.cfg = MIPSCfg(self,self.xnode.find('cfg'))
        self.faddr = self.xnode.get('a')
        vxnode = UF.get_function_vars_xnode(self.app.path,self.app.filename,self.faddr)
        invnode = UF.get_function_invs_xnode(self.app.path,self.app.filename,self.faddr)
        self.vardictionary = FnVarDictionary(self,vxnode.find('var-dictionary'))
        self.invdictionary = FnInvDictionary(self.vardictionary,invnode.find('inv-dictionary'))
        self.invariants = FnInvariants(self.invdictionary,invnode.find('locations'))
        self.dictionary = FnMIPSDictionary(self,self.xnode.find('instr-dictionary'))

    def has_name(self): return self.app.functionsdata.has_name(self.faddr)

    def get_names(self):
        if self.has_name():
            return self.app.functionsdata.get_names(self.faddr)
        return []

    def get_block(self,baddr):
        self._get_blocks()
        if baddr in self.blocks:
            return self.blocks[baddr]

    def has_instruction(self,iaddr):
        self._get_blocks()
        for b in self.blocks:
            if self.blocks[b].has_instruction(iaddr):
                return True
        return False
    
    def get_instruction(self,iaddr):
        self._get_blocks()
        for b in self.blocks:
            if self.blocks[b].has_instruction(iaddr):
                return self.blocks[b].get_instruction(iaddr)
        print('Instruction at ' + iaddr + ' not found in function ' + self.faddr)

    def get_instructions(self):     # returns iaddr -> MIPSInstruction
        self._get_blocks()
        result = {}
        for b in self.blocks: result.update(self.blocks[b].instructions)
        return result

    def iter_instructions(self,f):
        instrs = self.get_instructions()
        for iaddr in sorted(instrs):
            f(iaddr,instrs[iaddr])

    def get_byte_string(self,chunksize=None):
        s = []
        def f(ia,i):s.extend(i.get_byte_string())
        self.iter_instructions(f)
        if chunksize is None:
            return ''.join(s)
        else:
            s = ''.join(s)
            size = len(s)
            chunks = [ s[i:i+chunksize] for i in range(0,size,chunksize) ]
            return '\n'.join(chunks)

    def get_md5_hash(self):
        m = hashlib.md5()
        def f(ia,i): m.update(i.get_byte_string())
        self.iter_instructions(f)
        return m.hexdigest()

    def get_calls_to_app_function(self,tgtaddr):
        result = []
        def f(iaddr,instr):
            if instr.is_call_to_app_function(tgtaddr):
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_app_calls(self):
        """Returns a list of MIPSInstruction that are calls to application functions."""
        result = []
        def f(iaddr,instr):
            if instr.is_call_instruction():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_call_instructions(self):
        result = []
        def f(iaddr,instr):
            if instr.is_call_instruction():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_call_instructions_to_target(self,tgt):
        """Returns a list of MIPSInstruction that are calls to the given app/lib function."""
        result = []
        def f(iaddr,instr):
            if instr.is_call_instruction():
                if str(instr.get_call_target()) == tgt:
                    result.append(instr)
        self.iter_instructions(f)
        return result

    def get_global_refs(self):
        lhsresult = []
        rhsresult = []
        def f(iaddr,instr):
            (lhs,rhs) = instr.get_global_refs()
            lhsresult.extend(lhs)
            rhsresult.extend(rhs)
        self.iter_instructions(f)
        return (lhsresult,rhsresult)

    # returns a list of strings referenced in the function
    def get_strings(self):
        result = []
        def f(iaddr,instr):
            result.extend(instr.get_strings())
        self.iter_instructions(f)
        return result

    # returns a dictionary of gvar -> count
    def get_global_variables(self):
        result = {}
        def f(iaddr,instr):
            iresult = instr.get_global_variables()
            for gv in iresult:
                result.setdefault(gv,0)
                result[gv] += iresult[gv]
        self.iter_instructions(f)
        return result

    # returns a dictionary of regular registers used in the function (name -> variable)
    def get_registers(self):
        result = {}
        def f(iaddr,instr):
            iresult = instr.get_registers()
            for r in iresult:
                result.setdefault(r,iresult[r])
        self.iter_instructions(f)
        return result

    def get_return_instructions(self):
        result = []
        def f(iaddr,instr):
            if instr.is_return_instruction():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_restore_register_instructions(self):
        result = []
        def f(iaddr,instr):
            if instr.is_restore_register_instruction():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_return_expr(self):
        exprs = self.get_return_expressions()
        if len(exprs) == 1:
            return exprs[0]
        elif len(exprs) == 0:
            raise UF.CHBError('No return expression found for function '
                                    + str(self.faddr))
        else:
            raise UF.CHBError('Multiple return expressions found for function '
                                    + str(self.faddr))

    def get_return_expressions(self):
        result = []
        for b in sorted(self.blocks):
            if self.blocks[b].has_return():
                result.append(self.blocks[b].get_return_expr())
        return result

    def to_sliced_string(self,registers):
        self._get_blocks()
        lines = []
        for b in sorted(self.blocks):
            looplevels = self.cfg.get_loop_levels(self.blocks[b].baddr)
            blocklines = self.blocks[b].to_sliced_string(registers,len(looplevels))
            if len(blocklines) > 0:
                lines.append(blocklines)
            else:
                lines.append(str(self.blocks[b].baddr).rjust(10) + ' ' + ('L' * len(looplevels)))
            lines.append('-' * 80)
        return '\n'.join(lines)

    def to_string(self,bytestring=False,sp=False,opcodetxt=True,hash=False,opcodewidth=40):
        self._get_blocks()
        lines = []
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(sp=sp,opcodetxt=opcodetxt,opcodewidth=opcodewidth))
            lines.append('-' * 80)
        if bytestring: lines.append(self.get_byte_string(chunksize=80))
        if hash: lines.append('hash: ' + self.get_md5_hash())
        return '\n'.join(lines)

    def __str__(self): return self.to_string()

    def _get_blocks(self):
        if len(self.blocks) > 0: return
        for n in self.xnode.find('instructions').findall('bl'):
            self.blocks[ n.get('ba') ] = MIPSBlock(self,n)

    def _get_cfg(self):
        if self.cfg is None:
            self.cfg = MIPSCfg(self,self.xnode)
