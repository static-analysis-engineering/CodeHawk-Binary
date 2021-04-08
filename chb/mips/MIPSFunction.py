# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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

import hashlib
import xml.etree.ElementTree as ET

from typing import Dict, Mapping, Optional, TYPE_CHECKING

import chb.util.fileutil as UF
import chb.simulate.SimUtil as SU

import chb.app.AppAccess as AP
import chb.app.BasicBlock as B
import chb.app.Cfg as C
import chb.app.Function as F
import chb.util.fileutil as UF

from chb.mips.FnMIPSDictionary import FnMIPSDictionary
from chb.mips.MIPSBlock import MIPSBlock
from chb.mips.MIPSCfg import MIPSCfg

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnInvariants import FnInvariants

if TYPE_CHECKING:
    import chb.app.AppAccess


class MIPSFunction(F.Function):

    def __init__(self,
                 app: "chb.app.AppAccess.AppAccess",
                 xnode: ET.Element):
        F.Function.__init__(self, app, xnode)
        self._blocks: Dict[str, MIPSBlock] = {}
        self._cfg: Optional[MIPSCfg] = None

    @property
    def blocks(self) -> Dict[str, MIPSBlock]:
        if len(self._blocks) == 0:
            xinstrs = self.xnode.find("instructions")
            if xinstrs is None:
                raise UF.CHBError("Xml element instructions missing from function xml")
            for b in xinstrs.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Block address is missing from xml")
                self._blocks[baddr] = MIPSBlock(self, b)
        return self._blocks

    @property
    def cfg(self) -> C.Cfg:
        if self._cfg is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("Element cfg missing from function xml")
            self._cfg = MIPSCfg(self, xcfg)
        return self._cfg

    def get_address_reference(self):
        """Return map of addr -> block addr."""
        result = {}
        def add(baddr,block):
            for a in block.instructions:
                result[a] = baddr
        self.iter_blocks(add)
        return result

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

    def get_load_word_instructions(self):
        result = []
        def f(iaddr,instr):
            if instr.is_load_word_instruction():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_store_word_instructions(self):
        result = []
        def f(iaddr,instr):
            if instr.is_store_word_instruction():
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

    def get_jump_conditions(self): return self.cfg.get_conditions()

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
        lines = []
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(sp=sp,opcodetxt=opcodetxt,opcodewidth=opcodewidth))
            lines.append('-' * 80)
        if bytestring: lines.append(self.get_byte_string(chunksize=80))
        if hash: lines.append('hash: ' + self.get_md5_hash())
        return '\n'.join(lines)

    def __str__(self): return self.to_string()
