# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs, LLC
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

from chb.asm.FnX86Dictionary import FnX86Dictionary
from chb.asm.AsmBlock import AsmBlock
from chb.asm.Cfg import Cfg

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnInvariants import FnInvariants


class AsmFunction(object):

    def __init__(self,app,xnode):
        self.app = app    # AppAccess
        self.xnode = xnode
        self.blocks = {}      # baddr (hex-address) -> AsmBlock
        self.cfg = Cfg(self,self.xnode.find('cfg'))
        self.faddr = self.xnode.get('a')
        vxnode = UF.get_function_vars_xnode(self.app.path,self.app.filename,self.faddr)
        invnode = UF.get_function_invs_xnode(self.app.path,self.app.filename,self.faddr)
        self.vardictionary = FnVarDictionary(self,vxnode.find('var-dictionary'))
        self.invdictionary = FnInvDictionary(self.vardictionary,invnode.find('inv-dictionary'))
        self.invariants = FnInvariants(self.invdictionary,invnode.find('locations'))
        self.dictionary = FnX86Dictionary(self,self.xnode.find('instr-dictionary'))

    def has_name(self): return self.app.functionsdata.has_name(self.faddr)

    def get_names(self):
        if self.has_name():
            return self.app.functionsdata.get_names(self.faddr)
        return []

    def get_block(self,baddr):
        self._get_blocks()
        if baddr in self.blocks:
            return self.blocks[baddr]

    def get_arg_count(self):
        xvalues = self.vardictionary.get_constant_value_variables()
        argvalues = [ x for x in xvalues if x.is_argument_value() ]
        argcount = 0
        for a in argvalues:
            argindex = a.get_argument_index()
            if argindex > argcount: argcount = argindex
        return argcount

    def get_instruction(self,iaddr):
        self._get_blocks()
        for b in self.blocks:
            if self.blocks[b].has_instruction(iaddr):
                return self.blocks[b].get_instruction(iaddr)
        print('Instruction at ' + iaddr + ' not found in function ' + self.faddr)

    def get_instructions(self):     # returns iaddr -> AsmInstruction
        self._get_blocks()
        result = {}
        for b in self.blocks: result.update(self.blocks[b].instructions)
        return result

    def get_instruction_count(self): return len(self.get_instructions())

    def iter_instructions(self,f):
        instrs = self.get_instructions()
        for iaddr in sorted(instrs):
            f(iaddr,instrs[iaddr])

    def get_operands(self):
        result = {}
        def f(ia,i):
            operands = i.get_operands()
            if len(operands) > 0:
                result[ia] = operands
        self.iter_instructions(f)
        return result

    def get_operand_values(self):
        result = {}
        def f(ia,i):
            opvalues = i.get_operand_values()
            if len(opvalues) > 0:
                result[ia] = opvalues
        self.iter_instructions(f)
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

    def get_md5_hash(self):
        m = hashlib.md5()
        def f(ia,i): m.update(i.get_byte_string().encode('utf-8'))
        self.iter_instructions(f)
        return m.hexdigest()

    def get_calls_to_app_function(self,tgtaddr):
        result = []
        def f(iaddr,instr):
            if instr.is_call_to_app_function(tgtaddr):
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_dll_calls(self):
        result = []
        def f(iaddr,instr):
            if instr.is_dll_call():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_branch_predicates(self):
        result = []
        def f(iaddr,instr):
            if instr.has_branch_predicate():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_so_calls(self):
        result = []
        def f(iaddr,instr):
            if instr.is_so_call():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_app_calls(self):
        result = []
        def f(iaddr,instr):
            if instr.is_app_call():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_unresolved_calls(self):
        result = []
        def f(iaddr,instr):
            if instr.is_unresolved_call():
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

    def get_structured_lhs_variables(self):
        result = []
        def f(iaddr,instr):
            result.extend(instr.get_structured_lhs())
        self.iter_instructions(f)
        return result

    def get_structured_lhs_instructions(self):
        result = []
        def f(iaddr,instr):
            if instr.has_structured_lhs():
                result.append(instr)
        self.iter_instructions(f)
        return result

    def get_structured_rhs_expressions(self):
        result = []
        def f(iaddr,instr):
            result.extend(instr.get_structured_rhs())
        self.iter_instructions(f)
        return result

    def get_return_expressions(self):
        result = []
        for b in sorted(self.blocks):
            if self.blocks[b].has_return():
                result.append(self.blocks[b].get_return_expr())
        return result

    def get_ioc_arguments(self):  # returns [ (rolename,parametername,argument value) ]
        result = []
        def f(iaddr,instr):
            result.extend(instr.get_ioc_arguments())
        self.iter_instructions(f)
        return result

    def as_dictionary(self):
        self._get_blocks()
        result = {}
        for b in sorted(self.blocks):
            block = self.blocks[b]
            result[block.baddr] = block.as_dictionary()
        return result

    def simulate_block(self,simstate,blockaddr,processed):
        if not blockaddr in self.blocks:
            raise SU.CHBSimError(simstate,blockaddr,'Block address not found: ' + str(blockaddr))
        block = self.blocks[blockaddr]
        def f(_,i):
            i.simulate(simstate)
            processed.append(i)
        try:
            block.iter_instructions(f)
            return (block.baddr,processed)
        except SU.CHBSimError as e:
            e.set_instructions_processed(processed)
            raise
        except SU.SimFallthroughException as e:
            e.set_instructions_processed(processed)
            e.set_block_address(block.baddr)
            raise
        except SU.SimJumpException as e:
            processed.append(self.get_instruction(e.iaddr))
            tgtaddr = str(e.tgtaddr)
            if tgtaddr in self.blocks:
                return self.simulate_block(simstate,tgtaddr,processed)
            else:
                targets = ','.join([ str(t) for t in self.blocks ])
                eerror = SU.CHBSimError(simstate,e.iaddr,
                                              'Target block address not found: ' + str(e.tgtaddr)
                                              + ' (targets: ' + targets + ')')
                raise eerror

    def simulate(self,simstate,processed=[]):
        self._get_blocks()
        blockaddr = self.faddr
        while True:
            try:
                (baddr,processed) = self.simulate_block(simstate,blockaddr,processed)
                bsuccessors = self.cfg.get_successors(baddr)
            except SU.SimFallthroughException as e:
                baddr = e.blockaddr
                processed = e.processed
                bsuccessors = self.cfg.get_successors(baddr)
                bsuccessors = [ x for x in bsuccessors if not x == e.tgtaddr ]

            if len(bsuccessors) == 1:
                blockaddr = bsuccessors[0]
                if not (blockaddr in self.blocks):
                    raise SU.CHBSimError(simstate,baddr,
                                            'Block successor not found: ' + str(blockaddr))
            elif len(bsuccessors) == 0:
                raise SU.CHBSimError(simstate,baddr,'No block successors found'+
                                           str(self.cfg))
            else:
                err = SU.CHBSimError(simstate,baddr,'Multiple block successors found: ' +
                                        ','.join([ str(x) for x in bsuccessors ]))
                err.set_instructions_processed(processed)
                raise err

    def to_opcode_operations_string(self):
        self._get_blocks()
        lines = []
        for b in sorted(self.blocks):
            lines.append(self.blocks[b].to_opcode_operations_string())
            lines.append('-'  * 80)
        return '\n'.join(lines)

    def to_string(self,bytestring=False,bytes=False,esp=False,opcodetxt=True,hash=False,
                  opcodewidth=25):
        self._get_blocks()
        lines = []
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(bytestring=bytestring,
                                         bytes=bytes,
                                         esp=esp,
                                         opcodewidth=opcodewidth,
                                         opcodetxt=opcodetxt))
            lines.append('-' * 80)
        if bytestring: lines.append(self.get_byte_string(chunksize=80))
        if hash: lines.append('hash: ' + self.get_md5_hash())
        return '\n'.join(lines)

    def __str__(self): return self.to_string()

    def _get_blocks(self):
        if len(self.blocks) > 0: return
        for n in self.xnode.find('instructions').findall('bl'):
            self.blocks[ n.get('ba') ] = AsmBlock(self,n)

    def _get_cfg(self):
        if self.cfg is None:
            self.cfg = Cfg(self,self.xnode)
