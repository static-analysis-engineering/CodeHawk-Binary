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

import chb.util.fileutil as UF

import chb.asm.X86OpcodeBase as X
import chb.simulate.SimulationState as S
import chb.simulate.SimUtil as SU
import chb.simulate.SimValue as SV


class X86Jcc(X.X86OpcodeBase):

    # tags: [ 'jnz', .... ]
    # args: [ i-operand ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def is_conditional_branch(self): return True

    def has_predicate(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return len(xprs) > 0

    def get_predicate(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return xprs[0]
        else:
            return None

    def get_target_address(self):
        return self.x86d.get_operand(self.args[0])

    def get_operands(self): return [ self.get_target_address() ]

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ str(xprs[1]), str(xprs[0]) ]
        return []

    # xdata: [ "a:x": branch predicate ]
    #        [ ]: no predicate found
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        tgtaddr = str(self.get_target_address())
        if len(xprs) > 0:
            return 'if ' + str(xprs[0]) + ' goto ' + tgtaddr
        else:
            return 'if ? goto ' + tgtaddr

    # --------------------------------------------------------------------------
    # Checks the state of one or more of the status flags in the EFLAGS register
    # (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state
    # (condition), performs a jump to the target instruction specified by the
    # destination operand. A condition code (cc) is associated with each
    # instruction to indicate the condition being tested for. If the condition is
    # not satisfied, the jump is not performed and execution continues with the
    # instruction following the Jcc instruction.
    #
    # jc : jump if carry (CF = 1)
    # jnz: jump if not zero  (ZF = 0)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        tag = self.tags[0]
        tgt = str(self.get_target_address())
        def jump(): raise SU.KTSimJumpException(iaddr,tgt)
        def fallthrough(): raise SU.KTSimFallthroughException(iaddr,tgt)
        def undefined(flag): raise SU.KTCHBError('Flag value ' + flag + ' is undefined')

        if tag == 'jc':
            cf = simstate.get_flag_value('CF')
            if cf == 1: jump()
            elif cf == 0: fallthrough()
            else: undefined('CF')
        elif tag == 'jnz':
            zf = simstate.get_flag_value('ZF')
            if zf == 0: jump()
            elif zf == 1: fallthrough()
            else: undefined('ZF')
        else:
            raise SU.KTCHBError('Conditional jump tag not yet supported: ' + tag)
                
