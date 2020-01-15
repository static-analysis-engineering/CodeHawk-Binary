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

import chb.asm.X86OpcodeBase as X
import chb.simulate.SimulationState as S
import chb.simulate.SimUtil as SU
import chb.simulate.SimValue as SV

class X86And(X.X86OpcodeBase):

    # tags: [ 'and' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:v" : lhs ] when the second operand is zero
    #        [ "a:vxx": lhs, rhs, rhs-rewrittne ] when dst = src
    #        [ "a:vxxxx" ],[ lhs, rhs1, rhs2, and-expr, and-expr simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'stack-realign':
            alignment = str(xargs[0])
            return 'align stack on ' + alignment + ' bytes'
        elif len(xprs) == 1:       # rhs is zero, result is zero
            lhs = str(xprs[0])
            return lhs + ' = 0'
        elif len(xprs) == 3:       # dst = src, value is unchanged
            lhs = str(xprs[0])
            rhs = str(xprs[2])
            return lhs + ' = ' + rhs + ' (unchanged)'
        elif len(xprs) == 5:
            lhs = str(xprs[0])
            result = str(xprs[3])
            rresult = str(xprs[4])
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return lhs + ' = ' + result
        else:
            return 'and:????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'stack-realign':
            return []
        elif len(xprs) == 1 or len(xprs) == 3 or len(xprs) == 5:
            return [ xprs[0] ]
        else:
            return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'stack-realign':
            return []
        elif len(xprs) == 3:
            return [ xprs[2] ]
        elif len(xprs) == 5:
            return [ xprs[4] ]
        else:
            return []

    # --------------------------------------------------------------------------
    # Performs a bitwise AND operation on the destination (first) and source
    # (second) operands and stores the result in the destination operand
    # location.
    #
    # Flags affected:
    # The OF and CF flags are cleared; the SF, ZF, and PF flags are set according
    # to the result.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        dstval = simstate.get_rhs(iaddr,dstop)
        result = dstval.bitwise_and(srcval)
        simstate.set(iaddr,dstop,result)
        simstate.clear_flag('OF')
        simstate.clear_flag('CF')
        simstate.update_flag('SF',result.is_negative())
        simstate.update_flag('ZF',result.is_zero())
        simstate.update_flag('PF',result.is_odd_parity())
