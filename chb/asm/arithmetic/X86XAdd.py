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

class X86XAdd(X.X86OpcodeBase):

    # tags: [ 'xadd' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:vvxxxx": srclhs, dstlhs, rhs1, rhs2, sum, sum-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        srclhs = str(xprs[0])
        dstlhs = str(xprs[1])
        srcrhs = str(xprs[2])
        dstrhs = str(xprs[3])
        result = str(xprs[4])
        rresult = str(xprs[5])
        result = X.simplify_result(xargs[4],xargs[5],result,rresult)
        return dstlhs + ' = ' + result + '; ' + srclhs + ' = ' + dstrhs

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0], xprs[1] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[3], xprs[5] ]

    # -------------------------------------------------------------------------
    # Exchanges the first operand (destination operand) with the second operand
    # (source operand), then loads the sum of the two values into the
    # destination operand.
    #
    # TEMP = SRC + DEST
    # Src = DEST
    # DEST = TEMP
    #
    # Flags affected:
    # The CF, PF, AF, SF, ZF, and OF flags are set according to the result of
    # the addition, which is stored in the destination operand.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        dstval = simstate.get_rhs(iaddr,dstop)
        result = dstval.add(srcval)
        simstate.set(iaddr,srcop,dstval)
        simstate.set(iaddr,dstop,result)
        simstate.update_flag('CF',dstval.add_carries(srcval))
        simstate.update_flag('OF',dstval.add_overflows(srcval))
        simstate.update_flag('SF',result.is_negative())
        simstate.update_flag('PF',result.is_odd_parity())
        
