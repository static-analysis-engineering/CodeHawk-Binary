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

class X86ShiftLeft(X.X86OpcodeBase):

    # tags: [ 'shl' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:vxxxx": lhs, rhsbase, rhs-expr, rhs-result, rhs-result-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5:
            lhs = str(xprs[0])
            rhs = str(xprs[3])
            rrhs = str(xprs[4])
            rrhs = X.simplify_result(xargs[3],xargs[4],rhs,rrhs)
            return lhs + ' = ' + rrhs
        else:
            return (self.tags[0] + ':????')

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5: return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5: return [ xprs[2] ]
        else: return []

    # --------------------------------------------------------------------------
    # Shifts the bits in the first operand (destination operand) to the left by
    # the number of bits specified in the second operand (count operand).
    # The count operand can be an immediate value or the CL register. The count
    # is masked to 5 bits. Bits shifted beyond the destination operand boundary
    # are first shifted into the CF flag, then discarded. At the end of the shift
    # operation, the CF flag contains the last bit shifted out of the
    # destination operand. For each shift count, the most significant bit of the
    # destination operand is shifted into the CF flag, and the least significant
    # bit is cleared.
    #
    # The OF flag is affected only on 1-bit shifts. The OF flag is set to 0 if
    # the most-significant bit of the result is the same as the CF flag (that
    # is, the top two bits of the original operand were the same); otherwise,
    # it is set to 1.
    #
    # Flags affected:
    # The CF flag contains the value of the last bit shifted out of the
    # destination operand; it is undefined for SHL instructions where
    # the count is greater than or equal to the size (in bits) of the destination
    # operand. The OF flag is affected only for 1-bit shifts; otherwise, it is
    # undefined. The SF, ZF, and PF flags are set according to the result. If the
    # count is 0, the flags are not affected. For a non- zero count, the AF flag
    # is undefined.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        dstval = simstate.get_rhs(iaddr,dstop)
        (cflag,result) = dstval.bitwise_shl(srcval)
        simstate.set(iaddr,dstop,result)
        if srcval.value > 0:
            simstate.update_flag('CF',cflag)
            if srcval.value == 1:
                msb = result.get_msb()
                if not (msb == cflag):
                    simstate.clear_flag('OF')
                else:
                    simstate.set_flag('OF')
            else:
                simstate.undefine_flag('OF')
            simstate.update_flag('CF',cflag)
            simstate.update_flag('SF',result.is_negative())
            simstate.update_flag('ZF',result.is_zero())
            simstate.update_flag('PF',result.is_odd_parity())
