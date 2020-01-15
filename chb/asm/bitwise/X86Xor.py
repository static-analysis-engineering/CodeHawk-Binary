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

class X86Xor(X.X86OpcodeBase):

    # tags: [ 'xor' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:v" ],[ lhs, rhs ] when src and dst are the same
    #        [ "a:vxxxx" ],[ lhs, rhs1, rhs2, xor expr, xor-expr simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1:       # src, dst are the same, result is zero
            lhs = str(xprs[0])
            return lhs + ' = 0'
        elif len(xprs) == 5:
            lhs = str(xprs[0])
            result = str(xprs[3])
            rresult = str(xprs[4])
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return lhs + ' = ' + result
        else:
            return 'xor:????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 or len(xprs) == 5:
            return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5: return [ xprs[4] ]
        else: return []

    # --------------------------------------------------------------------------
    # Performs a bitwise exclusive OR (XOR) operation on the destination (first)
    # and source (second) operands and stores the result in the destination
    # operand location.
    # Each bit of the result is 1 if the corresponding bits of the operands are
    # different; each bit is 0 if the corresponding bits are the same.
    #
    # Flags affected:
    # The OF and CF flags are cleared; the SF, ZF, and PF flags are set according
    # to the result. The state of the AF flag is undefined.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        if (srcop.is_register() and dstop.is_register()
                and srcop.get_register() == dstop.get_register()):
            zero = SV.mk_simvalue(dstop.get_size(),0)
            simstate.set(iaddr,dstop,zero)
            simstate.set_flag('ZF')
            simstate.clear_flag('PF')
            simstate.clear_flag('CF')
            simstate.clear_flag('OF')
            simstate.clear_flag('SF')
        else:
            try:
                srcval = simstate.get_rhs(iaddr,srcop)
                dstval = simstate.get_rhs(iaddr,dstop)
                result = dstval.bitwise_xor(srcval)
                simstate.set(iaddr,dstop,result)
                simstate.clear_flag('OF')
                simstate.clear_flag('CF')
                simstate.update_flag('SF',result.is_negative())
                simstate.update_flag('ZF',result.is_zero())
                simstate.update_flag('PF',result.is_odd_parity())
            except SU.KTCHBSimError as e:
                raise
            except UF.KTError as e:
                raise SU.KTCHBSimError(simstate,iaddr,str(e))
