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

class X86Movs(X.X86OpcodeBase):

    # tags: [ 'movs' ]
    # args: [ size, dst-op, src-op, src-ptr-op (esi), dst-ptr-op (edi) ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_size(self):  return int(self.args[0])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[1])

    def get_src_operand(self): return self.x86d.get_operand(self.args[2])

    def get_srcptr_operand(self): return self.x86d.get_operand(self.args[3])

    def get_dstptr_operand(self): return self.x86d.get_operand(self.args[4])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand(),
                     self.get_srcptr_operand(), self.get_dstptr_operand() ]

    # xdata: [ "a:vvvxxxxxx": lhs, srcptrlhs (esi), dsptrlhs (edi),
    #                         rhs, rhs-rewritten, srcptrrhs, srcptrrhs-rewritten,
    #                         dstptrrhs, dstptrrhs-rewritten ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[3])
        rrhs = str(xprs[4])
        rhs = X.simplify_result(xargs[3],xargs[4],rhs,rrhs)
        srcptrrhs = str(xprs[5])
        rsrcptrrhs = str(xprs[6])
        srcptrrhs = X.simplify_result(xargs[5],xargs[6],srcptrrhs,rsrcptrrhs)
        dstptrrhs = str(xprs[7])
        rdstptrrhs = str(xprs[8])
        dstptrrhs = X.simplify_result(xargs[7],xargs[8],dstptrrhs,rdstptrrhs)
        return (lhs + ' = ' +  rhs + '; esi = ' + srcptrrhs  + '; edi = ' + dstptrrhs)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[4], xprs[6], xprs[8] ]

    # --------------------------------------------------------------------------
    # Moves the byte, word, or doubleword specified with the second operand
    # (source operand) to the location specified with the first operand
    # (destination operand). Both the source and destination operands are
    # located in memory. The address of the source operand is read from the
    # DS:ESI or the DS:SI registers (depending on the address-size attribute
    # of the instruction, 32 or 16, respectively). The address of the
    # destination operand is read from the ES:EDI or the ES:DI registers
    # (again depending on the address-size attribute of the instruction).
    #
    # After the move operation, the (E)SI and (E)DI registers are incremented or
    # decremented automatically according to the setting of the DF flag in the
    # EFLAGS register. (If the DF flag is 0, the (E)SI and (E)DI register are
    # incremented; if the DF flag is 1, the (E)SI and (E)DI registers are
    # decremented.) The registers are incremented or decremented by 1 for byte
    # operations, by 2 for word operations, or by 4 for double- word operations.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcptrop = self.get_srcptr_operand()
        dstptrop = self.get_dstptr_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        srcptrval = simstate.get_rhs(iaddr,srcptrop)
        dstptrval = simstate.get_rhs(iaddr,dstptrop)
        # raise UF.KTCHBError(str(iaddr) + ': '
        #                        + 'srcop: ' + str(srcop)
        #                        + '; srcval: ' + str(srcval)
        #                        + '; esi: ' + str(srcptrval)
        #                        + '; edi: ' + str(dstptrval)
        #                        + '\n' + str(simstate))        
        dflag = simstate.get_flag_value('DF')
        incr = SV.mk_simvalue(srcptrop.get_size(),self.get_size())
        simstate.set(iaddr,dstop,srcval)
        if dflag == 0:
            simstate.set(iaddr,srcptrop,srcptrval.add(incr))
            simstate.set(iaddr,dstptrop,dstptrval.add(incr))
        elif dflag == 1:
            simstate.set(iaddr,srcptrop,srcptrval.sub(incr))
            simstate.set(iaddr,dstptrop,dstptrval.sub(incr))
        else:
            raise UF.KTCHBError('Unexpected value for direction flag: ' + str(dflag))
                             
            
