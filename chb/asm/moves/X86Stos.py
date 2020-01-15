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

class X86Stos(X.X86OpcodeBase):

    # tags: [ 'stosb' ]
    # args: [ width, dst-op, src-op, edi-op, df-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[1])   # (Edi)

    def get_src_operand(self): return self.x86d.get_operand(self.args[2])   # AL, AX, or EAX

    def get_edi_operand(self): return self.x86d.get_operand(self.args[3])   # Edi

    def get_df_operand(self): return self.x86d.get_operand(self.args[4])    # direction flag

    def get_width(self): return self.args[0]

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:vvxxxxxx": lhs, edilhs, rhs, rrhs, edirhs, redirhs, dfrhs, rdfrhs ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        edilhs = str(xprs[1])
        rhs = str(xprs[3])
        edirhs = str(xprs[5])
        dfrhs = xprs[7]
        ediop = ' +/- '
        if dfrhs.is_int_const_value(0): ediop = ' + '
        elif dfrhs.is_int_const_value(1): ediop = ' - '
        return (lhs + ' = ' + rhs + '; ' + edilhs + ' = '+  edirhs + ediop
                    + str(self.get_width()) + ' (df = ' + str(dfrhs) + ')')

    # --------------------------------------------------------------------------
    # Stores a byte, word, or doubleword from the AL, AX, or EAX register
    # (respectively) into the destination operand. The destination operand is a
    # memory location, the address of which is read from either the ES:EDI or
    # ES:DI register.
    #
    # After the byte, word, or doubleword is transferred from the register to
    # the memory location, the (E)DI register is incremented or decremented
    # according to the setting of the DF flag in the EFLAGS register. If the DF
    # flag is 0, the register is incremented; if the DF flag is 1, the register
    # is decremented (the register is incremented or decre- mented by 1 for
    # byte operations, by 2 for word operations, by 4 for doubleword
    # operations).
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        size = dstop.get_size()
        ediop = self.get_edi_operand()
        dfop = self.get_df_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        edival = simstate.get_rhs(iaddr,ediop)
        dfval = simstate.get_rhs(iaddr,dfop)
        ediinc = SV.mk_simvalue(4,size)
        if dfval.is_set():
            edinewval = srcval.sub(ediinc)
        else:
            edinewval = srcval.add(ediinc)
        simstate.set(iaddr,dstop,srcval)            
        simstate.set(iaddr,ediop,edinewval)
        
