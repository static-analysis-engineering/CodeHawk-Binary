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


class X86Loop(X.X86OpcodeBase):

    # tags: [ 'loop' ]
    # args: [ op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_target_address(self):
        return self.x86d.get_operand(self.args[0])

    def get_operands(self): return [ self.get_target_address() ]

    def get_annotation(self,xdata):
        return 'loop ' + str(self.get_target_address())

    # --------------------------------------------------------------------------
    # Performs a loop operation using the ECX or CX register as a counter
    # (depending on whether address size is 32 bits, or 16 bits).
    #
    # Each time the LOOP instruction is executed, the count register is
    # decremented, then checked for 0. If the count is 0, the loop is terminated
    # and program execution continues with the instruction following the LOOP
    # instruction. If the count is not zero, a near jump is performed to the
    # destination (target) operand, which is presumably the instruction at the
    # beginning of the loop.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        ecxval = simstate.get_regval(iaddr,'ecx')
        newval = ecxval.sub(SV.simone)
        simstate.set_register(iaddr,'ecx',newval)
        tgtaddr = str(self.get_target_address())
        if newval.value != 0:
            raise SU.KTSimJumpException(iaddr,tgtaddr)
        raise SU.KTSimFallthroughException(iaddr,tgtaddr)
        
        
        

 
