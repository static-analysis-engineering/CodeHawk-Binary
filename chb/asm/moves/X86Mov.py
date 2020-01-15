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

class X86Mov(X.X86OpcodeBase):

    # tags: [ 'mov' ]
    # args: [ size, dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_src_operand(self): return self.x86d.get_operand(self.args[2])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    def get_opcode_operations(self):
        src = self.get_src_operand()
        dst = self.get_dst_operand()
        return [ dst.to_operand_string() + ' = ' + src.to_operand_string() ]

    # xdata: [ "nop" ]  no state change
    #        [ "a:xx" ; "arg", callsite ],[ x, x, argindex ] function argument
    #        [ "a:vxx" ]  assignment (lhs, rhs, rhs-simplified)
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) > 0 and xtags[0] == 'arg':
            callsite = xtags[1]
            argindex = xargs[2]
            xval = str(xprs[1])
            return '[' + str(callsite) + ':' + str(argindex) + ': ' + xval + ']'
        if len(xprs) == 3:
            lhs = str(xprs[0])
            rhs = str(xprs[1])
            rrhs = str(xprs[2])
            rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
            return lhs + ' = ' + rhs
        else:
            if len(xtags) > 0:
                return xtags[0]
            else:
                return 'mov:????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) > 0 and xtags[0] == 'arg': return []
        if len(xprs) == 3: return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) > 0 and xtags[0] == 'arg': return [ xprs[1] ]
        if len(xprs) == 3: return [ xprs[2] ]
        else: return []

    def get_operand_values(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) > 0 and xtags[0] == 'arg':
            return [ xprs[1] ]
        elif len(xprs) == 3:
            return [ xprs[2] ]
        else:
            return []

    # --------------------------------------------------------------------------
    # Copies the second operand (source operand) to the first operand
    # (destination operand).
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        simstate.set(iaddr,self.get_dst_operand(),srcval)
