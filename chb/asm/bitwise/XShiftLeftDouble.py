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


class X86ShiftLeftDouble(X.X86OpcodeBase):

    # tags: [ 'shld' ]
    # args: [ dst-op, src-op, shift ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_shift_operand(self): return self.x86d.get_operand(self.args[2])

    def get_operands(self):
        return  [ self.get_dst_operand(), self.get_src_operand(),
                      self.get_shift_operand() ]

    # xdata: [ "a:vxxxxx": lhs, dstrhs, dstrhs-rewrittten, srcrhs, srcrhs-rewritten, shift ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        dstrhs = str(xprs[1])
        rdstrhs = str(xprs[2])
        srcrhs = str(xprs[3])
        rsrcrhs = str(xprs[4])
        shift = str(xprs[5])
        return (lhs + ' = ' + rdstrhs + ' shift in left ' + rsrcrhs + ' by ' + shift + ' bits')

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) == xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[5] ]
