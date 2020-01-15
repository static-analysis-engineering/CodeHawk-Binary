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

class X86RotateLeft(X.X86OpcodeBase):

    # tags: [ 'rol' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:vxx" ],[ lhs, number of bits to rotate, value to rotate ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 3:
            lhs = str(xprs[0])
            rhs1 = str(xprs[1])
            rhs2 = str(xprs[2])
            return lhs + ' = ' + rhs2 + ' rotate-left-by' + rhs1
        else:
            return 'rol:????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 3: return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 3: return [ xprs[2] ]
        else: return []

    # --------------------------------------------------------------------------
    # Rotates the bits of the first operand (destination operand) the number of
    # bit positions specified in the second operand (count operand) and stores
    # the result in the destination operand. The count operand is an unsigned
    # integer that can be an immediate or a value in the CL register. In legacy
    # and compatibility mode, the processor restricts the count to a number
    # between 0 and 31 by masking all the bits in the count operand except the
    # 5 least-significant bits.
    #
    # The rotate left (ROL) instruction shifts all the bits toward
    # more-significant bit positions, except for the most-significant bit,
    # which is rotated to the least-significant bit location.
    # For the ROL instruction, the original value of the CF flag is not a part
    # of the result, but the CF flag receives a copy of the bit that was shifted
    # from one end to the other.
    #
    # The OF flag is defined only for the 1-bit rotates; it is undefined in
    # all other cases (except that a zero-bit rotate does nothing, that is affects
    # no flags). For left rotates, the OF flag is set to the exclusive OR
    # of the CF bit (after the rotate) and the most- significant bit of the
    # result.
    #
    # IF (tempCOUNT > 0) (* Prevents updates to CF *)
    #    WHILE (tempCOUNT <> 0) DO
    #       tempCF = MSB(DEST);
    #       DEST = (DEST * 2) + tempCF;
    #       tempCOUNT = tempCOUNT - 1;
    #    CF = LSB(DEST);
    #    IF COUNT == 1
    #       THEN OF = MSB(DEST) XOR CF;
    #       ELSE OF is undefined;
    #
    # Flags affected:
    # The CF flag contains the value of the bit shifted into it. The OF flag is
    # affected only for single-bit rotates; it is undefined for multi-bit
    # rotates. The SF, ZF, AF, and PF flags are not affected.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        dstval = simstate.get_rhs(iaddr,dstop)
        result = dstval.bitwise_rol(srcval)
        simstate.set(iaddr,dstop,result)
        if srcval.value > 0:
            cflag = result.get_lsb()
            simstate.update_flag('CF',cflag)
            if srcval.value == 1:
                oflag = result.get_msb() ^ cflag
            else:
                oflag = None
            simstate.update_flag('OF',oflag)
