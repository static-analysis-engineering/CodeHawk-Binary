# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

max8 = 255
max7 = 127

max16 = 65535
max15 = 32767

max32 = 4294967295
max31 = 2147483648

max64 = 18446744073709551615
max63 = 9223372036854775807

def is_full_reg(reg):
    return reg in [ 'eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi' ]

def is_half_reg(reg):
    return reg in [ 'ax', 'bx', 'cx', 'dx', 'sp', 'bp', 'si', 'di' ]

def is_qlow_reg(reg):
    return reg in [ 'al', 'bl', 'cl', 'dl' ]

def is_qhigh_reg(reg):
    return reg in [ 'ah', 'bh', 'ch', 'dh' ]

mips_register_order = [
    'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
    't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra' ]

fullregmap = {
    'al': 'eax',
    'ah': 'eax',
    'ax': 'eax',
    'bl': 'ebx',
    'bh': 'ebx',
    'bx': 'ebx',
    'cl': 'ecx',
    'ch': 'ecx',
    'cx': 'ecx',
    'dl': 'edx',
    'dh': 'edx',
    'dx': 'edx',
    'sp': 'esp',
    'bp': 'ebp',
    'si': 'esi',
    'di': 'edi'
    }

def get_full_reg(reg):
    if is_full_reg(reg):
        return reg
    elif reg in fullregmap:
        return fullregmap[reg]
    else:
        return reg

def compute_dw_value(byte1,byte2,byte3,byte4):
    return (byte1 + (byte2 << 8) + (byte3 << 16) + (byte4 << 24))

def compute_dw_value_eb(byte1,byte2,byte3,byte4):
    return (byte4 + (byte3 << 8) + (byte2 << 8) + (byte1 << 24))

def simassign(iaddr,simstate,lhs,rhs,intermediates=''):
    lhs = simstate.get_lhs(iaddr,lhs)
    intermediates = ' ; ' + intermediates if intermediates else ''
    return str(lhs) + ' := ' + str(rhs) + intermediates

def simcall(iaddr,simstate,tgtval,returnaddr,intermediates=''):
    return 'call ' + str(tgtval) + ', ra := ' + returnaddr

def simbranch(iaddr,simstate,truetgt,falsetgt,expr,result):
    if result.is_defined():
        taken = 'T' if str(result) == '1' else 'F'
    else:
        taken = '?'
    return 'if ' + expr + ' then goto ' + str(truetgt) + ' (' + taken + ')'
        

class CHBSimError(UF.CHBError):

    def __init__(self,simstate,iaddr,msg):
        UF.CHBError.__init__(self,msg)
        self.simstate = simstate
        self.iaddr = iaddr
        self.instrtxt = None
        self.processed = []

    def set_instructions_processed(self,p): self.processed = p

    def __str__(self):
        lines = []
        pinstr = '' if self.instrtxt is None else ': ' + self.instrtxt
        lines.append(UF.CHBError.__str__(self))
        lines.append('-' * 80)
        lines.append('Instruction at address: ' + str(self.iaddr) + pinstr)
        if len(self.processed) > 0:
            lines.append('-' * 80)
            lines.append('Instructions processed (' + str(len(self.processed)) +'):')
            for i in self.processed:
                lines.append('  ' + str(i.iaddr) + '  ' + i.to_string(opcodewidth=30))
            lines.append('-' * 80)
        # lines.append(str(self.simstate))
        return '\n'.join(lines)

class CHBSimOpError(UF.CHBError):

    def __init__(self,msg,ops):
        UF.CHBError.__init__(self,msg)
        self.ops = ops

    def __str__(self):
        lines = []
        lines.append(UF.CHBError.__str__(self))
        lines.append('-' * 80)
        lines.append('Operands:')
        for op in self.ops:
            lines.append('  ' + str(op))
        return '\n'.join(lines)

class CHBSimStaticLibFunction(CHBSimError):

    def __init__(self,iaddr,startaddr,registers):
        CHBSimError.__init__(self,None,iaddr,'enter static library with startaddr ' + startaddr)
        self.startaddr = startaddr
        self.registers = registers

class CHBSimBranchUnknownError(CHBSimError):

    def __init__(self,simstate,iaddr,truetgt,falsetgt,msg):
        CHBSimError.__init__(self,simstate,iaddr,msg)
        self.truetgt = truetgt
        self.falsetgt = falsetgt

class CHBSimCallTargetUnknownError(CHBSimError):

    def __init__(self,simstate,iaddr,calltgt,msg):
        CHBSimError.__init__(self,simstate,iaddr,msg)
        self.calltgt = calltgt

class CHBSimJumpTargetUnknownError(CHBSimError):

    def __init__(self,simstate,iaddr,jumptgt,msg):
        CHBSimError.__init__(self,simstate,iaddr,msg)
        self.jumptgt = jumptgt

class CHBSymbolicExpression(CHBSimError):

    def __init__(self,simstate,iaddr,dstop,msg):
        CHBSimError.__init__(self,simstate,iaddr,msg)
        self.dstop = dstop

class CHBSymbolicPointer(CHBSimError):

    def __init__(self,simstate,iaddr,base,offset):
        CHBSimError.__init__(self,simstate,iaddr,
                             'symbolic pointer with base ' + base + ' and offset ' + offset)
        self.base = base
        self.offset = offset

class CHBSimValueUndefinedError(UF.CHBError):

    def __init__(self,msg):
        UF.CHBError.__init__(self,msg)

class CHBSimValueSymbolicError(UF.CHBError):

    def __init__(self,msg):
        UF.CHBError.__init__(self,msg)


class CHBSimFunctionReturn(Exception):

    def __init__(self,iaddr):
        self.iaddr = iaddr


class CHBSimJumpException(Exception):

    def __init__(self,iaddr,tgtaddr):
        self.iaddr = iaddr
        self.tgtaddr = tgtaddr

class CHBSimFallthroughException(Exception):

    def __init__(self,iaddr,tgtaddr):
        self.iaddr = iaddr
        self.tgtaddr = tgtaddr
        self.blockaddr = None
        self.processed = None

    def set_block_address(self,baddr): self.blockaddr = baddr

    def set_instructions_processed(self,p): self.processed = p

