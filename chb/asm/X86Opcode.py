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
"""X86 Opcode specializations."""


import chb.util.fileutil as UF

import chb.asm.X86OpcodeBase as X
import chb.simulate.SimulationState as S
import chb.simulate.SimUtil as SU
import chb.simulate.SimValue as SV

from chb.asm.arithmetic.X86Add import X86Add
from chb.asm.arithmetic.X86Compare import X86Compare
from chb.asm.arithmetic.X86Dec import X86Dec
from chb.asm.arithmetic.X86Div import X86Div
from chb.asm.arithmetic.X86IDiv import X86IDiv
from chb.asm.arithmetic.X86IMul import X86IMul
from chb.asm.arithmetic.X86Inc import X86Inc
from chb.asm.arithmetic.X86Mul import X86Mul
from chb.asm.arithmetic.X86Negate import X86Negate
from chb.asm.arithmetic.X86Sub import X86Sub
from chb.asm.arithmetic.X86SubBorrow import X86SubBorrow
from chb.asm.arithmetic.X86XAdd import X86XAdd

from chb.asm.bitwise.X86And import X86And
from chb.asm.bitwise.X86BNot import X86BNot
from chb.asm.bitwise.X86Or import X86Or
from chb.asm.bitwise.X86RotateLeft import X86RotateLeft
from chb.asm.bitwise.X86RotateLeftCF import X86RotateLeftCF
from chb.asm.bitwise.X86RotateRight import X86RotateRight
from chb.asm.bitwise.X86RotateRightCF import X86RotateRightCF
from chb.asm.bitwise.X86ShiftARight import X86ShiftARight
from chb.asm.bitwise.X86ShiftLeft import X86ShiftLeft
from chb.asm.bitwise.X86ShiftLeftDouble import X86ShiftLeftDouble
from chb.asm.bitwise.X86ShiftRight import X86ShiftRight
from chb.asm.bitwise.X86ShiftRightDouble import X86ShiftRightDouble
from chb.asm.bitwise.X86Xor import X86Xor

from chb.asm.controlflow.X86Jcc import X86Jcc
from chb.asm.controlflow.X86Jump import X86Jump
from chb.asm.controlflow.X86Loop import X86Loop
from chb.asm.controlflow.X86Return import X86Return

from chb.asm.moves.X86Lea import X86Lea
from chb.asm.moves.X86Leave import X86Leave
from chb.asm.moves.X86Mov import X86Mov
from chb.asm.moves.X86Movs import X86Movs
from chb.asm.moves.X86Movsx import X86Movsx
from chb.asm.moves.X86Movzx import X86Movzx
from chb.asm.moves.X86Pop import X86Pop
from chb.asm.moves.X86Push import X86Push
from chb.asm.moves.X86PushRegisters import X86PushRegisters
from chb.asm.moves.X86Stos import X86Stos
from chb.asm.moves.X86Xchg import X86Xchg


x86_opcode_constructors = {
    'add': lambda x: X86Add(*x),
    'and': lambda x: X86And(*x),
    'cdq': lambda x: X86ConvertLongToDouble(*x),
    'cmp': lambda x: X86Compare(*x),
    'cwd': lambda x: X86ConvertLongToDouble(*x),
    'call': lambda x: X86Call(*x),
    'call*': lambda x: X86Call(*x),
    'dec': lambda x: X86Dec(*x),
    'div': lambda x: X86Div(*x),
    'idiv': lambda x: X86IDiv(*x),
    'imul': lambda x: X86IMul(*x),
    'inc': lambda x: X86Inc(*x),
    'jmp': lambda x: X86Jump(*x),
    'jmp*': lambda x: X86IndirectJmp(*x),
    'lea': lambda x: X86Lea(*x),
    'leave': lambda x: X86Leave(*x),
    'loop': lambda x: X86Loop(*x),
    'mov': lambda x: X86Mov(*x),
    'movs': lambda x: X86Movs(*x),
    'movsx': lambda x: X86Movsx(*x),
    'movzx': lambda x: X86Movzx(*x),
    'mul': lambda x: X86Mul(*x),
    'neg': lambda x: X86Negate(*x),
    'not': lambda x: X86BNot(*x),
    'or': lambda x:X86Or(*x),
    'pop': lambda x: X86Pop(*x),    
    'push': lambda x: X86Push(*x),
    'pusha': lambda x: X86PushRegisters(*x),
    'rcl': lambda x: X86RotateLeftCF(*x),
    'rcr': lambda x: X86RotateRightCF(*x),
    'ret': lambda x: X86Return(*x),
    'rol': lambda x: X86RotateLeft(*x),
    'ror': lambda x: X86RotateRight(*x),
    'sar': lambda x: X86ShiftARight(*x),
    'sbb': lambda x: X86SubBorrow(*x),
    'shl': lambda x: X86ShiftLeft(*x),
    'shld': lambda x: X86ShiftLeftDouble(*x),
    'shr': lambda x: X86ShiftRight(*x),
    'shrd': lambda x: X86ShiftRightDouble(*x),
    'stos': lambda x: X86Stos(*x),
    'sub': lambda x: X86Sub(*x),
    'test': lambda x: X86Test(*x),
    'xadd': lambda x: X86XAdd(*x),
    'xchg': lambda x: X86Xchg(*x),
    'xor': lambda x:X86Xor(*x)
    }

def get_opcode(tag,args):
    if tag in [ 'jo', 'jno', 'jc', 'jnc', 'jz', 'jnz', 'jbe', 'ja', 'js',
                    'jns', 'jpe', 'jpo', 'jl', 'jge', 'jle', 'jg' ]:
        return X86Jcc(*args)
    if tag in [ 'seto', 'setna', 'setc', 'setnc', 'setz', 'setnz', 'setbe',
                    'seta', 'sets', 'setns', 'setpe', 'setpo', 'setl', 'setge',
                    'setle', 'setg' ]:
        return X86Setcc(*args)
    if tag in x86_opcode_constructors:
        return x86_opcode_constructors[tag](args)
    else:
        return X.X86OpcodeBase(*args)

class X86ConvertLongToDouble(X.X86OpcodeBase):

    # tags: [ 'cdq' or 'cwd' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return  [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata [ "a:vxx": lhs, rhs, rhs-rewritten ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        return lhs + ' = sign-extend ' + rhs


class X86Call(X.X86OpcodeBase):

    # tags: [ 'call' or 'call*' ]
    # args: [ i-operand ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self): return [ self.get_operand() ]

    def is_call(self): return True

    def get_target_address(self):
        return self.x86d.get_operand(self.args[0])

    def get_call_target(self,xdata):
        (xtags,xargs,_) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'u':
            return None
        elif len(xargs) == 1:
            return self.ixd.get_call_target(xargs[0])
        elif len(xargs) > 1:
            return self.ixd.get_call_target(xargs[-1])

    def is_dll_call(self,xdata):
        target = self.get_call_target(xdata)
        if target is None:
            return False
        else:
            return target.is_dll_target()

    def is_so_call(self,xdata):
        target = self.get_call_target(xdata)
        if target is None:
            return False
        else:
            return target.is_so_target()

    def is_unresolved_call(self,xdata):
        (xtags,_,_) = xdata.get_xprdata()
        return len(xtags) == 1 and xtags[0] == 'u'

    def get_unresolved_call_target(self,xdata):
        (xtags,_,xprs) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'u':
            return xprs[1]

    def has_global_value_unresolved_call_target(self,xdata):
        tgt = self.get_unresolved_call_target(xdata)
        return ((not (tgt is None))
                    and tgt.is_var()
                    and tgt.get_variable().is_global_value())

    def is_app_call(self,xdata):
        target = self.get_call_target(xdata)
        if target is None:
            return False
        else:
            return target.is_app_target()

    def get_dll_target(self,xdata):
        return self.get_call_target(xdata).get_stub()

    def get_app_target(self,xdata):
        return self.get_call_target(xdata).get_address()

    def get_arguments(self,xdata):
        (_,xargs,xprs) = xdata.get_xprdata()
        if len(xargs) > 1:
            return xprs
        else:
            return []

    def get_annotated_arguments(self,xdata):
        tgt = self.get_call_target(xdata)
        (_,_,xprs) = xdata.get_xprdata()
        if tgt.is_dll_target():
            dll = tgt.get_dll()
            name = tgt.get_name()
            if self.app.models.has_dll_summary(dll,name):
                summary = self.app.models.get_dll_summary(dll,name)
                params = summary.get_stack_parameters()
                if len(xprs) == len(params):
                    result = []
                    for (p,x) in zip(params,xprs):
                        if p.get_type().is_string():
                            if self.app.stringxrefs.has_string(str(x)):
                                pvalue = '"' + self.app.stringxrefs.get_string(str(x)) + '"'
                            else:
                                pvalue = str(x)
                        else:
                            pvalue = p.represent_value(x)
                        result.append((p.name,pvalue))
                    return result
                else:
                    print(dll + ':' + name + ": params, args don't match")
            else:
                print(dll + ':' + name + ': summary not found')
        return [ ('arg' + str(i+1),x) for (i,x) in enumerate(xprs) ]

    # xdata: [],[] no call target
    #        ["a:x...", 'u' (if unresolved) ],[ callargs:i-x , i-call-target ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'u':
            calltgt = str(xprs[1])
            return '?(' + ','.join([ str(x) for x in xprs[2:] ]) + ') (with tgt: ' + calltgt + ')'
        if len(xargs) > 1:
            calltgt = self.ixd.get_call_target(xargs[-1])
            pdll = ' (' + str(calltgt.get_stub().get_dll()) + ')' if calltgt.is_dll_target() else ''
            arguments = self.get_annotated_arguments(xdata)
            arguments = ','.join([ p + ':' + str(x) for (p,x) in arguments ])
            return str(calltgt) + '(' + arguments + ')' + pdll
        elif len(xargs) == 1:
            return str(self.ixd.get_call_target(xargs[0])) + '()'
        else:
            tgtaddr = str(self.get_target_address())
            if self.x86d.app.functionsdata.has_name(tgtaddr):
                name = self.x86d.app.functionsdata.get_name(tgtaddr)
            else:
                name = tgtaddr
            return 'call_lib ' + name


class X86IndirectJmp(X.X86OpcodeBase):

    # tags: [ 'jmp*' ]
    # args: [ op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self): return [ self.get_operand() ]

    def is_indirect_jump(self): return True

    # xdata: [ "a:xx": tgtop, tgtop-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 and len(xargs) == 1:
            tgtop = str(xprs[0])
            return 'jmp*  ' + tgtop
        elif len(xprs) == 2:
            tgtop = str(xprs[0])
            vx = str(xprs[1])
            reg = self.bd.get_register(xargs[2])
            base = self.bd.get_address(xargs[3])
            return str(reg) + ' ' + str(base)
        elif len(xprs) == 3:
            tgtop = str(xprs[0])
            vx = str(xprs[1])
            rng = str(xprs[2])
            reg = self.bd.get_register(xargs[3])
            base = str(self.bd.get_address(xargs[4]))
            if self.app.has_jump_table(base):
                jt = self.app.get_jump_table(base)
                tgts = jt.get_targets()
                ptgts = (vx + ': '
                             +  ','.join([ '(' + str(i) + ':' + str(t) + ')'
                                               for (i,t) in enumerate(tgts) ]))
                return ptgts
            return '++++' + str(rng)  + '  ' + str(reg) + '  ' +  str(base)
        else:
            return 'jmp* ?'

    def get_targets(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 2:
            base = self.bd.get_address(xargs[3])
        elif len(xprs) == 3:
            base = self.bd.get_address(xargs[4])
        else:
            raise UF.CHBError('No jumptable targets available')
        if self.app.has_jump_table(base):
            jt = self.app.get_jump_table(str(base))
            return jt.get_targets()
        raise UF.CHBError('Jumptable not found for base: ' + str(base))

    def get_selector_expr(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 3:
            return xprs[1]
        else:
            raise UF.CHBError('Selector expression not found')

class X86Setcc(X.X86OpcodeBase):

    # tags: [ 'set' + condition code ]
    # args: [ op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self): return [ self.get_operand() ]

    # xdata: [ "a:vx": lhs, rhs ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 2:
            lhs = str(xprs[0])
            rhs = str(xprs[1])
            return lhs + ' = ' + rhs
        else:
            return (self.tags[0] + ':????')


class X86Test(X.X86OpcodeBase):

    # tags: [ 'test' ]
    # args: [ op1, op2 ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_operand_1(self): return self.x86d.get_operand(self.args[0])

    def get_operand_2(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_operand_1(), self.get_operand_2() ]

    # xdata: [ "a:xx" ],[ rhs1, rhs2 ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        rhs1 = str(xprs[0])
        rhs2 = str(xprs[1])
        return 'test ' + rhs1 + ', ' + rhs2

    # --------------------------------------------------------------------------
    # Computes the bit-wise logical AND of first operand (source 1 operand) and
    # the second operand (source 2 operand) and sets the SF, ZF, and PF status
    # flags according to the result. The result is then discarded.
    #
    # Flags affected:
    # The OF and CF flags are set to 0. The SF, ZF, and PF flags are set according
    # to the result
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        op1 = self.get_operand_1()
        op2 = self.get_operand_2()
        opval1 = simstate.get_rhs(iaddr,op1)
        opval2 = simstate.get_rhs(iaddr,op2)
        testresult = opval1.bitwise_and(opval2)
        simstate.clear_flag('OF')
        simstate.clear_flag('CF')
        simstate.update_flag('SF',testresult.is_negative())
        simstate.update_flag('ZF',testresult.is_zero())
        simstate.update_flag('PF',testresult.is_odd_parity())
