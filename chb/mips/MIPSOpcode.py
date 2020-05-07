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

import chb.mips.MIPSOpcodeBase as X

mips_opcode_constructors = {
    'add'  : lambda x: MIPSAdd(*x),
    'and'  : lambda x: MIPSAnd(*x),
    'addiu': lambda x: MIPSAddImmediateUnsigned(*x),
    'addu' : lambda x: MIPSAddUnsigned(*x),
    'andi' : lambda x: MIPSAndImmediate(*x),
    'b'    : lambda x: MIPSBranch(*x),
    'bal'  : lambda x: MIPSBranchLink(*x),
    'bc1f' : lambda x: MIPSBranchFPFalse(*x),
    'bc1t' : lambda x: MIPSBranchFPTrue(*x),
    'beq'  : lambda x: MIPSBranchEqual(*x),
    'bgezal': lambda x: MIPSBranchGEZeroLink(*x),
    'bgez' : lambda x: MIPSBranchGEZero(*x),
    'blez' : lambda x: MIPSBranchLEZero(*x),
    'bltz' : lambda x: MIPSBranchLTZero(*x),
    'bne'  : lambda x: MIPSBranchNotEqual(*x),
    'c.olt.d': lambda x: MIPSFPCompare(*x),
    'hlt'  : lambda x: MIPSHalt(*x),
    'j'    : lambda x: MIPSJump(*x),
    'jal'  : lambda x: MIPSJumpLink(*x),
    'jalr' : lambda x: MIPSJumpLinkRegister(*x),
    'jr'   : lambda x: MIPSJumpRegister(*x),
    'lb'   : lambda x: MIPSLoadByte(*x),
    'lbu'  : lambda x: MIPSLoadByteUnsigned(*x),
    'ldc1' : lambda x: MIPSLoadDoublewordToFP(*x),
    'lhu'  : lambda x: MIPSLoadHalfWordUnsigned(*x),
    'li'   : lambda x: MIPSLoadImmediate(*x),
    'lui'  : lambda x: MIPSLoadUpperImmediate(*x),
    'lw'   : lambda x: MIPSLoadWord(*x),
    'lwl'  : lambda x: MIPSLoadWordLeft(*x),
    'lwr'  : lambda x: MIPSLoadWordRight(*x),
    'mflo' : lambda x: MIPSMoveFromLo(*x),
    'move' : lambda x: MIPSMove(*x),
    'mult' : lambda x: MIPSMultiplyWord(*x),
    'nop'  : lambda x: MIPSNoOperation(*x),
    'nor'  : lambda x: MIPSNor(*x),
    'or'   : lambda x: MIPSOr(*x),
    'ori'  : lambda x: MIPSOrImmediate(*x),
    'ret'  : lambda x: MIPSReturn(*x),
    'sb'   : lambda x: MIPSStoreByte(*x),
    'sh'   : lambda x: MIPSStoreHalfWord(*x),
    'sll'  : lambda x: MIPSShiftLeftLogical(*x),
    'sllv' : lambda x: MIPSShiftLeftLogicalVariable(*x),
    'slt'  : lambda x: MIPSSetLT(*x),
    'slti' : lambda x: MIPSSetLTImmediate(*x),
    'sltiu': lambda x: MIPSSetLTImmediateUnsigned(*x),
    'sltu' : lambda x: MIPSSetLTUnsigned(*x),
    'sra'  : lambda x: MIPSShiftRightArithmetic(*x),
    'srav' : lambda x: MIPSShiftRightArithmeticVariable(*x),
    'srl'  : lambda x: MIPSShiftRightLogical(*x),
    'srlv' : lambda x: MIPSShiftRightLogicalVariable(*x),
    'subu' : lambda x: MIPSSubtractUnsigned(*x),
    'sw'   : lambda x: MIPSStoreWord(*x),
    'swl'  : lambda x: MIPSStoreWordLeft(*x),
    'swr'  : lambda x: MIPSStoreWordRight(*x),
    'xor'  : lambda x: MIPSXor(*x),
    'xori' : lambda x: MIPSXorImmediate(*x)
    }

def derefstr(x): return '*(' + str(x) + ')'

def extract_string_manipulations(c1,c2):
    if c1.is_string_manipulation_condition():
        return (c1.string_condition_to_pretty(),
                    c2.string_condition_to_pretty())
    return (str(c1),str(c2))

def get_mips_opcode(tag,args):
    if tag in mips_opcode_constructors:
        return mips_opcode_constructors[tag](args)
    else:
        return X.MIPSOpcodeBase(*args)

# groups jump table targets
def get_jump_table_targets(tgts):
    result = zip(tgts[::2], tgts[1::2])
    d = {}
    for (i,j) in result:
        d.setdefault(j,[])
        d[j].append(i)
    return d


class MIPSAdd(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rsum = xprs[3]
        rrsum = xprs[4]
        rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
        addxpr = lhs + ' := ' + rsum
        return addxpr

class MIPSAnd(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            rsum = xprs[3]
            rrsum = xprs[4]
            rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
            addxpr = lhs + ' := ' + rsum
            return addxpr
        else:
            return 'pending:' + self.tags[0]


class MIPSAddImmediateUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_strings(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[4]
        if result.is_const():
            c = result.get_const()
            if c.is_intconst():
                cv = c.get_constant().get_value()
                if c.is_string_reference(cv):
                    s = c.get_string_reference(cv)
                    return [ s ]
        return []

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rsum = xprs[3]
        rrsum = xprs[4]
        rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
        addxpr = lhs + ' := ' + rsum
        return addxpr

class MIPSAddUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rsum = xprs[3]
        rrsum = xprs[4]
        rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
        return lhs + ' := ' + rsum

class MIPSAndImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            result = xprs[3]
            rresult = xprs[4]
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return  lhs + ' := ' + result
        else:
            return 'pending:' + self.tags[0]

class MIPSBranch (X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_annotation(self,_):
        return 'goto ' + str(self.get_target())

class MIPSBranchEqual(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[2])        

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[2]
        rresult = xprs[3]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[4], xprs[3] ]

class MIPSBranchFPFalse(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_operands(self): return [ self.get_target() ]

    def get_annotation(self,xdata):
        return 'if ? then goto ' + str(self.get_target())

class MIPSBranchFPTrue(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_operands(self): return [ self.get_target() ]

    def get_annotation(self,xdata):
        return 'if ? then goto ' + str(self.get_target())

class MIPSBranchGEZeroLink(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self,xdata): return self.mipsd.get_mips_operand(self.args[1])

    def has_branch_condition(self): return True

    def get_branch_condition(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[2]

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[3], xprs[2] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[1]
        rresult = xprs[2]
        result = X.simplify_result(xargs[1],xargs[2],result,rresult)
        return 'if ' + result + ' then call ' + str(self.get_target(xdata))

class MIPSBranchGEZero(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[1])

    def has_branch_condition(self): return True

    def get_branch_condition(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[2]

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[3], xprs[2] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[1]
        rresult = xprs[2]
        result = X.simplify_result(xargs[1],xargs[2],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

class MIPSBranchLEZero(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[1])

    def has_branch_condition(self): return True

    def get_branch_condition(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[2]

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[3], xprs[2] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[1]
        rresult = xprs[2]
        result = X.simplify_result(xargs[1],xargs[2],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

class MIPSBranchLTZero(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[1])

    def has_branch_condition(self): return True

    def get_branch_condition(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[2]

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[3], xprs[2] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[1]
        rresult = xprs[2]
        result = X.simplify_result(xargs[1],xargs[2],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

class MIPSBranchNotEqual(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[2])

    def has_branch_condition(self): return True

    def get_branch_condition(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[3]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[2]
        rresult = xprs[3]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[4], xprs[3] ]


class MIPSBranchLink(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_call_instruction(self,xdata): return True

    def get_target(self,xdata): return self.mipsd.get_mips_operand(self.args[0])

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def get_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i] for i in range(0,len(xargs)-1) ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xargs) == 1:
            tgt = self.ixd.get_call_target(xargs[0])
            return 'call ' + str(tgt)
        elif len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            args = [ xprs[i] for i in range(0,len(xargs)-1) ]
            return 'call ' + str(tgt) + '(' + ','.join( [ str(x) for x in args ]) + ')'
        else:
            return 'call ' + str(self.get_target(xdata))
        

class MIPSFPCompare(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_operands(self):
        return [ self.mipsd.get_mips_operand(x) for x in self.args[3:] ]

    def get_annotation(self,xdata):
        return self.tags[0] + ':pending'

class MIPSHalt(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        return 'halt'

class MIPSJump(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_annotation(self,xdata):
        return 'goto ' + str(self.get_target())

class MIPSJumpLink(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_call_instruction(self,xdata): return True

    def get_target(self,xdata): return self.mipsd.get_mips_operand(self.args[0])

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def get_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i] for i in range(0,len(xargs)-1) ]
        return []

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            tgt = self.ixd.get_call_target(xargs[-1])
            args = [ xprs[i] for i in range(0,len(xargs)-1) ]
            return 'call ' + str(tgt) + '(' + ','.join( [ str(x) for x in args ]) + ')'
        if len(xargs) == 1:
            tgt = self.ixd.get_call_target(xargs[0])
            return 'call ' + str(tgt)
        else:
            return 'call ' + str(self.get_target(xdata))

class MIPSJumpLinkRegister(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_call_instruction(self,xdata): return True

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def get_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i] for i in range(0,len(xargs)-1) ]
        return []

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 and len(xargs) == 1:
            tgt = str(xprs[0])
            return 'call* ' + tgt
        if len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            args = [ xprs[i] for i in range(0,len(xargs)-1) ]
            return 'call ' + str(tgt) + '(' + ','.join( [ str(x) for x in args ]) + ')'
        else:
            return '**call: invalid format**'

    def get_target(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 and len(xargs) == 1:
            return str(xprs[0])
        if len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            if tgt.is_app_target():
                return str(tgt.get_address())
            return str(tgt)
        return "**call: invalid format**"


class MIPSJumpRegister(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def get_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i] for i in range(0,len(xargs)-1) ]
        return []

    def is_call_instruction(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return (len(xargs) > len(xprs))

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            args = [ xprs[i] for i in range(0,len(xargs)-1) ]
            return 'call ' + str(tgt) + '(' + ','.join( [ str(x) for x in args ]) + ')'
        tgt = str(xprs[0])
        if len(xtags) > 0 and xtags[0] == 'table':
            tgtd = get_jump_table_targets(xargs[1:])
            tgtstr = ' ('
            for t in sorted(tgtd):
                tgtaddr  = self.mipsd.app.bdictionary.get_address(int(t))
                tgtstr += (str(tgtd[t]) + ':' + str(tgtaddr) + ',')
            tgtstr  += ')'
            jtgts = tgtstr
        else:
            jtgts = ''
        return 'jmp* ' + tgt + '  ' + jtgts

    def get_target(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 and len(xargs) == 1:
            return str(xprs[0])
        if len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            if tgt.is_app_target():
                return str(tgt.get_address())
            return str(tgt)
        return "**call: invalid format**"


class MIPSLoadByte(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSLoadByteUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        if rhs == '?' and len(xprs) == 3:
            rhs = '*(' + str(xprs[2]) + ')'
        return lhs + ' := ' + rhs

class MIPSLoadDoublewordToFP(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSLoadHalfWordUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSLoadImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSLoadUpperImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSLoadWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        if rhs == '?' and len(xprs) == 3:
            rhs = '*(' + str(xprs[2]) + ')'
        return lhs + ' := ' + rhs

class MIPSLoadWordLeft(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSLoadWordRight(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSMoveFromLo(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSMove(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSMultiplyWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        hi = str(xprs[0])
        lo = str(xprs[1])
        result = str(xprs[4])
        rresult = str(xprs[5])
        result = X.simplify_result(xargs[4],xargs[5],result,rresult)
        return '(' + hi + ',' + lo + ') := ' + result

class MIPSNoOperation(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        return ''

class MIPSOr(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[3],xargs[4],result,rresult)
        return lhs + ' := ' + result


class MIPSOrImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[3],xargs[4],result,rresult)
        return lhs + ' := ' + result


class MIPSNor(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[3],xargs[4],result,rresult)
        return lhs + ' := ' + result


class MIPSReturn(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_return_expr(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xargs) == 1:
            return xprs[0]

    def get_annotation(self,xdata):
        rtnxpr = str(self.get_return_expr(xdata))
        rtnxpr = '' if rtnxpr == 'v0' else rtnxpr                         
        return 'return ' + rtnxpr

class MIPSSetLT(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return lhs + ' := 1 if ' + result + ' else 0'
  
class MIPSSetLTImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return lhs + ' := 1 if ' + result + ' else 0'

class MIPSSetLTImmediateUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return lhs + ' := 1 if ' + result + ' else 0'

class MIPSSetLTUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return lhs + ' := 1 if ' + result + ' else 0'

class MIPSShiftLeftLogical(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 3:
            lhs = str(xprs[0])
            result = xprs[2]
            rresult = xprs[3]
            result = X.simplify_result(xargs[2],xargs[3],result,rresult)
            return lhs + ' := ' + result
        else:
            return self.tags[0] + ':???'

class MIPSShiftLeftLogicalVariable(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            rsum = xprs[3]
            rrsum = xprs[4]
            rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
            addxpr = lhs + ' := ' + rsum
            return addxpr
        else:
            return 'pending:' + self.tags[0]

class MIPSShiftRightArithmetic(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 3:
            lhs = str(xprs[0])
            result = xprs[2]
            rresult = xprs[3]
            result = X.simplify_result(xargs[2],xargs[3],result,rresult)
            addxpr = lhs + ' := ' + result
            return addxpr
        else:
            return self.tags[0] + ':???'

class MIPSShiftRightArithmeticVariable(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            rsum = xprs[3]
            rrsum = xprs[4]
            rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
            addxpr = lhs + ' := ' + rsum
            return addxpr
        else:
            return 'pending:' + self.tags[0]

class MIPSShiftRightLogical(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 3:
            lhs = str(xprs[0])
            result = xprs[2]
            rresult = xprs[3]
            result = X.simplify_result(xargs[2],xargs[3],result,rresult)
            addxpr = lhs + ' := ' + result
            return addxpr
        else:
            return self.tags[0] + ':???'

class MIPSShiftRightLogicalVariable(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            rsum = xprs[3]
            rrsum = xprs[4]
            rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
            addxpr = lhs + ' := ' + rsum
            return addxpr
        else:
            return 'pending:' + self.tags[0]

class MIPSStoreByte(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[0].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        return lhs + ' := ' + rhs

class MIPSStoreHalfWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[0].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        if lhs == '?' and len(xprs) == 4:
            lhs = derefstr(xprs[3])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        return lhs + ' := ' + rhs

class MIPSStoreWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[0].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        if lhs == '?' and len(xprs) == 4:
            lhs = derefstr(xprs[3])
        return lhs + ' := ' + rhs

class MIPSStoreWordLeft(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[0].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        return lhs + ' := ' + rhs

class MIPSStoreWordRight(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[0].get_global_variables()

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        return lhs + ' := ' + rhs

class MIPSSubtractUnsigned(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[3],xargs[4],result,rresult)
        return lhs + ' := ' + result

class MIPSXor(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            result = xprs[3]
            rresult = xprs[4]
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return  lhs + ' := ' + result
        else:
            return 'pending:' + self.tags[0]

class MIPSXorImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            result = xprs[3]
            rresult = xprs[4]
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return  lhs + ' := ' + result
        else:
            return 'pending:' + self.tags[0]
