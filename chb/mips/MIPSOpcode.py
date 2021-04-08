# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
import chb.api.LinuxSyscalls as SC

import chb.mips.MIPSOpcodeBase as X
import chb.simulate.SimUtil as SU
import chb.simulate.SimSymbolicValue as SSV
import chb.simulate.SimValue as SV


mips_opcode_constructors = {
    'add'  : lambda x: MIPSAdd(*x),
    'and'  : lambda x: MIPSAnd(*x),
    'addi' : lambda x: MIPSAddImmediate(*x),
    'addiu': lambda x: MIPSAddImmediateUnsigned(*x),
    'addu' : lambda x: MIPSAddUnsigned(*x),
    'andi' : lambda x: MIPSAndImmediate(*x),
    'aui'  : lambda x: MIPSAddUpperImmediate(*x),
    'b'    : lambda x: MIPSBranch(*x),
    'bal'  : lambda x: MIPSBranchLink(*x),
    'bc1f' : lambda x: MIPSBranchFPFalse(*x),
    'bc1t' : lambda x: MIPSBranchFPTrue(*x),
    'beq'  : lambda x: MIPSBranchEqual(*x),
    'beql' : lambda x: MIPSBranchEqualLikely(*x),
    'bgezal': lambda x: MIPSBranchGEZeroLink(*x),
    'bgez' : lambda x: MIPSBranchGEZero(*x),
    'bgezl': lambda x: MIPSBranchGEZeroLikely(*x),
    'bgtz' : lambda x: MIPSBranchGTZero(*x),
    'bgtzl': lambda x: MIPSBranchGTZeroLikely(*x),
    'blez' : lambda x: MIPSBranchLEZero(*x),
    'blezl': lambda x: MIPSBranchLEZeroLikely(*x),
    'bltz' : lambda x: MIPSBranchLTZero(*x),
    'bltzal': lambda x: MIPSBranchLTZeroLink(*x),
    'bltzl': lambda x: MIPSBranchLTZeroLikely(*x),
    'bne'  : lambda x: MIPSBranchNotEqual(*x),
    'bnel' : lambda x: MIPSBranchNotEqualLikely(*x),
    'break': lambda x: MIPSBreak(*x),
    'c.olt.d': lambda x: MIPSFPCompare(*x),
    'clz'  : lambda x: MIPSCountLeadingZeros(*x),
    'div'  : lambda x: MIPSDivideWord(*x),
    'divu' : lambda x: MIPSDivideUnsignedWord(*x),
    'hlt'  : lambda x: MIPSHalt(*x),
    'j'    : lambda x: MIPSJump(*x),
    'jal'  : lambda x: MIPSJumpLink(*x),
    'jalr' : lambda x: MIPSJumpLinkRegister(*x),
    'jr'   : lambda x: MIPSJumpRegister(*x),
    'lb'   : lambda x: MIPSLoadByte(*x),
    'lbu'  : lambda x: MIPSLoadByteUnsigned(*x),
    'ldc1' : lambda x: MIPSLoadDoublewordToFP(*x),
    'lh'   : lambda x: MIPSLoadHalfWord(*x),
    'lhu'  : lambda x: MIPSLoadHalfWordUnsigned(*x),
    'li'   : lambda x: MIPSLoadImmediate(*x),
    'll'   : lambda x: MIPSLoadLinkedWord(*x),
    'lui'  : lambda x: MIPSLoadUpperImmediate(*x),
    'lw'   : lambda x: MIPSLoadWord(*x),
    'lwc1' : lambda x: MIPSLoadWordFP(*x),
    'lwl'  : lambda x: MIPSLoadWordLeft(*x),
    'lwr'  : lambda x: MIPSLoadWordRight(*x),
    'madd' : lambda x: MIPSMultiplyAddWord(*x),
    'maddu': lambda x: MIPSMultiplyAddUnsignedWord(*x),
    'mfc2' : lambda x: MIPSMoveWordFromCoprocessor2(*x),
    'mfhc2': lambda x: MIPSMoveWordFromHighHalfCoprocessor2(*x),
    'mfhi':  lambda x: MIPSMoveFromHi(*x),
    'mflo' : lambda x: MIPSMoveFromLo(*x),
    'move' : lambda x: MIPSMove(*x),
    'movn' : lambda x: MIPSMoveConditionalNotZero(*x),
    'movz' : lambda x: MIPSMoveConditionalZero(*x),
    'mtc2' : lambda x: MIPSMoveWordToCoprocessor2(*x),
    'mthi' : lambda x: MIPSMoveToHi(*x),
    'mtlo' : lambda x: MIPSMoveToLo(*x),
    'mul'  : lambda x: MIPSMultiplyWordToGPR(*x),
    'mult' : lambda x: MIPSMultiplyWord(*x),
    'multu': lambda x: MIPSMultiplyUnsignedWord(*x),
    'nop'  : lambda x: MIPSNoOperation(*x),
    'nor'  : lambda x: MIPSNor(*x),
    'or'   : lambda x: MIPSOr(*x),
    'ori'  : lambda x: MIPSOrImmediate(*x),
    'pref' : lambda x: MIPSPrefetch(*x),
    'sb'   : lambda x: MIPSStoreByte(*x),
    'sc'   : lambda x: MIPSStoreConditionalWord(*x),
    'sdc1' : lambda x: MIPSStoreDoubleWordFromFP(*x),
    'seb'  : lambda x: MIPSSignExtendByte(*x),
    'seh'  : lambda x: MIPSSignExtendHalfword(*x),
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
    'swc1' : lambda x: MIPSStoreWordFromFP(*x),
    'swl'  : lambda x: MIPSStoreWordLeft(*x),
    'swr'  : lambda x: MIPSStoreWordRight(*x),
    'syscall 0': lambda x: MIPSSyscall(*x),
    'teq'  : lambda x: MIPSTrapIfEqual(*x),
    # 'teqi' : lambda x: MIPSTrapIfEqualImmediate(*x),
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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   GPR[rd] <- GPR[rs] and GPR[rt]
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' +&' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        else:
            result = src1val.bitwise_and(src2val)
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,
                            lhs,result,('val(' + str(src1op) + ') = ' + str(src1val)
                                          + ', val(' + str(src2op) + ') = ' + str(src2val)))

class MIPSAddImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_strings(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[4]
        if result.is_const():
            c = result.get_const()
            if c.is_intconst():
                if c.is_string_reference():
                    s = c.get_string_reference()
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

class MIPSAddUpperImmediate(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_strings(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[4]
        if result.is_const():
            c = result.get_const()
            if c.is_intconst():
                if c.is_string_reference():
                    s = c.get_string_reference()
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

class MIPSAddImmediateUnsigned(X.MIPSOpcodeBase):
    """ADDIU rt, rs, immediate

    Programming notes:
    The term 'unsigned' in the instruction name is a misnomer; this operation
    is 32-bit modulo arithmetic that does not trap an overflow. This instruction
    is appropriate for unsigned arithmetic, such as address arithmetic, or
    integer arithmetic environments that ignore overflow, such as C language
    arithmetic.
    """

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_strings(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[4]
        if result.is_const():
            c = result.get_const()
            if c.is_intconst():
                if c.is_string_reference():
                    s = c.get_string_reference()
                    return [ s ]
        return []

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxxx" ] lhs, rs-val, imm-val, result, result-simplified
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rsum = xprs[3]
        rrsum = xprs[4]
        rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
        addxpr = lhs + ' := ' + rsum
        return addxpr

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   temp <- GPR[rs] + sign_extend(immediate)
    #   GPR[rt] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        immval = self.get_imm_operand().to_signed_int()
        imm = SV.mk_simvalue(immval)
        if srcval.is_symbol():
            expr = str(srcval) + ' + ' + str(immval)
            result = SSV.mk_symbol(srcval.get_name() + ': add ' + str(immval))
            # raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        elif srcval.is_address():
            result = srcval.add_offset(immval)
        elif srcval.is_string_address():
            if immval == len(srcval.get_string()):
                result = SSV.mk_string_address('')
            else:
                result = SSV.mk_string_address(srcval.get_string()[immval:])
        else:
            result = srcval.add(imm)
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,
                            lhs,result,'val(' + str(srcop) + ') = ' + str(srcval))


class MIPSAddUnsigned(X.MIPSOpcodeBase):
    """ADDU rd, rs, rt"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxxx" ] lhs, rs-val, rt-val, result, result-simplified
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rsum = xprs[3]
        rrsum = xprs[4]
        rsum = X.simplify_result(xargs[3],xargs[4],rsum,rrsum)
        return lhs + ' := ' + rsum

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   temp <- GPR[rs] + GPR[rt]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src2val.is_symbol():
            result = SSV.mk_symbol(src2val.get_name() + ':add ' + str(src1val))
        elif src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' + ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        elif src2val.is_address() and src1val.is_defined():
            result = src2val.add(src1val)
        elif src1val.is_defined():
            result = src1val.add(src2val)
        else:
            result = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,
                            lhs,result,('val(' + str(src1op) + ') = ' + str(src1val)
                                          + ', val(' + str(src2op) + ') = ' + str(src2val)))


class MIPSAndImmediate(X.MIPSOpcodeBase):
    """ANDI rt, rs, immediate"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxxx" ] lhs, rs-val, imm-val, result, result-simplified
    # --------------------------------------------------------------------------
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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   GPR[rt] <- GPR[rs] and zero_extend(immediate)  (bitwise logical and)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        immval = SV.mk_simvalue(self.get_imm_operand().to_unsigned_int())
        if srcval.is_symbol():
            expr = str(srcval) + ' & ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        elif srcval.is_address():
            expr = str(srcval) + ' & ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        else:
            result = srcval.bitwise_and(immval)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            'val(' + str(srcop) + ') = ' + str(srcval))

class MIPSBranch(X.MIPSOpcodeBase):
    """B offset  (assembly idiom)"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_annotation(self,_):
        return 'goto ' + str(self.get_target())

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset || 0[2])
    #   I+1: PC <- PC + target_offset
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        tgt = SSV.mk_global_address(self.get_target().get_mips_absolute_address_value())
        simstate.increment_program_counter()
        simstate.set_delayed_program_counter(tgt)
        return 'goto ' + str(tgt)


class MIPSBranchEqual(X.MIPSOpcodeBase):
    """BEQ rs, rt, offset"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[2])        

    # --------------------------------------------------------------------------
    # xdata: [ "a:xxxxx" ] rs-val, rt-val, result, result-simplified, negated-result
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[2]
        rresult = xprs[3]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[4], xprs[3] ]

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset || 0[2])
    #          condition <- (GPR[rs] = GPR[rt])
    #   I+1: if condition then
    #          PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if src1val.is_string_address() or src1val.is_address():
            if src2val.is_literal():
                result = SV.simfalse   #  constant string is not NULL
            else:
                result = SV.simUndefinedBool   # no information on string address value
        elif src1val.is_address() and src2val.is_address():
            if src1val.offset_value == src2val.offset_value:
                result = SV.simtrue
            else:
                result = SV.simUndefinedBool
        else:
            result = src1val.is_equal(src2val)
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if result.is_defined():
            simstate.increment_program_counter()
            if result.is_true():
                simstate.set_delayed_program_counter(truetgt)
            else:
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(src1val) + ' == ' + str(src2val)
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        else:
            raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                              'branch-equal condition: ' +
                                              str(src1val) + ' == ' + str(src2val))


class MIPSBranchEqualLikely(X.MIPSOpcodeBase):

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

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset || 0[2])
    #          condition <- (GPR[rs] = GPR[rt])
    #   I+1: if condition then
    #          PC <- PC + target_offset
    #        else
    #          NullifyCurrentInstruction
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if src1val.is_string_address():
            if src2val.is_literal() and src2val.value == 0:
                result = SV.simfalse   #  constant string is not NULL
            else:
                result = SV.simUndefinedBool   # no information on string address value
        else:
            result = src1val.is_equal(src2val)
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if result.is_defined():
            simstate.increment_program_counter()
            if result.is_true():
                simstate.set_delayed_program_counter(truetgt)
            else:
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(src1val) + ' == ' + str(src2val)
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        else:
            raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                              'branch-equal-likely condition: ' +
                                              str(src1val) + ' == ' + str(src2val))

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
        return 'if ' + result + ' then call ' + str(self.get_target())

class MIPSBranchGEZero(X.MIPSOpcodeBase):
    """BGEZ rs, offset"""

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

    # --------------------------------------------------------------------------
    # xdata: [ "a:xxxx" ] rs, result, result-simplified, negated-result
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[1]
        rresult = xprs[2]
        result = X.simplify_result(xargs[1],xargs[2],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:    target_offset <- sign_extend(offset || 0[2])
    #         condition <- GPR[rs] >= 0[GPRLEN]
    #   I+1:  if condition then
    #            PC <- PC + target_offset
    #         endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_non_negative()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' >= 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        elif srcval.is_symbol():
            result = srcval.is_non_negative()
            simstate.increment_program_counter()
            if result.is_defined():
                if result.is_true():
                    simstate.set_delayed_program_counter(truetgt)
                else:
                    simstate.set_delayed_program_counter(falsetgt)
                expr = str(srcval) + ' >= 0'
                return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch greater or equal to zero condition: ' +
                                          str(srcval) + ' >= 0')


class MIPSBranchGEZeroLikely(X.MIPSOpcodeBase):

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[1])

    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_non_negative()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' >= 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        elif srcval.is_symbol():
            result = srcval.is_non_negative()
            simstate.increment_program_counter()
            if result.is_defined():
                if result.is_true():
                    simstate.set_delayed_program_counter(truetgt)
                else:
                    simstate.set_delayed_program_counter(falsetgt)
                expr = str(srcval) + ' >= 0'
                return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch greater or equal to zero condition: ' +
                                          str(srcval) + ' >= 0')


class MIPSBranchGTZero(X.MIPSOpcodeBase):

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: target_offset <- sign_extend(offset || 0[2])
    #      condition <- GPR[rs] > 0[GPRLEN]
    #   I+1: if condition then
    #           PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        tgt = self.get_tgt_offset().get_mips_absolute_address_value()
        truetgt = SSV.mk_global_address(tgt)
        falsetgt = simstate.get_program_counter().add_offset(8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_positive()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' > 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        elif srcval.is_symbol():
            result = srcval.is_positive()
            simstate.increment_program_counter()
            if result.is_defined():
                if result.is_true():
                    simstate.set_delayed_program_counter(truetgt)
                else:
                    simstate.set_delayed_program_counter(falsetgt)
                expr = str(srcval) + ' > 0'
                return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch greater than zero condition: '
                                          + str(srcval) + ' > 0')


class MIPSBranchGTZeroLikely(X.MIPSOpcodeBase):

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: target_offset <- sign_extend(offset || 0[2])
    #      condition <- GPR[rs] <= 0[GPRLEN]
    #   I+1: if condition then
    #           PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        tgt = self.get_tgt_offset().get_mips_absolute_address_value()
        srcval = simstate.get_rhs(iaddr,srcop)
        truetgt = SSV.mk_global_address(tgt)
        falsetgt = simstate.get_program_counter().add_offset(8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_non_positive()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' <= 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        elif srcval.is_symbol():
            result = srcval.is_non_positive()
            simstate.increment_program_counter()
            if result.is_defined():
                if result.is_true():
                    simstate.set_delayed_program_counter(truetgt)
                else:
                    simstate.set_delayed_program_counter(falsetgt)
                expr = str(srcval) + ' <= 0'
                return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch less than or equal to zero condition: ' +
                                          str(srcval) + ' <= 0')

class MIPSBranchLEZeroLikely(X.MIPSOpcodeBase):

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: target_offset <- sign_extend(offset || 0[2])
    #      condition <- GPR[rs] <= 0[GPRLEN]
    #   I+1: if condition then
    #           PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        tgt = self.get_tgt_offset().get_mips_absolute_address_value()
        srcval = simstate.get_rhs(iaddr,srcop)
        truetgt = SSV.mk_global_address(tgt)
        falsetgt = simstate.get_program_counter().add_offset(8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_non_positive()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' <= 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        elif srcval.is_symbol():
            result = srcval.is_non_positive()
            simstate.increment_program_counter()
            if result.is_defined():
                if result.is_true():
                    simstate.set_delayed_program_counter(truetgt)
                else:
                    simstate.set_delayed_program_counter(falsetgt)
                expr = str(srcval) + ' <= 0'
                return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch less than or equal to zero condition (likely): ' +
                                          str(srcval) + ' <= 0')

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:    target_offset <- sign_extend(offset || 0[2])
    #         condition <- GPR[rs] < 0[GPRLEN]
    #   I+1:  if condition then
    #            PC <- PC + target_offset
    #         endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_negative()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' < 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        elif srcval.is_symbol():
            result = srcval.is_negative()
            simstate.increment_program_counter()
            if result.is_true():
                simstate.set_delayed_program_counter(truetgt)
            else:
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' < 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch less than zero condition: ' +
                                          str(srcval) + ' < 0')


class MIPSBranchLTZeroLikely(X.MIPSOpcodeBase):

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

class MIPSBranchLTZeroLink(X.MIPSOpcodeBase):

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: target_offset <- sign_extend(offset || 0[2])
    #      condition <- GPR[rs] < 0[GPRLEN]
    #      GPR[31] <- PC + 8
    #   I+1: if condition then
    #           PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        truetgt = SSV.mk_global_address(self.get_target().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        simstate.registers['ra'] = SSV.mk_global_address(int(iaddr,16)+8)
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.is_negative()
            simstate.increment_program_counter()
            if result:
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' < 0'
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                          'branch less than zero condition: ' +
                                          str(srcval) + ' < 0')


class MIPSBranchNotEqual(X.MIPSOpcodeBase):
    """BNE rs, rt, offset"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_target(self): return self.mipsd.get_mips_operand(self.args[2])

    def has_branch_condition(self): return True

    def get_branch_condition(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[3]

    # --------------------------------------------------------------------------
    # xdata: [ "a:xxxxx" ] rs-val, rt-val, result, result-simplified, negated result
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        result = xprs[2]
        rresult = xprs[3]
        result = X.simplify_result(xargs[2],xargs[3],result,rresult)
        return 'if ' + result + ' then goto ' + str(self.get_target())

    def get_ft_conditions(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[4], xprs[3] ]

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset) || 0[2]
    #        condition <- (GPR[rs] != GPR[rt])
    #   I+1: if condition then
    #          PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if src1val.is_string_address():
            if src2val.is_literal() and src2val.value == 0:
                result = SV.simtrue   #  constant string is not NULL
            else:
                result = SV.simUndefinedBool   # no information on string address value
        elif src1val.is_address():
            if src2val.is_literal() and src2val.value == 0:
                result = SV.simtrue
            elif src2val.is_address():
                result = src1val.is_not_equal(src2val)
            else:
                result = SV.simUndefinedBool
        else:
            result = src1val.is_not_equal(src2val)
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if result.is_defined():
            simstate.increment_program_counter()
            if result.is_true():
                simstate.set_delayed_program_counter(truetgt)
            else:
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(src1val) + ' != ' + str(src2val)
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        else:
            raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                              'branch-not-equal condition: ' +
                                              str(src1val) + ' != ' + str(src2val))


class MIPSBranchNotEqualLikely(X.MIPSOpcodeBase):

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

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_tgt_offset(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset) || 0[2]
    #        condition <- (GPR[rs] != GPR[rt])
    #   I+1: if condition then
    #          PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if src1val.is_string_address():
            if src2val.is_literal() and src2val.value == 0:
                result = SV.simtrue   #  constant string is not NULL
            else:
                result = SV.simUndefinedBool   # no information on string address value
        elif src1val.is_address():
            print('src1val is address')
            if src2val.is_literal() and src2val.value == 0:
                result = SV.simtrue
            elif src2val.is_address():
                print('src2val is address')
                result = src1val.is_not_equal(src2val)
            else:
                result = SV.simUndefinedBool
        else:
            result = src1val.is_not_equal(src2val)
        truetgt = SSV.mk_global_address(self.get_tgt_offset().get_mips_absolute_address_value())
        falsetgt = simstate.get_program_counter().add_offset(8)
        if result.is_defined():
            simstate.increment_program_counter()
            if result.is_true():
                simstate.set_delayed_program_counter(truetgt)
            else:
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(src1val) + ' != ' + str(src2val)
            return SU.simbranch(iaddr,simstate,truetgt,falsetgt,expr,result)
        else:
            raise SU.CHBSimBranchUnknownError(simstate,iaddr,truetgt,falsetgt,
                                              'branch-not-equal-likely condition: ' +
                                              str(src1val) + ' != ' + str(src2val))


class MIPSBranchLink(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_call_instruction(self,xdata): return True

    def get_target(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_call_target(self,xdata): return self.get_target()

    def has_string_arguments(self,xdata):
        args = self.get_arguments(xdata)
        if args:
            return any([ x.is_string_reference() for x in self.get_arguments(xdata) ])
        else:
            False

    def has_stack_arguments(self,xdata):
        args = self.get_arguments(xdata)
        if args:
            return any([ x.is_stack_address() for x in self.get_arguments(xdata) ])
        else:
            False

    def get_annotated_call_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i].to_annotated_value() for i in range(0,len(xargs)-1) ]
        return []

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
            return 'call ' + str(self.get_target())

    def get_tgt_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    I:    target_offset <- sign_extend(offset || 0[2])
    #          GPR[31] <- PC + 8
    #    I+1:  PC <- PC + target_offset
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        tgtaddr = self.get_tgt_operand().get_mips_absolute_address_value()
        tgt = SSV.mk_global_address(tgtaddr)
        simstate.registers['ra'] = SSV.mk_global_address(int(iaddr,16)+8)
        simstate.increment_program_counter()
        simstate.set_delayed_program_counter(tgt)


class MIPSBreak(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_operands(self): return []

    def get_annotation(self,xdata):
        return 'break ' + str(self.args[0])

class MIPSFPCompare(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_operands(self):
        return [ self.mipsd.get_mips_operand(x) for x in self.args[3:] ]

    def get_annotation(self,xdata):
        return self.tags[0] + ':pending'

class MIPSCountLeadingZeros(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        return lhs + ' := count-leading-zeros(' + rhs + ')'

    def get_tgt_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   temp <- 32
    #   for i in 31..0
    #     if GPR[rs][i] = 1 then
    #       temp <- 31 - 1
    #       break
    #     endif
    #   endfor
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_tgt_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        result = srcval.count_leading_zeros()
        result = SV.mk_simvalue(result)
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result)

class MIPSDivideWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhslo = str(xprs[0])
        lhshi = str(xprs[1])
        resultlo = str(xprs[4])
        rresultlo = str(xprs[6])
        resulthi = str(xprs[5])
        rresulthi = str(xprs[7])
        resultlo = X.simplify_result(xargs[4],xargs[6],resultlo,rresultlo)
        resulthi = X.simplify_result(xargs[5],xargs[7],resulthi,rresulthi)
        pdiv = lhslo + ' := ' + resultlo
        pmod = lhshi + ' := ' + resulthi
        return pdiv + '; ' + pmod

    def get_dsthi_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_dstlo_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_rs_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_rt_operand(self): return self.mipsd.get_mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #   q <- GPR[rs][31..0] div GPR[rt][31..0]
    #   LO <- q
    #   r <- GPRprs[p31..0] mod GPR[rt][31..0]
    #   HI <- r
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dsthi = self.get_dsthi_operand()
        dstlo = self.get_dstlo_operand()
        srcrs = self.get_rs_operand()
        srcrt = self.get_rt_operand()
        src1val = simstate.get_rhs(iaddr,srcrs)
        src2val = simstate.get_rhs(iaddr,srcrt)
        if src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' / ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        elif (src1val.is_literal() and src1val.is_defined()
              and src2val.is_literal() and src2val.is_defined()):
            q = src1val.value // src2val.value
            r = src1val.value % src2val.value
            loval = SV.mk_simvalue(q)
            hival = SV.mk_simvalue(r)
        else:
            loval = SV.simUndefinedDW
            hival = SV.simUndefinedDW
        lhslo = simstate.set(iaddr,dstlo,loval)
        lhshi = simstate.set(iaddr,dsthi,hival)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhslo,str(loval),
                            intermediates=str(lhshi) + ' := ' + str(hival))

class MIPSDivideUnsignedWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhslo = str(xprs[0])
        lhshi = str(xprs[1])
        resultlo = str(xprs[4])
        rresultlo = str(xprs[6])
        resulthi = str(xprs[5])
        rresulthi = str(xprs[7])
        resultlo = X.simplify_result(xargs[4],xargs[6],resultlo,rresultlo)
        resulthi = X.simplify_result(xargs[5],xargs[7],resulthi,rresulthi)
        pdiv = lhslo + ' := ' + resultlo
        pmod = lhshi + ' := ' + resulthi
        return pdiv + '; ' + pmod

    def get_dsthi_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_dstlo_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #   q <- (0 || GPR[rs][31..0]) div (0 || GPR[rt][31..0])
    #   r <- (0 || GPR[rs][31..0]) mod (0 || GPR[rt][31..0])
    #   LO <- sign_extend(q[31..0])
    #   HI <- sign_extend(r[31..0])
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dsthi = self.get_dsthi_operand()
        dstlo = self.get_dstlo_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if src1val.is_defined() and src2val.is_defined():
            q = src1val.divu(src2val)
            r = src1val.modu(src2val)
            lhslo = simstate.set(iaddr,dstlo,q)
            lhshi = simstate.set(iaddr,dsthi,r)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhslo,q,
                                intermediates=str(lhshi) + ' := ' + str(r))
        else:
            lhslo = simstate.set(iaddr,dstlo,SV.simUndefinedDW)
            lhshi = simstate.set(iaddr,dsthi,SV.simUndefinedDW)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhslo,SV.simUndefinedDW)


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

    def simulate(self,iaddr,simstate):
        tgtoffset = self.get_target().get_mips_opkind().get_address().get_int()
        tgt = SSV.SimGlobalAddress(SV.SimDoubleWordValue(tgtoffset))
        simstate.increment_program_counter()
        simstate.set_delayed_program_counter(tgt)


class MIPSJumpLink(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_call_instruction(self,xdata): return True

    def get_target(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_call_target(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 and len(xargs) == 1:
            return str(xprs[0])
        if len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            if tgt.is_app_target():
                return str(tgt.get_address())
            return str(tgt)
        return "**call: invalid format**"

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def has_stack_arguments(self,xdata):
        args = self.get_arguments(xdata)
        if args:
            return any([ x.is_stack_address() for x in self.get_arguments(xdata) ])
        else:
            False

    def get_annotated_call_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i].to_annotated_value() for i in range(0,len(xargs)-1) ]
        return []

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
            return 'call ' + str(self.get_target())

    # ----------------------------------------------------------------------
    # Operation:
    #   I: GPR[31] <- PC + 8
    #   I+1: PC <- PC[GPRLEN..28] || instr_index || 0[2]
    # ----------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        tgtaddr = self.get_target().get_mips_absolute_address_value()
        tgt = SSV.mk_global_address(tgtaddr)
        returnaddr = SSV.mk_global_address(int(iaddr,16)+8)
        simstate.registers['ra'] = returnaddr
        simstate.increment_program_counter()
        simstate.set_delayed_program_counter(tgt)
        return SU.simcall(iaddr,simstate,tgt,str(returnaddr))

class MIPSJumpLinkRegister(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_call_instruction(self,xdata): return True

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def has_stack_arguments(self,xdata):
        args = self.get_arguments(xdata)
        if args:
            return any([ x.is_stack_address() for x in self.get_arguments(xdata) ])
        else:
            False

    def get_annotated_call_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i].to_annotated_value() for i in range(0,len(xargs)-1) ]
        return []

    def get_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i] for i in range(0,len(xargs)-1) ]
        return []

    def get_operand_values(self,xdata): return self.get_arguments(xdata)

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

    def get_call_target(self,xdata): return self.get_target(xdata)

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

    def get_tgt_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: temp <- GPR[rs]
    #      GPR[rd] <- PC + 8
    #   I+1: if Config1[CA] = 0 then
    #            PC <- temp
    #        else
    #            PC <- temp[GPRLEN-1..1] || 0
    #            ISAMode <- temp[0]
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        tgtop = self.get_tgt_operand()
        tgtval = simstate.get_rhs(iaddr,tgtop)
        simstate.increment_program_counter()
        returnaddr = int(iaddr,16)+8+simstate.baseaddress
        simstate.registers['ra'] = SSV.mk_global_address(returnaddr)
        if tgtval.is_literal() and tgtval.is_defined():
            tgtval = SSV.mk_global_address(tgtval.value)
            simstate.set_delayed_program_counter(tgtval)
            return SU.simcall(iaddr,simstate,tgtval,hex(returnaddr))
        elif tgtval.is_address():
            simstate.set_delayed_program_counter(tgtval)
            return SU.simcall(iaddr,simstate,tgtval,hex(returnaddr))
        elif tgtval.is_symbolic() and tgtval.is_dynamic_link_symbol():
            simstate.set_delayed_program_counter(tgtval)
            return SU.simcall(iaddr,simstate,tgtval,hex(returnaddr))
        else:
            raise SU.CHBSimCallTargetUnknownError(simstate,iaddr,tgtval,
                                                  'target = ' + str(tgtval))


class MIPSJumpRegister(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def is_return_instruction(self):
        opkind = self.get_src_operand().get_mips_opkind()
        if opkind.is_mips_register():
            return opkind.get_mips_register() == 'ra'
        return False

    def has_string_arguments(self,xdata):
        return any([ x.is_string_reference() for x in self.get_arguments(xdata)  ])

    def has_stack_arguments(self,xdata):
        args = self.get_arguments(xdata)
        if args:
            return any([ x.is_stack_address() for x in self.get_arguments(xdata) ])
        else:
            False

    def get_annotated_call_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            return [ xprs[i].to_annotated_value() for i in range(0,len(xargs)-1) ]
        return []

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
        return 'jmp* ' + tgt + '  ' + jtgts + ' (' + str(self.get_src_operand()) + ')'

    def get_call_target(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 1 and len(xargs) == 1:
            return str(xprs[0])
        if len(xargs) > len(xprs):
            tgt = self.ixd.get_call_target(xargs[-1])
            if tgt.is_app_target():
                return str(tgt.get_address())
            return str(tgt)
        return "**call: invalid format**"

    def get_target(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    I: temp <- GPR[rs]
    #    I+1: if Config1[CA] = 0 then
    #            PC <- temp
    #         else
    #            PC <- temp[GPRLEN-1..1] || 0
    #         endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        simstate.increment_program_counter()
        if srcval.is_symbolic():
            addr = srcval
            simstate.set_delayed_program_counter(addr)
        elif (srcval.is_literal() and srcval.is_defined()
              and srcval.value > simstate.imagebase.get_offset_value()):
            addr = SSV.mk_global_address(srcval.value)
            simstate.set_delayed_program_counter(addr)
        elif srcval.is_literal() and srcval.is_defined():
            addr = SSV.mk_global_address(srcval.value)
            simstate.add_logmsg(iaddr,'Low instruction address: ' + str(addr))
            simstate.set_delayed_program_counter(addr)
        else:
            raise SU.CHBSimJumpTargetUnknownError(simstate,iaddr,srcval,'')
        if str(addr).endswith('ra_in'):
            return 'return'
        else:
            return 'goto ' + str(addr)


class MIPSLoadByte(X.MIPSOpcodeBase):
    """LB rt, offset(base)"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxa" ] lhs, rhs, address
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #   memword <- LoadMemory (CCA, BYTE, pAddr, vAddr, DATA)
    #   byte <- vAddr[1..0] xor BigEndianCPU[2]
    #   GPR[t] <- sign_extend(memwor[7+8*byte..8*byte])
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand(),opsize=1)
        if srcval.is_symbolic():
            raise SU.CHBSimError(simstate,iaddr,'encountered symbolic value in lb: '
                                 + str(srcval)
                                 + ' at address: ' + str(self.get_src_operand()))
        if srcval.is_defined():
            srcval = srcval.sign_extend(4)
        else:
            srcval = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

class MIPSLoadByteUnsigned(X.MIPSOpcodeBase):
    """LBU rt, offset(base)"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[1].get_global_variables()

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxa" ] lhs, rhs, address
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        if rhs == '?' and len(xprs) == 3:
            rhs = '*(' + str(xprs[2]) + ')'
        return lhs + ' := ' + rhs

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2]
    #   memword <- LoadMemory (CCA, BYTE, pAddr, vAddr, DATA)
    #   byte <- vAddr[1..0] xor BigEndianCPU[2]
    #   GPR[rt] <- zero_extend(memword[7+8*byte..8*byte)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand(),opsize=1)
        if srcval.is_literal() and srcval.is_defined():
            srcval = srcval.zero_extend(4)
        else:
            srcval = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

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

class MIPSLoadHalfWord(X.MIPSOpcodeBase):

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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   if vAddr[0] <> 0 then
    #      SignalException(AddressError)
    #   endif
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor (ReverseEndian || 0))
    #   memword <- LoadMemory (CCA, HALFWORD, pAddr, vAddr, DATA)
    #   byte <- vAddr[1..0] xor (BigEndianCPU || 0)
    #   GPR[rt] <- sign_extend(memword[15+8*byte..8*byte])
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop,opsize=2)
        print('srcval = ' + str(srcval))
        if srcval.is_literal():
            if srcval.is_defined():
                srcval = srcval.sign_extend(4)
            else:
                srcval = SV.simUndefinedWord
        elif srcval.is_libc_table_value_deref() and srcval.name == 'ctype_toupper':    # __ctype_toupper table
            srcval = srcval.get_toupper_result()
            simstate.add_logmsg('ctype_toupper: ', str(srcval) + ' (' + str(chr(srcval.value)) + ')')
        elif srcval.is_libc_table_value_deref() and srcval.name == 'ctype_b':
            srcval = srcval.get_b_result()
            simstate.add_logmsg('ctype_b: ', str(srcval) + ' (' + str(chr(srcval.value)) + ')')
        else:
            srcval = SV.simUndefinedWord
        try:
            intermediates = 'val(' + str(simstate.get_lhs(iaddr,srcop)) + ') = ' + str(srcval)
        except:
            intermediates = ''
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval,intermediates)

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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR(base)
    #   if vAddr[0] != 0 then
    #      SignalException(AddressError)
    #   endif
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor (ReverseEndian || 0))
    #   memwork <- LoadMemory (CCA, HALFWORD, pAddr, vAddr, DATA)
    #   byte <- vAddr[1..0] xor (BigEndianCPU)
    #   GPR[rt] <- zero_extend(memword[15+8*byte..8*byte])
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand(),opsize=2)
        src1val = srcval
        if srcval.is_literal() and srcval.is_defined():
            srcval = srcval.zero_extend(4)
        elif srcval.is_symbolic() and srcval.is_libc_table_value() and srcval.name == 'ctype_b':
            srcval = srcval.get_b_result()
            simstate.add_logmsg('ctype_b: ', str(srcval) + ' (' + str(src1val) + ')')
        elif srcval.is_symbolic() and srcval.is_libc_table_value_deref() and srcval.name == 'ctype_toupper':    # __ctype_toupper table
            srcval = srcval.get_toupper_result()
            simstate.add_logmsg('ctype_toupper: ', str(srcval) + ' (' + str(chr(srcval.value)) + ')')
        elif srcval.is_symbolic() and srcval.is_libc_table_value_deref() and srcval.name == 'ctype_b':
            srcval = srcval.get_b_result()
            simstate.add_logmsg('ctype_b: ', str(srcval) + ' (' + str(chr(srcval.value)) + ')')
        elif srcval.is_literal():
            srcval = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

class MIPSLoadImmediate(X.MIPSOpcodeBase):
    """LI rt, immediate (pseudo instruction for ADDIU rt, 0, immediate)"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    # --------------------------------------------------------------------------
    # xdata: [ "a:vx" ] lhs, rhs
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = SV.mk_simvalue(srcop.get_value())
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)


class MIPSLoadUpperImmediate(X.MIPSOpcodeBase):
    """LUI rt, immediate"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    # --------------------------------------------------------------------------
    # xdata: [ "a:vx" ] lhs, rhs
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.xprdata
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GPR[rt] <- immediate || 0[16]
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = srcop.to_unsigned_int()
        result = SV.mk_simvalue(256 * 256 * srcval)
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,'')


class MIPSLoadWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[1] ]

    def get_load_address(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[2]

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

    def is_restore_register(self):
        return (self.get_dst_operand().is_mips_register()
                and self.get_src_operand().is_mips_indirect_register_with_reg('sp'))

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   if vAddr[1..0] <> a[2] then
    #      SignalException(AddressError)
    #   endif
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   memword <- LoadMemory (CCA, WORD, pAddr, vAddr, DATA)
    #   GPR[rt] <- memword
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        try:
            intermediates = 'val(' + str(simstate.get_lhs(iaddr,srcop)) + ') = ' + str(srcval)
        except:
            intermediates = ''
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval,intermediates)

class MIPSLoadWordFP(X.MIPSOpcodeBase):

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

class MIPSLoadLinkedWord(X.MIPSOpcodeBase):

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
    """LWL rt, offset(base)"""

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

    # --------------------------------------------------------------------------
    # xdata [ "a:vxa" ] lhs, rhs, address
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #   if BigEndianMem = 0 then
    #      pAddr <- pAddr[PSIZE-1..2] || 0[2]
    #   endif
    #   byte <- vAddr[1..0] xor BigEndianCPU[2]
    #   memword <- LoadMemory (CCA, byte, pAdr, vAddr, DATA)
    #   temp <- memword[7+8*byte..0] || GPR[rt][23-8*byte..0]
    #   GPR[rt] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        srclocation = simstate.get_lhs(iaddr,srcop)
        if srclocation.is_memory_location():
            if srclocation.is_global_location():
                srcaddress = srclocation.get_address()
                alignment = srcaddress.get_alignment()
            elif srclocation.is_stack_location():
                srcaddress = srclocation.get_address()
                alignment = srcaddress.get_offset_value() % 4
            else:
                raise SU.CHBSimError(simstate,iaddr,
                                     'Load-word-left source is not a memory location: '
                                     + str(srclocation))
        else:
            raise SU.CHBSimError(simstate,iaddr,
                                 'Load-word-left source is not a memory location: '
                                 + str(srclocation))
        dstop = self.get_dst_operand()
        dstvalue = simstate.get_rhs(iaddr,dstop)
        if dstvalue.is_address():
            dstvalue = SV.simUndefinedDW
        # bytes are set in the destination value with b1 = lsf byte, etc.
        if simstate.bigendian:
            if alignment == 0:
                dstval = simstate.get_rhs(iaddr,srcop)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 1:   # set byte1, byte2, byte3
                b4 = simstate.get_memval(iaddr,srcaddress,1)
                b3 = simstate.get_memval(iaddr,srcaddress.add_offset(1),1)
                b2 = simstate.get_memval(iaddr,srcaddress.add_offset(2),1)
                dstval = dstvalue.set_byte2(b2).set_byte3(b3).set_byte4(b4)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 2:   # set byte1, byte2
                b4 = simstate.get_memval(iaddr,srcaddress,1)
                b3 = simstate.get_memval(iaddr,srcaddress.add_offset(1),1)
                dstval = dstvalue.set_byte3(b3).set_byte4(b4)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 3:   # set byte1
                b4 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte4(b4)
                lhs = simstate.set(iaddr,dstop,dstval)
            else: pass
        else:
            if alignment == 0:     # set byte 1
                b1 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte1(b1)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 1:   # set byte1, byte2
                b1 = simstate.get_memval(iaddr,srcaddress.add_offset(-1),1)
                b2 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte1(b1).set_byte2(b2)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 2:   # set byte1, byte2, byte3
                b1 = simstate.get_memval(iaddr,srcaddress-2,1)
                b2 = simstate.get_memval(iaddr,srcaddress-1,1)
                b3 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte1(b1).set_byte(b2).set_byte(b3)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 3:
                dstval = simstate.get_rhs(iaddr,srcop)
                lhs = simstate.set(iaddr,dstop,dstval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,dstval)


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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    vAddr <- sign_extend(offset) + GPR(base)
    #    (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #    pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #    if BigEndianMem = 0 then
    #       pAddr <- pAddr[PSIZE-1..2] || 0[2]
    #    endif
    #    byte <- vAddr[1..0] xor BigEndianCPU[2]
    #    memword <- LoadMemory (CCA, byte, pAddr, vAddr, DATA)
    #    temp <- memword[31..32-8*byte] || GPR[rt][31-8*byte..0]
    #    GPR[rt] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        srclocation = simstate.get_lhs(iaddr,srcop)
        if srclocation.is_memory_location():
            if srclocation.is_global_location():
                srcaddress = srclocation.get_address()
                alignment = srcaddress.get_offset_value() % 4
            elif srclocation.is_stack_location():
                srcaddress = srclocation.get_address()
                alignment = srcaddress.get_offset_value() % 4
            else:
                raise SU.CHBSimError(simstate,iaddr,
                                     'Load-word-right source is not a memory location: '
                                     + str(srclocation))
        else:
            raise SU.CHBSimError(simstate,iaddr,
                                 'Load-word-right source is not a memory location: '
                                 + str(srclocation))
        dstop = self.get_dst_operand()
        dstvalue = simstate.get_rhs(iaddr,dstop)
        if dstvalue.is_address():
            dstvalue = SV.simUndefinedDW
        # bytes are set in the destination value with b1 = lsf byte, etc.
        if simstate.bigendian:
            if alignment == 0:
                b1 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte1(b1)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 1:
                b1 = simstate.get_memval(iaddr,srcaddress,1)
                b2 = simstate.get_memval(iaddr,srcaddress-1,1)
                dstval = dstvalue.set_byte1(b1).set_byte2(b2)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 2:
                b1 = simstate.get_memval(iaddr,srcaddress,1)
                b2 = simstate.get_memval(iaddr,srcaddress-1,1)
                b3 = simstate.get_memval(iaddr,srcaddress-2,1)
                dstval = dstvalue.set_byte1(b1).set_byte2(b2).set_byte3(b3)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 3:
                dstval = simstate.get_rhs(iaddr,srcop)
                lhs = simstate.set(iaddr,dstop,dstval)
            else: pass
        else:
            if alignment == 0:
                dstval = simstate.get_rhs(iaddr,srcop)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 1:
                b3 = simstate.get_memval(iaddr,srcaddress.add_offset(-2),1)
                b2 = simstate.get_memval(iaddr,srcaddress.add_offset(-1),1)
                b1 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte1(b1).set_byte2(b2).set_byte3(b3)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 2:
                b2 = simstate.get_memval(iaddr,srcaddress.add_offset(-1),1)
                b1 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte2(b2).set_byte1(b1)
                lhs = simstate.set(iaddr,dstop,dstval)
            elif alignment == 3:
                byte4 = simstate.get_memval(iaddr,srcaddress,1)
                dstval = dstvalue.set_byte4(byte4)
                lhs = simstate.set(iaddr,dstop,dstval)
            else: pass
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,dstval)


class MIPSMoveWordFromCoprocessor2(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        return lhs + ' := word from coprocessor 2'

class MIPSMoveWordFromHighHalfCoprocessor2(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        return lhs + ' := word from high half coprocessor 2'

class MIPSMoveWordToCoprocessor2(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        rhs = str(xprs[0])
        return Coprocessor2[reg] + " := " + rhs

class MIPSMoveFromHi(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GPR[rd] <- HI
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

class MIPSMoveFromLo(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GPR[rd] <- LO
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)


class MIPSMoveToLo(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        return lhs + ' := ' + rhs

class MIPSMoveToHi(X.MIPSOpcodeBase):

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

class MIPSMoveConditionalNotZero(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xata.get_xprdata()
        return [ xprs[1] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        cond = str(xprs[2])
        ccond = str(xprs[3])
        cond = X.simplify_result(xargs[2],xargs[3],cond,ccond)
        return 'if ' + cond + ' then ' + lhs + ' := ' + rhs

    def get_con_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])


    # --------------------------------------------------------------------------
    # Operation:
    #   if GPR[rt] <> 0 then
    #       GPR[rd] <- GPR[rs]
    #   endif
    # ---------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        conop = self.get_con_operand()
        conval = simstate.get_rhs(iaddr,conop)
        if conval.is_defined() and conval.is_literal():
            if conval.value != 0:
                dstop = self.get_dst_operand()
                srcop = self.get_src_operand()
                srcval = simstate.get_rhs(iaddr,srcop)
                lhs = simstate.set(iaddr,dstop,srcval)
                result = SU.simassign(iaddr,simstate,lhs,srcval)
            else:
                result = 'nop'
        else:
            result = '?'
        simstate.increment_program_counter()
        return result

class MIPSMoveConditionalZero(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xata.get_xprdata()
        return [ xprs[1] ]

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        cond = str(xprs[2])
        ccond = str(xprs[3])
        cond = X.simplify_result(xargs[2],xargs[3],cond,ccond)
        return 'if ' + cond + ' then ' + lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_test_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    if GPR[rt] = 0 then
    #       GPR[rd] <- GPR[rs]
    #    endif
    # ---------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        testop = self.get_test_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        testval = simstate.get_rhs(iaddr,testop)
        if testval.is_literal() and testval.is_defined():
            if testval.value == 0:
                lhs = simstate.set(iaddr,dstop,srcval)
                simstate.increment_program_counter()
                return SU.simassign(iaddr,simstate,lhs,srcval)
            else:
                simstate.increment_program_counter()
                return 'nop'
        else:
            simstate.increment_program_counter()
            return '?'

class MIPSMultiplyAddUnsignedWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        hi = str(xprs[0])
        lo = str(xprs[1])
        result = str(xprs[6])
        rresult = str(xprs[7])
        result = X.simplify_result(xargs[6],xargs[7],result,rresult)
        return '(' + hi + ',' + lo + ') := ' + result

class MIPSMultiplyAddWord(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        hi = str(xprs[0])
        lo = str(xprs[1])
        result = str(xprs[6])
        rresult = str(xprs[7])
        result = X.simplify_result(xargs[6],xargs[7],result,rresult)
        return '(' + hi + ',' + lo + ') := ' + result

class MIPSMultiplyUnsignedWord(X.MIPSOpcodeBase):

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

    def get_dstlo_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dsthi_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #    prod <- (0 || GPR[rs][31..0]) . (0 || GPR[rt][31..0])
    #    LO <- prod[31..0]
    #    HI <- prod[63..32]
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstlo = self.get_dstlo_operand()
        dsthi = self.get_dsthi_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' * ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        elif (src1val.is_literal() and src1val.is_defined()
              and src2val.is_literal() and src2val.is_defined()):
            p = src1val.value * src2val.value
            loval = SV.mk_simvalue(p % (SU.max32 + 1))
            hival = SV.mk_simvalue(p >> 32)
        else:
            loval = SV.simUndefinedDW
            hival = SV.simUndefinedDW
        lhslo = simstate.set(iaddr,dstlo,loval)
        lhshi = simstate.set(iaddr,dsthi,hival)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhslo,str(loval),
                            intermediates=str(lhshi) + ' := ' + str(hival))

class MIPSMultiplyWordToGPR(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 0:
            lhs = str(xprs[0])
            result = str(xprs[3])
            rresult = str(xprs[4])
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return (lhs + ' := ' + result)
        else:
            return 'mul pending'

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #    temp <- GPR[rs] * GPR[rt]
    #    GPR[rd] <- temp[31..0]
    #    HI <- UNPREDICTABLE
    #    LO <- UNPREDICTABLE
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' * ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        else:
            if (src1val.is_literal() and src1val.is_defined()
                and src2val.is_literal() and src2val.is_defined()):
                result = SV.mk_simvalue(src1val.value * src2val.value)
            else:
                raise SU.CHBSimError(simstate,iaddr,'mul undefined: '
                                     + str(src1op) + ':' + str(src1val) + ', '
                                     + str(src2op) + ':' + str(src2val))
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,str(result),
                            intermediates=str(lhs) + ' := ' + str(src1val) + ' * '
                            + str(src2val))

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

    def get_dstlo_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dsthi_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #    prod = GPR[rs][31..0] . GPR[rt][31..0]
    #    lo <- prod[31..0]
    #    hi <- prod[63..32]
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dsthi = self.get_dsthi_operand()
        dstlo = self.get_dstlo_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_defined() and src2val.is_defined():
            p = src1val.value * src2val.value
            loval = p % (SU.max32 + 1)
            hival = p >> 32
            lhslo = simstate.set(iaddr,dstlo,SV.mk_simvalue(loval))
            lhshi = simstate.set(iaddr,dsthi,SV.mk_simvalue(hival))
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhslo,str(loval),
                                intermediates=str(lhshi) + ' := ' + str(hival))
        else:
            lhslo = simstate.set(iaddr,dstlo,SV.simUndefinedDW)
            lhshi = simstate.set(iaddr,dsthi,SV.simUndefinedDW)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhslo,SV.simUndefinedDW)

class MIPSNoOperation(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        return ''

    def simulate(self,iaddr,simstate):
        simstate.increment_program_counter()
        return ''

class MIPSOr(X.MIPSOpcodeBase):
    """OR rd, rs, rt"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxxx" ] lhs, rs-val, rt-val, result, result-simplified
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        result = xprs[3]
        rresult = xprs[4]
        result = X.simplify_result(xargs[3],xargs[4],result,rresult)
        return lhs + ' := ' + result

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GRP[rd] <- GPR[rs] or GPR[rt]  (bitwise logical or)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if (src1val.is_literal() and src1val.is_defined()
            and src2val.is_literal() and src2val.is_defined()):
            result = src1val.bitwise_or(src2val)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' | ' + str(src2val))
        elif (src1val.is_symbol() and src2val.is_literal() and src2val.is_defined()):
            result = SSV.mk_symbol(src1val.get_name() + ' | ' + str(sr2val))
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' | ' + str(src2val))
        elif (src1val.is_literal() and src1val.is_defined() and src2val.is_symbol()):
            result = SSV.mk_symbol(str(src2val) + ' | ' + src2val.get_name())
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' | ' + str(src2val))
        else:
            result = SV.simUndefinedDW
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' | ' + str(src2val))

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    GPR[rt] <- GPR[rs] or zero_extend(immediate)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        immval = self.get_imm_operand().get_mips_opkind().to_unsigned_int()
        imm = SV.SimDoubleWordValue(immval)
        if srcval.is_symbolic() and srcval.is_symbol():
            expr = str(srcval) + ' | ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        result = srcval.bitwise_or(imm)
        lhs = simstate.set(iaddr,self.get_dst_operand(),result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            str(srcval) + ' | ' + str(immval))


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

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GRP[rd] <- GPR[rs] nor GPR[rt]  (bitwise logical not or)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if (src1val.is_literal() and src1val.is_defined()
            and src2val.is_literal() and src2val.is_defined()):
            result = src1val.bitwise_nor(src2val)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' nor ' + str(src2val))
        elif (src1val.is_symbol() and src2val.is_literal() and src2val.is_defined()):
            result = SSV.mk_symbol(src1val.get_name() + ' nor ' + str(sr2val))
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' nor ' + str(src2val))
        elif (src1val.is_literal() and src1val.is_defined() and src2val.is_symbol()):
            result = SSV.mk_symbol(str(src2val) + ' nor ' + src2val.get_name())
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' nor ' + str(src2val))
        else:
            result = SV.simUndefinedDW
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' nor ' + str(src2val))


class MIPSPrefetch(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        addr = str(xprs[0])
        return 'prefetch ' + addr

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

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   if GPR[rs] < GPR[rt] then
    #      GPR[rd] <- 0[GPRLEN-1] || 1
    #   else
    #      GPR[rd] <- 0[GPRLEN]
    #   endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_symbol() or src2val.is_symbol():
            conditional = str(src1val) + ' < ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,conditional)
        if src1val.is_defined() and src2val.is_defined():
            if src1val.to_signed_int() < src2val.to_signed_int():
                result = SV.simOne
            else:
                result = SV.simZero
        else:
            result = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            str(src1val) + ' < ' + str(src2val))

  
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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    if GPR[rs] < sign_extend(immediate) then
    #       GPR[rd] <- 0[GPRLEN-1] || 1
    #    else
    #       GPR[rd] <- 0
    #    endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        immval = self.get_imm_operand().get_mips_opkind().get_value()
        dstop = self.get_dst_operand()
        if srcval.is_symbol():
            conditional = str(srcval) + ' < ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,conditional)
        if srcval.is_defined():
            if srcval.to_signed_int() < immval:
                result = SV.simOne
            else:
                result = SV.simZero
        else:
            result = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            str(srcval) + ' < ' + str(immval))

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    if (0 || GPR[rs]) < (0 || sign_extend(immediate)) then
    #       GPR[rd] <- 0[GPRLEN-1] || 1
    #    else
    #       GPR[rd] <- 0[GPRLEN]
    #    endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        immval = self.get_imm_operand().get_mips_opkind().get_value()
        if srcval.is_defined():
            if srcval.to_unsigned_int() < immval:
                result = 1
            else:
                result = 0
            result = SV.SimDoubleWordValue(result)
        else:
            result = SV.simUndefinedDW
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            str(srcval) + ' < ' + str(immval))

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

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   if (0 || GPR[rs]) < (0 || GPR[rt]) then
    #     GPR[rd] <- 0[GPRLEN-1] || 1
    #   else
    #     GPR[rd] <- 0[GPRLEN]
    #   endif
    # ---------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if src1val.is_symbol() or src2val.is_symbol():
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,str(src1val) + ' < ' + str(src2val))
        elif src1val.is_address() and src2val.is_address():
            if src1val.get_offset_value() < src2val.get_offset_value():
                result = 1
            else:
                result = 0
            result = SV.SimDoubleWordValue(result)
        elif src1val.is_defined() and src2val.is_defined():
            if src1val.to_unsigned_int() < src2val.to_unsigned_int():
                result = 1
            else:
                result = 0
            result = SV.SimDoubleWordValue(result)
        else:
            result = SV.simUndefinedDW
        simstate.set(iaddr,self.get_dst_operand(),result)
        simstate.increment_program_counter()

class MIPSShiftLeftLogical(X.MIPSOpcodeBase):
    """SLL rd, rt, sa"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxx" ] lhs, rd-val, result, result-simplified
    # --------------------------------------------------------------------------
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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   s <- sa
    #   temp <- GPR[rt][31-s..0] || 0[s]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        immval = self.get_imm_operand().get_mips_opkind().to_unsigned_int()
        if srcval.is_literal() and srcval.is_defined():
            result = srcval.bitwise_sll(immval)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                '(val(' + str(srcop) + ') = ' + str(srcval))
        elif srcval.is_symbol():
            result = SSV.mk_symbol(srcval.get_name() + ':shifted left by 2')
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                '(val(' + str(srcop) + ') = ' + str(srcval))
        else:
            expr = str(srcval) + ' << ' + str(immval) + ' (val(' + str(srcop) + '))'
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)


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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])


    # --------------------------------------------------------------------------
    # Operation:
    #   s <- GPR[rs][4..0]
    #   temp <- GPR[rt][31-s..0] || 0[s]
    #   GPR[rd] <- temp
    # ---------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if (src1val.is_literal() and src1val.is_defined()
            and src2val.is_literal() and src2val.is_defined()):
            result = src1val.bitwise_sll(src2val.value)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' << ' + str(src2val))
        elif (src1val.is_symbol() and src2val.is_literal() and src2val.is_defined()):
            result = SSV.mk_symbol(src1val.get_name() + ':shifted left by ' + str(src2val))
            lhs = simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' << ' + str(src2val))
        else:
            expr = str(src1val) + ' << ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)

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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   s <- sa
    #   temp <- (GPR[rt][31](s) || GPR[rt][31..s]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        immval = self.get_imm_operand().get_mips_opkind().to_unsigned_int()
        result = srcval.bitwise_sra(immval)
        lhs = simstate.set(iaddr,dstop,result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            str(srcval) + ' >> ' + str(immval))

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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   s <- GPR[rs][4..0]
    #   temp <- (GPR[rt][31])^s || GPR[rt][31..6]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src2val.is_literal() and src2val.is_defined():
            src2val = src2val.value % 32
            result = src1val.bitwise_sra(src2val)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' >> ' + str(src2val))
        else:
            raise SU.CHBSimValueUndefinedError('Value undefined: ' + str(src2val))


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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   s <- sa
    #   temp <- 0[s] || GPR[rt][31..s]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        immval = self.get_imm_operand().get_mips_opkind().to_unsigned_int()
        if srcval.is_symbol():
            expr = str(srcval) + ' >> ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        elif srcval.is_address():
            expr = str(srcval) + ' >> ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        else:
            result = srcval.bitwise_srl(immval)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(srcval) + ' >> ' + str(immval))


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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   s <- GPR[rs][4..0]
    #   temp <- 0[s] || GPR[rt][31..s]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if (src1val.is_literal() and src1val.is_defined()
            and src2val.is_literal() and src2val.is_defined()):
            result = src1val.bitwise_srl(src2val.value)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' >> ' + str(src2val))
        elif (src1val.is_symbol() or src2val.is_symbol()):
            expr = str(src1val) + ' >> ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        else:
            result = SV.simUndefinedDW
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' >> ' + str(src2val))

class MIPSSignExtendByte(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if xprs:
            lhs = str(xprs[0])
            rhs = xprs[1]
            rrhs = xprs[2]
            rrhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
            return lhs + ' := ' + rrhs
        else:
            return 'pending:' + self.tags[0]

class MIPSSignExtendHalfword(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if xprs:
            lhs = str(xprs[0])
            rhs = xprs[1]
            rrhs = xprs[2]
            rrhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
            return lhs + ' := ' + rrhs
        else:
            return 'pending:' + self.tags[0]


class MIPSStoreByte(X.MIPSOpcodeBase):
    """SB rt, offset(base)"""

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

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxa" ] lhs, memval, memval-simplified, address
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        return lhs + ' := ' + rhs

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR(base)
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #   bytesel <- vAddr[1..] xor BigEndianCPU[2]
    #   dataword <- GPR[rt][31-8*bytesel..0] || 0[8*bytesel]
    #   StoreMemory (CCA, BYTE, dataword, pAddr, vAddr, DATA)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,self.get_src_operand(),opsize=1)
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    vAddr <- sign_extend(offset) + GPR[base]
    #    if vAddr[0] != 0 then
    #       SignalException(AddressError)
    #    endif
    #    (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    #    pAddr <- pAddr[PSIZE-1..2] || (pAddr1[1..0] xor (ReverseEndian || 0))
    #    bytesel <- vAddr1[1..0] xor (BigEndianCPU || 0)
    #    dataword <- GPR[rt][31-8*bytesel..0] || 0[8*bytesel]
    #    StoreMemory (CCA, HALFWORD, dataword, pAddr, vAddr, DATA)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop,opsize=2)
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)

class MIPSStoreConditionalWord(X.MIPSOpcodeBase):

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

class MIPSStoreWord(X.MIPSOpcodeBase):
    """SW rt, offset(base)"""

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[2] ]

    def get_global_variables(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return xprs[0].get_global_variables()

    # --------------------------------------------------------------------------
    # xdata: [ "a:vxxa" ] lhs, rhs, rhs-simplified, dst address
    # --------------------------------------------------------------------------
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[1])
        rrhs = str(xprs[2])
        rhs = X.simplify_result(xargs[1],xargs[2],rhs,rrhs)
        if lhs == '?' and len(xprs) == 4:
            lhs = derefstr(xprs[3])
        return lhs + ' := ' + rhs

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   memory[base+offset] <- rt
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        srcop = self.get_src_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        lhs = simstate.set(iaddr,dstop,srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,srcval)


class MIPSStoreDoubleWordFromFP(X.MIPSOpcodeBase):

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
        if lhs == '?' and len(xprs) == 3:
            lhs = derefstr(xprs[2])
        return lhs + ' := ' + rhs

class MIPSStoreWordFromFP(X.MIPSOpcodeBase):

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
        if lhs == '?' and len(xprs) == 3:
            lhs = derefstr(xprs[2])
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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    vAddr <- sign_extend(offset) + GPR[base]
    #    (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    #    pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #    if BigEndianMem = 0 then
    #       pAddr <- pAddr[PSIZE-1..2] || 0[2]
    #    endif
    #    byte <- vAddr[1..0] xor BigEndianCPU[2]
    #    dataword <- 0[24-8*byte] || GPR[rt][31..24-8*byte]
    #    StoreMemory (CCA, byte, dataword, pAddr, vAddr, DATA)
    #
    # Note: combining it with 0 seems incorrect, and contradicts the figure in
    #  the documentation; we assume the partial value from the register is
    #  merged with the contents, rather than combined with 0. Perhaps the
    #  merging is accomplished by the StoreMemory operation.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        dstlocation = simstate.get_lhs(iaddr,self.get_dst_operand())
        if dstlocation.is_memory_location():
            if dstlocation.is_global_location():
                dstaddr = dstlocation.get_address()
                alignment = dstaddr.get_offset_value() % 4
            elif dstlocation.is_stack_location():
                dstaddr = dstlocation.get_address()
                alignment = dstaddr.get_offset_value() % 4
            else:
                raise SU.CHBSimError(simstate,iaddr,
                                     'Store-word-left destination if not a memory location: '
                                     + str(dstlocation))
        else:
            raise SU.CHBSimError(simstate,iaddr,
                                 'Store-word-left destination is not a memory location: '
                                 + str(dstlocation))
        lhss = []
        if simstate.bigendian:
            if alignment == 0:
                lhss.append(simstate.set(iaddr,self.get_dst_operand(),srcval))
            elif alignment == 1:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_third_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr+1,srcval.get_snd_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr+2,srcval.get_low_byte()))
            elif alignment == 2:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_snd_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr+1,srcval.get_low_byte()))
            elif alignment == 3:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_low_byte()))
            else:
                pass
        else:
            if alignment == 0:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
            elif alignment == 1:
                lhss.append(simstate.set_memval(iaddr,dstaddr-1,srcval.get_third_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
            elif alignment == 2:
                lhss.append(simstate.set_memval(iaddr,dstaddr-2,srcval.get_snd_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr-1,srcval.get_third_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_hight_byte()))
            elif alignment == 3:
                lhss.append(simstate.set(iaddr,self.get_dst_operand(),srcval))
            else: pass
        simstate.increment_program_counter()
        return "assign " + ','.join(str(lhs) for lhs in lhss)


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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    vAddr <- sign_extend(offset) + GPR[base]
    #    (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    #    pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #    if BigEndianMem = 0 then
    #       pAddr <- pAddr[PSIZE-1..2] || 0[2]
    #    endif
    #    byte <- vAddr[1..0] xor BigEndianCPU[2]
    #    dataword <- GPR[rt][31-8*byte] || 0[8*byte]
    #    StoreMemory (CCA, WORD-byte, dataword, pAddr, vAddr, DATA)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        dstlocation = simstate.get_lhs(iaddr,self.get_dst_operand())
        if dstlocation.is_memory_location():
            if dstlocation.is_global_location():
                dstaddr = dstlocation.get_address()
                alignment = dstaddr.get_offset_value() % 4
            elif dstlocation.is_stack_location():
                dstaddr = dstlocation.get_address()
                alignment = dstaddr.get_offset_value() % 4
            else:
                raise SU.CHBSimError(simstate,iaddr,
                                     'Store-word-right destination is not a memory location: '
                                     + str(dstlocation))
        else:
            raise SU.CHBSimError(simstate,iaddr,
                                 'Store-word-right destination is not a memory location: '
                                 + str(dstlocation))
        lhss = []
        if simstate.bigendian:
            if alignment == 0:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
            elif alignment == 1:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr+1,srcval.get_third_byte()))
            elif alignment == 2:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr+1,srcval.get_third_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr+2,srcval.get_snd_byte()))
            elif alignment == 3:
                lhss.append(simstate.set(iaddr,self.get_dst_operand(),srcval))
            else:
                pass
        else:
            if alignment == 0:
                lhss.append(simstate.set(iaddr,self.get_dst_operand(),srcval))
            elif alignment == 1:
                lhss.append(simstate.set_memval(iaddr,dstaddr-2,srcval.get_snd_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr-1,srcval.get_third_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
            elif alignment == 2:
                lhs.append(simstate.set_memval(iaddr,dstaddr-1,srcval.get_third_byte()))
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
            elif alignment == 1:
                lhss.append(simstate.set_memval(iaddr,dstaddr,srcval.get_high_byte()))
            else:
                pass
        simstate.increment_program_counter()
        return 'assign ' + ','.join(str(lhs) for lhs in lhss)

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

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   temp <- GPR[rs] - GPR[rt]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' - ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        if src1val.is_string_address() and src2val.is_string_address():
            result = src2val.get_string().find(src1val.get_string())
            result = SV.mk_simvalue(result)
        else:
            result = src1val.subu(src2val)
        lhs = simstate.set(iaddr,self.get_dst_operand(),result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            ('val(' + str(src1op) + ') = ' + str(src1val)
                             + ', val(' + str(src2op) + ') = ' + str(src2val)))


class MIPSSyscall(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_operands(self): return []

    def get_code(self): return int(self.args[0])

    def get_mnemonic(self): return self.tags[0]

    def get_arguments(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 1:
            return [ xprs[i] for i in range(1,len(xargs)-1) ]
        return []

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if not xprs:
            return 'linux-systemcall'
        rhs = str(xprs[0])
        args = self.get_arguments(xdata)
        if args:
            args = '(' + ','.join([ str(a) for a in args ]) + ')'
        else:
            args = ''
        if rhs.startswith('0x'):
            syscallnumber = int(rhs,16)
            syscallfunction = SC.get_linux_syscall(syscallnumber)
            return 'linux-systemcall:' + syscallfunction + args
        else:
            return 'linux-systemcall(' + rhs + ')'

    # --------------------------------------------------------------------------
    # Operation:
    #    SignalException(SystemCall)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        syscallindex = simstate.registers['v0']
        if syscallindex.is_literal() and syscallindex.is_defined():
            raise SU.CHBSimSystemCallException(simstate,iaddr,syscallindex.value)
        else:
            raise SU.CHBSimCallTargetUnknownError(simstate,iaddr,syscallindex,
                                                  'syscall = ' + str(syscallindex))

class MIPSTrapIfEqual(X.MIPSOpcodeBase):

    def __init__(self,mipsd,index,tags,args):
        X.MIPSOpcodeBase.__init__(self,mipsd,index,tags,args)

    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) > 4:
            rhs1 = str(xprs[0])
            rhs2 = str(xprs[1])
            result = xprs[3]
            rresult = xprs[4]
            result = X.simplify_result(xargs[3],xargs[4],result,rresult)
            return 'trap if ' + rhs1 + ' == ' + rhs2 + ' (' + result + ')'
        else:
            return 'pending:' + self.tags[0]

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   if GPR[rs] = GPR[rt] then
    #     SignalException(Trap)
    #   endif
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op)
        if src1val.is_symbol() or src2val.is_symbol():
            expr = str(src1val) + ' == ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate,iaddr,None,expr)
        elif (src1val.is_literal() and src1val.is_defined()
              and src2val.is_literal() and src2val.is_defined()):
            if src1val.value == src2val.value:
                raise SU.CHBTrapSignalException(src1val,src2val)
            else:
                simstate.increment_program_counter()
                return 'trap if equal: ' + str(src1val) + ', ' + str(src2val)
        else:
            simstate.increment_program_counter()
            return 'trap if equal: ?'

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

    def get_src1_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_src2_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GRP[rd] <- GPR[rs] xor GPR[rt]  (bitwise logical exclusive or)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        dstop = self.get_dst_operand()
        src1val = simstate.get_rhs(iaddr,self.get_src1_operand())
        src2val = simstate.get_rhs(iaddr,self.get_src2_operand())
        if (src1val.is_literal() and src1val.is_defined()
            and src2val.is_literal() and src2val.is_defined()):
            result = src1val.bitwise_xor(src2val)
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' xor ' + str(src2val))
        elif (src1val.is_symbol() and src2val.is_literal() and src2val.is_defined()):
            result = SSV.mk_symbol(src1val.get_name() + ' xor ' + str(sr2val))
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' xor ' + str(src2val))
        elif (src1val.is_literal() and src1val.is_defined() and src2val.is_symbol()):
            result = SSV.mk_symbol(str(src2val) + ' xor ' + src2val.get_name())
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' xor ' + str(src2val))
        else:
            result = SV.simUndefinedDW
            lhs = simstate.set(iaddr,dstop,result)
            simstate.increment_program_counter()
            return SU.simassign(iaddr,simstate,lhs,result,
                                str(src1val) + ' xor ' + str(src2val))


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

    def get_src_operand(self): return self.mipsd.get_mips_operand(self.args[1])

    def get_imm_operand(self): return self.mipsd.get_mips_operand(self.args[2])

    def get_dst_operand(self): return self.mipsd.get_mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    GPR[rt] <- GPR[rs] xor zero_extend(immediate) (bitwise logical exclusive or)
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        immval = self.get_imm_operand().get_mips_opkind().to_unsigned_int()
        imm = SV.SimDoubleWordValue(immval)
        if srcval.is_symbolic() and srcval.is_symbol():
            expr = str(srcval) + ' xor ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate,iaddr,dstop,expr)
        result = srcval.bitwise_xor(imm)
        lhs = simstate.set(iaddr,self.get_dst_operand(),result)
        simstate.increment_program_counter()
        return SU.simassign(iaddr,simstate,lhs,result,
                            str(srcval) + ' xor ' + str(immval))
