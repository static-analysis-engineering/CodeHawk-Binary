# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2024  Aarno Labs, LLC
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
"""Function interface for AST construction."""

from typing import cast, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from chb.app.JumpTables import JumpTable

from chb.arm.ARMCodeGenerator import ARMCodeGenerator

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTFunction import ASTFunction
from chb.ast.ASTNode import ASTStmt, ASTVarInfo, ASTExpr
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.CustomASTSupport import CustomASTSupport

from chb.astinterface.ASTICodeTransformer import ASTICodeTransformer
from chb.astinterface.ASTICPrettyPrinter import ASTICPrettyPrinter
from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.ASTInterfaceBasicBlock import ASTInterfaceBasicBlock
from chb.astinterface.ASTInterfaceInstruction import ASTInterfaceInstruction
from chb.astinterface.CHBASTSupport import CHBASTSupport

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Function import Function
    from chb.app.JumpTables import JumpTable
    from chb.arm.ARMCfg import ARMCfg
    from chb.arm.ARMCfgBlock import ARMCfgTrampolineBlock
    from chb.arm.ARMFunction import ARMFunction
    from chb.cmdline.PatchResults import PatchEvent
    from chb.invariants.InvariantFact import InitialVarEqualityFact, NRVFact


class ASTInterfaceFunction(ASTFunction):

    def __init__(
            self,
            faddr: str,
            fname: str,
            f: "Function",
            astinterface: ASTInterface,
            patchevents: Dict[str, "PatchEvent"] = {}) -> None:
        ASTFunction.__init__(self, faddr, fname)
        self._function = f
        self._astinterface = astinterface
        self._patchevents = patchevents
        self._cfgtc: Optional["ARMCfg"] = None
        self._astblocks: Dict[str, ASTInterfaceBasicBlock] = {}
        self._astinstructions: Dict[str, ASTInterfaceInstruction] = {}

    @property
    def astblocks(self) -> Dict[str, ASTInterfaceBasicBlock]:
        if len(self._astblocks) == 0:
            for (addr, block) in self.function.blocks.items():
                if addr in self.cfg_tc.blocks:
                    cfgblock = self.cfg_tc.blocks[addr]
                    if cfgblock.is_trampoline:
                        cfgblock = cast("ARMCfgTrampolineBlock", cfgblock)
                        roles: Dict[str, "BasicBlock"] = {}
                        for (name, baddr) in cfgblock.roles.items():
                            roles[name] = self.function.blocks[baddr]
                        astblock = ASTInterfaceBasicBlock(block, roles)
                        self._astblocks[addr] = astblock
                    else:
                        astblock = ASTInterfaceBasicBlock(block)
                        self._astblocks[addr] = astblock
                else:
                    continue
        return self._astblocks

    @property
    def cfg_tc(self) -> "ARMCfg":
        if self._cfgtc is None:
            self._cfgtc = cast(
                "ARMFunction", self.function).cfg_tc(self.patchevents)
        return self._cfgtc

    @property
    def astinstructions(self) -> Dict[str, ASTInterfaceInstruction]:
        if len(self._astinstructions) == 0:
            for block in self.astblocks.values():
                for (iaddr, instr) in block.instructions.items():
                    self._astinstructions[iaddr] = instr
        return self._astinstructions

    @property
    def patchevents(self) -> Dict[str, "PatchEvent"]:
        return self._patchevents

    @property
    def jumptables(self) -> Dict[str, JumpTable]:
        return self.function.jumptables

    def has_jumptable(self, tgt: str) -> bool:
        return tgt in self.jumptables

    def get_jumptable(self, tgt: str) -> JumpTable:
        if self.has_jumptable(tgt):
            return self.jumptables[tgt]
        else:
            raise UF.CHBError(
                "Function "
                + self.name
                + " does not have a jumptable at address "
                + tgt)

    @property
    def astinterface(self) -> ASTInterface:
        return self._astinterface

    @property
    def function(self) -> "Function":
        return self._function

    @property
    def verbose(self) -> bool:
        return self.astinterface.verbose

    def astblock(self, startaddr: str) -> ASTInterfaceBasicBlock:
        return self.astblocks[startaddr]

    def ast(self, support: CustomASTSupport) -> ASTStmt:
        return self.cfg_tc.ast(self, self.astinterface)

    def cfg_ast(self, support: CustomASTSupport) -> ASTStmt:
        return self.cfg_tc.cfg_ast(self, self.astinterface)

    def mk_asts(self, support: CustomASTSupport) -> List[ASTStmt]:
        highlevel = self.mk_high_level_ast(support)
        lowlevel = self.mk_low_level_ast(support)

        # transfer provenance data to the AST abstract syntaxtree
        self.astinterface.set_ast_provenance()
        self.set_invariants()
        self.set_return_sequences()

        return highlevel + [lowlevel]

    def mk_low_level_ast(
            self,
            support: CustomASTSupport) -> ASTStmt:
        try:
            ast = self.cfg_tc.cfg_ast(self, self.astinterface)
            if self.verbose:
                print("\n\nLow-level instructions before transformation")
                print("=============================================")
                iprettyprinter = ASTICPrettyPrinter(
                    self.astinterface.symboltable,
                    self.astinterface.astiprovenance,
                    annotations=self.astinterface.annotations)
                print(iprettyprinter.to_c(ast))
            return ast
        except UF.CHBError as e:
            msg = (
                "Unable to create low-level ast for "
                + self.name
                + " ("
                + self.address
                + "):\n  "
                + str(e))
            raise UF.CHBError(msg)

    def mk_high_level_ast(
            self,
            support: CustomASTSupport) -> List[ASTStmt]:
        try:
            ast = self.cfg_tc.ast(self, self.astinterface)
        except UF.CHBError as e:
            msg = (
                "Unable to create high-level ast for "
                + self.name
                + " ("
                + self.address
                + "):\n  "
                + str(e))
            chklogger.logger.error(
                "Unable to create high-level ast for %s (%s): %s",
                self.name,
                self.address,
                str(e))
            raise UF.CHBError(msg)

        self.complete_instruction_connections()

        if self.verbose:
            print("\n\nHigh-level instructions before transformation")
            print("=============================================")
            iprettyprinter = ASTICPrettyPrinter(
                self.astinterface.symboltable,
                self.astinterface.astiprovenance,
                annotations=self.astinterface.annotations)
            print(iprettyprinter.to_c(ast))

        variablesused = ast.variables_used()

        codetransformer = ASTICodeTransformer(self.astinterface, list(variablesused))
        transformedcode = codetransformer.transform_stmt(ast)

        variablesused = transformedcode.variables_used()
        codetransformer = ASTICodeTransformer(self.astinterface, list(variablesused))
        transformedcode = codetransformer.transform_stmt(ast)

        if self.verbose:
            prettyprinter = ASTCPrettyPrinter(self.astinterface.symboltable)
            print("\n\nTransformed code")
            print(prettyprinter.to_c(transformedcode))

        return [transformedcode, ast]

    def complete_instruction_connections(self) -> None:
        """Connect hl-instrs to the ll-instrs subsumed by them."""

        for instr in self.astinstructions.values():
            if instr.is_subsumed:
                subsumeraddr = instr.subsumed_by()
                subsumerinstr = self.astinstructions[subsumeraddr]
                for hl_instr in subsumerinstr.hl_ast_instructions:
                    for ll_instr in instr.ll_ast_instructions:
                        self.astinterface.add_instr_mapping(hl_instr, ll_instr)

    def set_invariants(self) -> None:
        invariants = self.function.invariants
        aexprs: Dict[str, Dict[str, Tuple[int, int, str]]] = {}
        for loc in sorted(invariants):
            if loc.startswith("F:"):
                # skip invariants on addresses inlined by the analysis
                continue
            if loc == "exit":
                continue
            for fact in invariants[loc]:
                instr = self.function.instruction(loc)
                if fact.is_nonrelational:
                    fact = cast("NRVFact", fact)
                    if (
                            fact.variable.is_frozen_test_value
                            or fact.variable.is_bridge_variable):
                        # Exclude auxiliary analysis variables
                        continue

                    if fact.variable.is_constant_value_variable:
                        # Exclude invariants that equate symbolic constants
                        # with constant values
                        continue

                    var = XU.xvariable_to_ast_lval(
                        fact.variable,
                        instr.xdata,
                        instr.iaddr,
                        self.astinterface,
                        anonymous=True)

                    if "astmem_tmp" in str(var):
                        chklogger.logger.info(
                            "Skipping invariant %s at %s",
                            str(fact), str(loc))
                        continue

                    varindex = var.index(self.astinterface.serializer)
                    value = fact.value
                    if value.is_singleton_value:
                        aexpr: ASTExpr = self.astinterface.mk_integer_constant(
                            value.singleton_value)
                        aexprindex = aexpr.index(self.astinterface.serializer)

                    elif value.is_symbolic_expression:
                        aexpr = XU.xxpr_to_ast_def_expr(
                            fact.value.expr,
                            instr.xdata,
                            instr.iaddr,
                            self.astinterface,
                            anonymous=True)
                        if "astmem_tmp" in str(aexpr):
                            chklogger.logger.info(
                                "Skipping invariant %s at %s",
                                str(aexpr), str(loc))
                            continue
                        aexprindex = aexpr.index(self.astinterface.serializer)
                    else:
                        continue
                    aexprs.setdefault(loc, {})
                    aexprs[loc][str(var)] = (varindex, aexprindex, str(aexpr))

                if fact.is_initial_var_equality:
                    fact = cast("InitialVarEqualityFact", fact)

                    if fact.variable.is_constant_value_variable:
                        continue

                    if fact.variable.is_global_variable:
                        continue

                    # Filter out initial-value equalities on return values
                    if "rtn_" in str(fact.variable):
                        continue

                    var = XU.xvariable_to_ast_lval(
                        fact.variable,
                        instr.xdata,
                        instr.iaddr,
                        self.astinterface,
                        anonymous=True)

                    varindex = var.index(self.astinterface.serializer)
                    aexpr = XU.xvariable_to_ast_def_lval_expression(
                        fact.initial_value,
                        instr.xdata,
                        instr.iaddr,
                        self.astinterface,
                        anonymous=True)

                    if "astmem_tmp" in str(aexpr):
                        # if str(var).startswith("astmem_tmp"):
                        chklogger.logger.info(
                            "Skipping invariant %s at %s",
                            str(fact), str(loc))
                        continue

                    aexprindex = aexpr.index(self.astinterface.serializer)
                    aexprs.setdefault(loc, {})
                    aexprs[loc][str(var)] = (varindex, aexprindex, str(aexpr))

        num_aexprs = sum(len(aexprs[a]) for a in aexprs)
        chklogger.logger.info("Set %d available expressions", num_aexprs)
        self.astinterface.set_available_expressions(aexprs)

    def set_return_sequences(self) -> None:
        """Currently only supports Thumb-2 stack-adjustment, pop return sequence."""

        stacklayout = self.function.stackframe
        savedregisters = stacklayout.saved_registers.items()
        reglayout: Dict[int, int] = {}
        for (offset, reg) in savedregisters:
            if reg.name.startswith("R"):
                reglayout[offset] = int(reg.name[1:])
            elif reg.name == "LR":
                reglayout[offset] = 15

        setpc = False
        reglist: List[int] = []
        if len(reglayout) > 0:
            codegenerator = ARMCodeGenerator()
            startoff = sorted(reglayout.keys())[0]
            curroff = startoff
            for (off, index) in sorted(reglayout.items()):
                if off == curroff:
                    if index == 15:
                        setpc = True
                    else:
                        reglist.append(index)
                curroff += 4
            (popinstr, popassembly) = codegenerator.pop_registers_t1(reglist, setpc)

            for (addr, instr) in self.function.instructions.items():
                if addr.startswith("F:"):
                    # do not include return sequences for addresses of functions
                    # inlined by the analysis
                    continue
                ioffset = instr.stackpointer_offset.offset
                if ioffset.is_singleton:
                    offsetval = ioffset.lower_bound.bound.value
                    if offsetval < startoff:
                        (adjustspinstr, adjustspassembly) = (
                            codegenerator.get_stack_adjustment(startoff - offsetval))
                        instrseq = adjustspinstr + popinstr
                        assembly = adjustspassembly + [popassembly]
                    elif offsetval == startoff:
                        instrseq = popinstr
                        assembly = [popassembly]
                    else:
                        instrseq = ""
                        assembly = []

                    if setpc:
                        if len(assembly) > 0:
                            self.astinterface.add_return_sequence(
                                instrseq, assembly, addr)

                    # if the pc was not included in the POP statement, add BX LR
                    # as a return if the LR has its original value, otherwise skip
                    else:
                        originalLR = False
                        for inv in instr.invariants:
                            if inv.is_initial_var_equality and str(inv.variable) == "LR":
                                originalLR = True
                                break

                        if originalLR:
                            (bxlrinstr, bxlrassembly) = codegenerator.bx_lr()
                            instrseq = instrseq + bxlrinstr
                            assembly = assembly + [bxlrassembly]
                            self.astinterface.add_return_sequence(
                                instrseq, assembly, addr)
