# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2024  Aarno Labs LLC
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
"""Basic block in an abstract syntax tree."""

from typing import cast, Dict, List, Optional, Set, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.astinterface.ASTInterfaceInstruction import ASTInterfaceInstruction

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMCfgBlock import ARMCfgBlock
    from chb.app.BasicBlock import BasicBlock
    from chb.arm.ARMInstruction import ARMInstruction
    from chb.astinterface.ASTInterface import ASTInterface


class ASTInterfaceBasicBlock:

    def __init__(
            self,
            b: "BasicBlock",
            trampoline: Optional[Dict[str, "BasicBlock"]] = None) -> None:
        self._b = b
        self._instructions: Dict[str, ASTInterfaceInstruction] = {}
        self._trampoline = trampoline

    @property
    def basicblock(self) -> "BasicBlock":
        return self._b

    @property
    def trampoline(self) -> Optional[Dict[str, "BasicBlock"]]:
        return self._trampoline

    @property
    def instructions(self) -> Dict[str, ASTInterfaceInstruction]:
        if len(self._instructions) == 0:
            for (iaddr, instr) in self.basicblock.instructions.items():
                self._instructions[iaddr] = ASTInterfaceInstruction(instr)
        return self._instructions

    @property
    def has_return(self) -> bool:
        return self.basicblock.has_return

    @property
    def last_instruction(self) -> ASTInterfaceInstruction:
        bb_lastinstr = self.basicblock.last_instruction
        iaddr = bb_lastinstr.iaddr
        return self.instructions[iaddr]

    def assembly_ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.last_instruction.assembly_ast_condition(astree, reverse=reverse)

    def ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.last_instruction.ast_condition(astree, reverse=reverse)

    '''
    def ast_switch_condition(
            self, astree: "ASTInterface") -> Optional[AST.ASTExpr]:
        return self.last_instruction.ast_switch_condition(astree)
    '''

    def assembly_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(self.instructions.items(), key=lambda p: p[0]):
            instrs.extend(i.assembly_ast(astree))
        return astree.mk_instr_sequence(instrs)

    def trampoline_setup_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if not self.trampoline:
            raise UF.CHBError("Internal error")
        setupblock = self.trampoline["setupblock"]
        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(setupblock.instructions.items(), key=lambda p: p[0]):
            self._instructions[a] = ASTInterfaceInstruction(i)
            instrs.extend(self.instructions[a].ast(astree))
        return astree.mk_instr_sequence(instrs)

    def trampoline_payload_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if not self.trampoline:
            raise UF.CHBError("Internal error")
        payloadblock = self.trampoline["payload"]
        (iaddr, chkinstr) = sorted(payloadblock.instructions.items())[-2]
        chkinstr = cast("ARMInstruction", chkinstr)
        if chkinstr.mnemonic_stem == "MOV":
            if chkinstr.has_instruction_condition():
                condition = chkinstr.get_instruction_condition()
                rstmt = astree.mk_return_stmt(None)
                estmt = astree.mk_instr_sequence([])
                aexprs = XU.xxpr_to_ast_exprs(
                    condition, chkinstr.xdata, chkinstr.iaddr, astree)
                if len(aexprs) == 1:
                    cc = aexprs[0]
                    brstmt = astree.mk_branch(cc, rstmt, estmt, "0x0")
                    return brstmt

        '''
        if "payload-l" in self.trampoline and "payload-x" in self.trampoline:
            payloadc = self.trampoline["payload-c"]
            (ciaddr, cinstr) = sorted(payloadblock.instructions.items())[-1]
            cinstr = cast("ARMInstruction", cinstr)
            if cinstr.has_condition_block_condition():
                (tcond, fcond) = cinstr.ft_conditions
                instrs: List[AST.ASTInstruction] = []
                for (a, i) in sorted(payloadc.instructions.items())[:-1]:
                    self._instructions[a] = ASTInterfaceInstruction(i)
                    instrs.extend(self.instructions[a].ast(astree))
                initse = astree.mk_instr_sequence(instrs)
                rstmt = astree.mk_return_stmt(None)
                estmt = astree.mk_instr_sequence([])
                aexprs = XU.xxpr_to_ast_exprs(
                    fcond, cinstr.xdata, cinstr.iaddr, astree)
                cc = aexprs[0]
                rsstmt = astree.mk_block([sideeffect, rstmt])
                brstmt = astree.mk_branch(cc, rsstmt, estmt, "0x0")
                return brstmt
        (iaddr, pinstr) = sorted(payloadblock.instructions.items())[0]
        self._instructions[iaddr] = ASTInterfaceInstruction(pinstr)
        astinstr = self.instructions[iaddr].ast(astree)
        return astree.mk_instr_sequence(astinstr)

        '''
        if "payload-c" in self.trampoline and "payload-x" in self.trampoline:
            payloadc = self.trampoline["payload-c"]
            (ciaddr, cinstr) = sorted(payloadblock.instructions.items())[-1]
            cinstr = cast("ARMInstruction", cinstr)
            if cinstr.has_condition_block_condition():
                (tcond, fcond) = cinstr.ft_conditions
                instrs: List[AST.ASTInstruction] = []
                for (a, i) in sorted(payloadc.instructions.items())[:-1]:
                    self._instructions[a] = ASTInterfaceInstruction(i)
                    instrs.extend(self.instructions[a].ast(astree))
                sideeffect = astree.mk_instr_sequence(instrs)
                rstmt = astree.mk_return_stmt(None)
                estmt = astree.mk_instr_sequence([])
                aexprs = XU.xxpr_to_ast_exprs(
                    fcond, cinstr.xdata, cinstr.iaddr, astree)
                cc = aexprs[0]
                rsstmt = astree.mk_block([sideeffect, rstmt])
                brstmt = astree.mk_branch(cc, rsstmt, estmt, "0x0")
                return brstmt
        (iaddr, pinstr) = sorted(payloadblock.instructions.items())[0]
        self._instructions[iaddr] = ASTInterfaceInstruction(pinstr)
        astinstr = self.instructions[iaddr].ast(astree)
        return astree.mk_instr_sequence(astinstr)

    def trampoline_takedown_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if not self.trampoline:
            raise UF.CHBError("Internal error")
        takedownblock = self.trampoline["takedown"]
        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(takedownblock.instructions.items(), key=lambda p: p[0]):
            self._instructions[a] = ASTInterfaceInstruction(i)
            instrs.extend(self.instructions[a].ast(astree))
        return astree.mk_instr_sequence(instrs)

    def trampoline_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        stmts: List[AST.ASTStmt] = []
        if not self.trampoline:
            raise UF.CHBError("Internal error")
        if "setupblock" in self.trampoline:
            stmts.append(self.trampoline_setup_ast(astree))
        if "payload" in self.trampoline:
            stmts.append(self.trampoline_payload_ast(astree))
        if "takedown" in self.trampoline:
            stmts.append(self.trampoline_takedown_ast(astree))
        return astree.mk_block(stmts)

    def ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if self.trampoline:
            return self.trampoline_ast(astree)

        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(self.instructions.items(), key=lambda p: p[0]):
            instrs.extend(i.ast(astree))
        return astree.mk_instr_sequence(instrs)
