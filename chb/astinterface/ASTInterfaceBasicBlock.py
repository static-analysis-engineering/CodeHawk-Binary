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
from chb.util.loggingutil import chklogger


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
        self._trampoline_instructions: Dict[
            str, Dict[str, ASTInterfaceInstruction]] = {}

    @property
    def basicblock(self) -> "BasicBlock":
        return self._b

    def has_trampoline_role(self, role: str) -> bool:
        return role in self.trampoline

    def trampoline_basicblock(self, role: str) -> "BasicBlock":
        if role in self.trampoline:
            return self.trampoline[role]
        else:
            raise UF.CHBError("Trampoline role not found: " + role)

    @property
    def is_trampoline(self) -> bool:
        return self._trampoline is not None

    @property
    def trampoline(self) -> Dict[str, "BasicBlock"]:
        if self._trampoline is not None:
            return self._trampoline
        else:
            raise UF.CHBError("ASTIBlock is not a trampoline")

    @property
    def trampoline_payload_roles(self) -> List[str]:
        if self._trampoline is not None:
            return [k for k in self._trampoline if k.startswith("payload")]
        else:
            return []

    @property
    def instructions(self) -> Dict[str, ASTInterfaceInstruction]:
        if len(self._instructions) == 0:
            for (iaddr, instr) in self.basicblock.instructions.items():
                self._instructions[iaddr] = ASTInterfaceInstruction(instr)
        return self._instructions

    @property
    def trampoline_instructions(
            self) -> Dict[str, Dict[str, ASTInterfaceInstruction]]:
        return self._trampoline_instructions

    def trampoline_block_instructions(
            self, role: str) -> Dict[str, ASTInterfaceInstruction]:
        if self.is_trampoline and self.has_trampoline_role(role):
            if not role in self._trampoline_instructions:
                self._trampoline_instructions[role] = {}
                tb = self.trampoline_basicblock(role)
                for (iaddr, instr) in tb.instructions.items():
                    self._trampoline_instructions[role][iaddr] = (
                        ASTInterfaceInstruction(instr))
            return self._trampoline_instructions[role]
        else:
            raise UF.CHBError("ASTIBlock does not have role: " + role)

    @property
    def has_return(self) -> bool:
        return self.basicblock.has_return

    @property
    def last_instruction(self) -> ASTInterfaceInstruction:
        bb_lastinstr = self.basicblock.last_instruction
        iaddr = bb_lastinstr.iaddr
        return self.instructions[iaddr]

    def trampoline_block_last_instruction(
            self, role: str) -> ASTInterfaceInstruction:
        t_bb = self.trampoline_basicblock(role)
        iaddr = t_bb.last_instruction.iaddr
        return self.trampoline_block_instructions(role)[iaddr]

    def assembly_ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.last_instruction.assembly_ast_condition(
            astree, reverse=reverse)

    def ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.last_instruction.ast_condition(astree, reverse=reverse)

    def trampoline_ast_condition(
            self,
            role: str,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.trampoline_block_last_instruction(role).ast_condition(
            astree, reverse = reverse)

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

    def ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if self.is_trampoline:
            return self.trampoline_ast(astree)

        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(self.instructions.items(), key=lambda p: p[0]):
            instrs.extend(i.ast(astree))
        return astree.mk_instr_sequence(instrs)

    def trampoline_block_ast(
            self,
            role: str,
            astree: "ASTInterface",
            trim: int = 0) -> AST.ASTStmt:
        instrs: List[AST.ASTInstruction] = []
        if trim > 0:
            # remove last (condition setting) instruction
            for (a, i) in sorted(
                    self.trampoline_block_instructions(role).items(),
                    key=lambda p: p[0])[:-1]:
                instrs.extend(i.ast(astree))
        else:
            for (a, i) in sorted(
                    self.trampoline_block_instructions(role).items(),
                    key=lambda p: p[0]):
                instrs.extend(i.ast(astree))
        return astree.mk_instr_sequence(instrs)

    def trampoline_setup_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if not self.is_trampoline:
            raise UF.CHBError("Internal error")
        return self.trampoline_block_ast("setupblock", astree)

    def trampoline_payload_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        """Lifting of payload containing a single condition.

        Patterns currently recognized:

        case 1: fallthrough / exit function (return):
        <condition>
        MOVxx R0, #1
        BX    LR
        ------------

        fallthrough / continue:
        <condition>
        MOVxx R1, #1
        LSL   R0, R1, #1
        BX    LR
        """
        if not self.trampoline:
            raise UF.CHBError("Internal error")

        payloadblock = self.trampoline["payload"]
        payloadinstrs = sorted(payloadblock.instructions.items())
        (iaddr2, chkinstr2) = payloadinstrs[-2]
        chkinstr2 = cast("ARMInstruction", chkinstr2)

        # case 1
        if chkinstr2.mnemonic_stem == "MOV":
            if chkinstr2.has_instruction_condition():
                condition = chkinstr2.get_instruction_condition()
                rstmt = astree.mk_return_stmt(None)
                estmt = astree.mk_instr_sequence([])
                cc = XU.xxpr_to_ast_def_expr(condition,
                                             chkinstr2.xdata,
                                             chkinstr2.iaddr,
                                             astree)
                brstmt = astree.mk_branch(cc, rstmt, estmt, "0x0")
                return brstmt
            else:
                chklogger.logger.critical(
                    "trampoline payload cannot be lifted: "
                    + "expected to find conditional MOV instruction. "
                    + "Contact system maintainer for support.")

        # case 2
        elif chkinstr2.mnemonic_stem == "LSL":
            (iaddr3, chkinstr3) = payloadinstrs[-3]
            chkinstr3 = cast("ARMInstruction", chkinstr3)
            if chkinstr3.mnemonic_stem == "MOV":
                if chkinstr3.has_instruction_condition():
                    condition = chkinstr3.get_instruction_condition()
                    cstmt = astree.mk_continue_stmt()
                    estmt = astree.mk_instr_sequence([])
                    cc = XU.xxpr_to_ast_def_expr(
                        condition, chkinstr3.xdata, chkinstr3.iaddr, astree)
                    brstmt = astree.mk_branch(cc, cstmt, estmt, "0x0")
                    return brstmt
                else:
                    chklogger.logger.critical(
                        "trampoline payload cannot be lifted: "
                        + "expected to find conditional MOV instruction. "
                        + "Contact system maintainer for support.")
            else:
                chklogger.logger.critical(
                    "trampoline payload cannot be lifted: "
                    + "expected a MOV instruction and not a %s. "
                    + "Contact system maintainer for support.",
                    chkinstr3.mnemonic)
        else:
            chklogger.logger.critical(
                "trampoline payload cannot be lifted: "
                + "pattern not recognized. "
                + "Contact system maintainer for support.")
        return self.trampoline_block_ast("payload", astree)

    def trampoline_payload_sideeffect_ast(
            self, astree: "ASTInterface") -> AST.ASTStmt:

        cond = self.trampoline_ast_condition("payload-0", astree)
        # need to exclude last instruction of payload-1
        sideeffect = self.trampoline_block_ast("payload-1", astree, trim=1)
        rstmt = astree.mk_return_stmt(None)
        estmt = astree.mk_instr_sequence([])
        tr_stmt = astree.mk_block([sideeffect, rstmt])
        if cond is not None:
            return astree.mk_branch(cond, tr_stmt, estmt, "0x0")
        return tr_stmt

    def trampoline_payload_loop_ast(
            self, astree: "ASTInterface") -> AST.ASTStmt:
        """Assumes a return via conditional POP."""

        cond = self.trampoline_ast_condition("payload-0", astree, reverse=True)
        initcond = self.trampoline_ast_condition(
            "payload-1", astree, reverse=True)
        loopcond = self.trampoline_ast_condition(
            "payload-2", astree, reverse=True)

        initstmt = self.trampoline_block_ast("payload-1", astree)
        loopbody = self.trampoline_block_ast("payload-2", astree)
        rstmt = astree.mk_return_stmt(None)
        breakstmt = astree.mk_break_stmt()
        estmt = astree.mk_instr_sequence([])

        if cond is not None and initcond is not None and loopcond is not None:
            breakout = astree.mk_branch(loopcond, breakstmt, estmt, "0x0")
            loopbody = astree.mk_block([loopbody, breakout])
            loopstmt = astree.mk_loop(loopbody)
            c_loopstmt = astree.mk_branch(initcond, loopstmt, estmt, "0x0")

            sideeffect = astree.mk_block([initstmt, c_loopstmt, rstmt])
            return astree.mk_branch(cond, sideeffect, estmt, "0x0")

        else:
            raise UF.CHBError(
                "trampoline-payload-loop: one of the conditions not known")

    def trampoline_takedown_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        if not self.is_trampoline:
            raise UF.CHBError("Internal error")
        return self.trampoline_block_ast("fallthrough", astree)

    def trampoline_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        stmts: List[AST.ASTStmt] = []

        if not self.is_trampoline:
            raise UF.CHBError("Internal error")
        if "setupblock" in self.trampoline:
            stmts.append(self.trampoline_setup_ast(astree))
        if "payload-0" in self.trampoline or "payload" in self.trampoline:
            if len(self.trampoline_payload_roles) == 4:
                stmts.append(self.trampoline_payload_loop_ast(astree))
            elif len(self.trampoline_payload_roles) == 3:
                stmts.append(self.trampoline_payload_sideeffect_ast(astree))
            elif len(self.trampoline_payload_roles) == 1:
                stmts.append(self.trampoline_payload_ast(astree))
            else:
                chklogger.logger.critical(
                    "trampoline payload with %s basic blocks not recognized",
                    str(len(self.trampoline_payload_roles)))
        if "fallthrough" in self.trampoline:
            stmts.append(self.trampoline_takedown_ast(astree))
        return astree.mk_block(stmts)
