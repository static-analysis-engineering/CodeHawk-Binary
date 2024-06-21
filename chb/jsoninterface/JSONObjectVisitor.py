# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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

from abc import ABC

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyBlock import JSONAssemblyBlock
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONCallgraph as Cg
import chb.jsoninterface.JSONCallsiteRecords as CR
import chb.jsoninterface.JSONControlFlowGraph as Cfg
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC
import chb.jsoninterface.JSONPatchComponent as PC


class JSONObjectVisitor(ABC):

    def __init__(self) -> None:
        pass

    def visit_app_comparison(self, obj: AppC.JSONAppComparison) -> None:
        ...

    def visit_app_md5_comparison(self, obj: AppC.JSONAppMD5Comparison) -> None:
        ...

    def visit_assembly_block(self, obj: JSONAssemblyBlock) -> None:
        ...

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        ...

    def visit_binary_comparison(self, obj: AppC.JSONBinaryComparison) -> None:
        ...

    def visit_block_comparison(self, obj: BlockC.JSONBlockComparison) -> None:
        ...

    def visit_callgraph(self, obj: Cg.JSONCallgraph) -> None:
        ...

    def visit_callgraph_comparison(
            self, obj: AppC.JSONCallgraphComparison) -> None:
        ...

    def visit_callgraph_edge(self, obj: Cg.JSONCallgraphEdge) -> None:
        ...

    def visit_callgraph_node(self, obj: Cg.JSONCallgraphNode) -> None:
        ...

    def visit_callsite_argument(self, obj: CR.JSONCallsiteArgument) -> None:
        ...

    def visit_callsite_record(self, obj: CR.JSONCallsiteRecord) -> None:
        ...

    def visit_callsite_records(self, obj: CR.JSONCallsiteRecords) -> None:
        ...

    def visit_callsite_tgt_function(
            self, obj: CR.JSONCallsiteTgtFunction) -> None:
        ...

    def visit_callsite_tgt_parameter(
            self, obj: CR.JSONCallsiteTgtParameter) -> None:
        ...

    def visit_cfg_block_mapping_item(self, obj: FunC.JSONCfgBlockMappingItem) -> None:
        ...

    def visit_cfg_edge(self, obj: Cfg.JSONCfgEdge) -> None:
        ...

    def visit_cfg_node(self, obj: Cfg.JSONCfgNode) -> None:
        ...

    def visit_codefragment(self, obj: PC.JSONCodeFragment) -> None:
        ...

    def visit_control_flow_graph(self, obj: Cfg.JSONControlFlowGraph) -> None:
        ...

    def visit_function_added(self, obj: AppC.JSONFunctionAdded) -> None:
        ...

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        ...

    def visit_function_md5(
            self, obj: AppC.JSONFunctionMD5) -> None:
        ...

    def visit_globalvar_comparison(
            self, obj: AppC.JSONGlobalVarComparison) -> None:
        ...

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        ...

    def visit_hookinstr(self, obj: PC.JSONHookInstruction) -> None:
        ...

    def visit_patch_component(self, obj: PC.JSONPatchComponent) -> None:
        ...
