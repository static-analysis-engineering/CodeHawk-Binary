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


from typing import Any, Dict, List, Optional, Union

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyBlock import JSONAssemblyBlock
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONControlFlowGraph as Cfg
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC
from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONObjectNOPVisitor(JSONObjectVisitor):

    def __init__(self) -> None:
        pass

    def visit_app_comparison(self, obj: AppC.JSONAppComparison) -> None:
        pass

    def visit_app_md5_comparison(self, obj: AppC.JSONAppMD5Comparison) -> None:
        pass

    def visit_assembly_block(self, obj: JSONAssemblyBlock) -> None:
        pass

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        pass

    def visit_binary_comparison(self, obj: AppC.JSONBinaryComparison) -> None:
        pass

    def visit_block_comparison(self, obj: BlockC.JSONBlockComparison) -> None:
        pass

    def visit_block_expansion(self, obj: BlockC.JSONBlockExpansion) -> None:
        pass

    def visit_callgraph_comparison(
            self, obj: AppC.JSONCallgraphComparison) -> None:
        pass

    def visit_cfg_comparison(self, obj: FunC.JSONCfgComparison) -> None:
        pass

    def visit_cfg_edge(self, obj: Cfg.JSONCfgEdge) -> None:
        pass

    def visit_cfg_edge_comparison(
            self, obj: FunC.JSONCfgEdgeComparison) -> None:
        pass

    def visit_cfg_node(self, obj: Cfg.JSONCfgNode) -> None:
        pass

    def visit_control_flow_graph(self, obj: Cfg.JSONControlFlowGraph) -> None:
        pass

    def visit_function_added(self, obj: AppC.JSONFunctionAdded) -> None:
        pass

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        pass

    def visit_function_md5(
            self, obj: AppC.JSONFunctionMD5) -> None:
        pass

    def visit_function_semantic_comparison(
            self, obj: FunC.JSONFunctionSemanticComparison) -> None:
        pass

    def visit_globalvar_comparison(
            self, obj: AppC.JSONGlobalVarComparison) -> None:
        pass

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        pass

    def visit_localvars_comparison(
            self, obj: FunC.JSONLocalVarsComparison) -> None:
        pass

    def visit_xblock_detail(self, obj: BlockC.JSONXBlockDetail) -> None:
        pass

    def visit_xedge_detail(self, obj: BlockC.JSONXEdgeDetail) -> None:
        pass
