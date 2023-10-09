# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING, Union

from chb.jsoninterface.JSONBlockComparison import (
    JSONBlockComparison, JSONBlockExpansion)
from chb.jsoninterface.JSONControlFlowGraph import JSONControlFlowGraph
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONLocalVarsComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "localvarscomparison")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_localvars_comparison(self)


class JSONFunctionSemanticComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functionsemanticcomparison")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_semantic_comparison(self)


class JSONCfgEdgeComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgedgecomparison")

    @property
    def src1(self) -> str:
        return self.d.get("src1", self.property_missing("src1"))

    @property
    def src2(self) -> str:
        return self.d.get("src2", self.property_missing("src2"))

    @property
    def tgt1(self) -> str:
        return self.d.get("tgt1", self.property_missing("tgt1"))

    @property
    def tgt2(self) -> str:
        return self.d.get("tgt2", self.property_missing("tgt2"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_edge_comparison(self)


class JSONCfgBlockMappingItem(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgblockmappingitem")
        self._blocks2: Optional[List[Tuple[str, str]]] = None

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def cfg1_block_addr(self) -> str:
        return self.d.get("cfg1-block-addr", self.property_missing("cfg1-block-addr"))

    @property
    def cfg2_blocks(self) -> List[Tuple[str, str]]:
        if self._blocks2 is None:
            result: List[Tuple[str, str]] = []
            for b in self.d.get("cfg2-blocks", []):
                result.append((
                    b.get("cfg2-block-addr", self.property_missing("cfg2-block-addr")),
                    b.get("role")))
            self._blocks2 = result
        return self._blocks2

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        raise NotImplementedError("This is the previous JSON API and no longer supports visitors")


class JSONCfgComparison(JSONObject):
    """Comparison between two cfg's in terms of graph edits.

    A comparison consists of a number of graph edits that collectively
    cover all nodes of cfg1 as domain and all nodes of cfg2 as range,
    and similarly for the edges.

    Block edits include:
    - block substitutions: mapping a single node in cfg1 to a single
      node in cfg2
    - block insertions: a single node in cfg2
    - block deletions: a single node in cf1
    - block expansions: mapping a single node in cfg1 to multiple
      related blocks in cfg2

    Edge edits include:
    - edge substitutions: mapping a single edge in cfg1 to a single
      edge in cfg2
    - edge insertions: a single edge in cfg2
    - edge deletions: a single edge in cfg1
    """

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgcomparison")
        self._cfg1: Optional[JSONControlFlowGraph] = None
        self._cfg2: Optional[JSONControlFlowGraph] = None

        # original API
        self._mapping: Optional[List[JSONCfgBlockMappingItem]] = None

        # new API
        # block edits (transformations)
        self._blockinsertions: Optional[List[str]] = None
        self._blockdeletions: Optional[List[str]] = None
        self._blocksubstitutions: Optional[List[JSONBlockComparison]] =  None
        self._blockexpansions: Optional[List[JSONBlockExpansion]] = None

        # edge edits (transformations)
        self._edgeinsertions: Optional[List[Tuple[str, str]]] = None
        self._edgedeletions: Optional[List[Tuple[str, str]]] = None
        self._edgesubstitutions: Optional[List[JSONCfgEdgeComparison]] = None

    @property
    def similarity(self) -> str:
        return self.d.get("similarity", self.property_missing("similarity"))

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def cfg1(self) -> JSONControlFlowGraph:
        if self._cfg1 is None:
            self._cfg1 = JSONControlFlowGraph(self.d.get("cfg1", {}))
        return self._cfg1

    @property
    def cfg2(self) -> JSONControlFlowGraph:
        if self._cfg2 is None:
            self._cfg2 = JSONControlFlowGraph(self.d.get("cfg2", {}))
        return self._cfg2

    @property
    def cfg_block_mapping(self) -> List[JSONCfgBlockMappingItem]:
        if self._mapping is None:
            result: List[JSONCfgBlockMappingItem] = []
            for m in self.d.get("cfg-block-mapping", []):
                result.append(JSONCfgBlockMappingItem(m))
            self._mapping = result
        return self._mapping

    @property
    def block_insertions(self) -> List[str]:
        if self._blockinsertions is None:
            self._blockinsertions = []
            for b in self.d.get("block-insertions", []):
                self._blockinsertions.append(b)
        return self._blockinsertions

    @property
    def block_deletions(self) -> List[str]:
        if self._blockdeletions is None:
            self._blockdeletions = []
            for b in self.d.get("block-deletions", []):
                self._blockdeletions.append(b)
        return self._blockdeletions

    @property
    def block_substitutions(self) -> List[JSONBlockComparison]:
        if self._blocksubstitutions is None:
            self._blocksubstitutions = []
            for b in self.d.get("block-substitutions", []):
                self._blocksubstitutions.append(JSONBlockComparison(b))
        return self._blocksubstitutions

    @property
    def block_expansions(self) -> List[JSONBlockExpansion]:
        if self._blockexpansions is None:
            self._blockexpansions = []
            for b in self.d.get("block-expansions", []):
                self._blockexpansions.append(JSONBlockExpansion(b))
        return self._blockexpansions

    @property
    def edge_insertions(self) -> List[Tuple[str, str]]:
        if self._edgeinsertions is None:
            self._edgeinsertions = []
            for e in self.d.get("edge-insertions", []):
                src = e.get("src", self.property_missing("src"))
                dst = e.get("dst", self.property_missing("dst"))
                self._edgeinsertions.append((src, dst))
        return self._edgeinsertions

    @property
    def edge_deletions(self) -> List[Tuple[str, str]]:
        if self._edgedeletions is None:
            self._edgedeletions = []
            for e in self.d.get("edge-deletions", []):
                src = e.get("src", self.property_missing("src"))
                dst = e.get("dst", self.property_missing("dst"))
                self._edgedeletions.append((src, dst))
        return self._edgedeletions

    @property
    def edge_substitutions(self) -> List[JSONCfgEdgeComparison]:
        if self._edgesubstitutions is None:
            self._edgesubstitutions = []
            for e in self.d.get("edge-substitutions", []):
                self._edgesubstitutions.append(JSONCfgEdgeComparison(e))
        return self._edgesubstitutions

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_comparison(self)


class JSONFunctionComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functioncomparison")
        self._cfgcomparison: Optional[JSONCfgComparison] = None
        self._localvarscomparison: Optional[JSONLocalVarsComparison] = None
        self._semanticcomparison: Optional[JSONFunctionSemanticComparison] = None

    @property
    def faddr1(self) -> str:
        return self.d.get("faddr1", self.property_missing("faddr1"))

    @property
    def faddr2(self) -> str:
        return self.d.get("faddr2", self.property_missing("faddr2"))

    @property
    def name1(self) -> Optional[str]:
        return self.d.get("name1")

    @property
    def name2(self) -> Optional[str]:
        return self.d.get("name2")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def cfg_comparison(self) -> JSONCfgComparison:
        if self._cfgcomparison is None:
            self._cfgcomparison = JSONCfgComparison(
                self.d.get("cfg-comparison", {}))
        return self._cfgcomparison

    @property
    def localvars_comparison(self) -> JSONLocalVarsComparison:
        if self._localvarscomparison is None:
            self._localvarscomparison = JSONLocalVarsComparison(
                self.d.get("localvars-comparison", {}))
        return self._localvarscomparison

    @property
    def semantic_comparison(self) -> JSONFunctionSemanticComparison:
        if self._semanticcomparison is None:
            self._semanticcomparison = (
                JSONFunctionSemanticComparison(
                    self.d.get("semantic-comparison", {})))
        return self._semanticcomparison

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_comparison(self)
