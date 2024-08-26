# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from typing import Dict, List, Optional, Set, Tuple

max_label_length = 2000


def sanitize(s: str) -> str:
    if s is not None:
        return s.replace(
            '>', "\\>").replace(
                '"', '\\"').replace(
                    '%', "\\%").replace(
                        "<", "\\<").replace(
                            "{", "\\{").replace(
                                "}", "\\}")


class DotNode:

    def __init__(
            self,
            name: str,
            labeltxt: Optional[str] = None,
            color: Optional[str] = None,
            shaded: bool = False) -> None:
        self.name = name
        self.labeltxt = labeltxt
        self.shaded = shaded
        self.color = color
        self.addquotes = True

    def set_label(self, s: str) -> None:
        self.label = s

    def set_color(self, c: str) -> None:
        self.color = c

    def set_shaded(self) -> None:
        self.shaded = True

    def __str__(self) -> str:
        quote = '"' if self.addquotes else ''
        if self.labeltxt is None:
            labeltxt = ''
        elif len(self.labeltxt) > max_label_length:
            # suppress labels that are too long
            labeltxt = 'label="' + self.name + '\\n...."'
        else:
            labeltxt = 'label="' + self.labeltxt + '"'
        if self.shaded:
            shadetxt = 'style=filled,color=".7 .3 1.0"'
        elif self.color is not None:
            if self.color == "grey":
                shadetxt = 'style=filled,fillcolor="grey",color="black",penwidth=5'
            else:
                shadetxt = 'style=filled,color="' + self.color + '"'
        else:
            shadetxt = 'style=filled,color=".7 .3 1.0"'
        return (
            quote
            + self.name
            + quote
            + ' ['
            + labeltxt
            + ','
            + shadetxt
            + '];')


class DotEdge:

    def __init__(
            self,
            src: str,
            tgt: str,
            labeltxt: Optional[str] = None) -> None:
        self.src = src
        self.tgt = tgt
        self.bidirectional = False
        self.labeltxt = labeltxt
        self.addquotes = True

    def set_label(self, s: str) -> None:
        self.label = s

    def __str__(self) -> str:
        quote = '"' if self.addquotes else ''
        if self.labeltxt is None:
            attrs = ''
        else:
            attrs = ' [ label="' + self.labeltxt + '" ];'
        return (
            quote + self.src + quote + ' -> ' + quote + self.tgt + quote + attrs)


class DotCluster:

    def __init__(self, name: str) -> None:
        self._name = name
        self._edges: Set[Tuple[str, str]] = set([])
        self._style: Optional[str] = None
        self._color: str = "lightgrey"
        self._nodestyle: Optional[str] = None
        self._nodecolor: str = "white"

    @property
    def name(self) -> str:
        return "cluster_" + self._name

    @property
    def edges(self) -> Set[Tuple[str, str]]:
        return self._edges

    def add_edge(self, src: str, tgt: str) -> None:
        self._edges.add((src, tgt))

    def set_filled(self) -> None:
        self._style = "filled"

    def set_node_filled(self) -> None:
        self._nodestyle = "filled"

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("subgraph " + self.name + "{")
        if self._style:
            lines.append("  style=" + self._style + ";")
        lines.append("  color=" + self._color + ";")
        if self._nodestyle:
            lines.append(
                "  node [style="
                + self._nodestyle
                + ",color="
                + self._nodecolor
                + "];")
        else:
            lines.append("  node [color=" + self._nodecolor + "];")
        for (src, tgt) in sorted(self.edges):
            lines.append("  " + '"' + src + '"' + " -> " + '"' + tgt + '"' + ";")
        lines.append("}\n")
        return "\n".join(lines)


class DotGraph:

    def __init__(self, name: str, subgraph: bool = False) -> None:
        self.name = name
        self.nodes: Dict[str, DotNode] = {}
        self.edges: Dict[Tuple[str, str], DotEdge] = {}
        self.rankdir = 'TB'
        self.samerank: List[List[str]] = []
        self._clusters: List[DotCluster] = []
        self._subgraph: bool = subgraph

    @property
    def subgraph(self) -> bool:
        return self._subgraph

    def add_node(
            self,
            name: str,
            labeltxt: Optional[str] = None,
            shaded: bool = False,
            color: Optional[str] = None) -> None:
        if name not in self.nodes:
            if labeltxt is None:
                labeltxt = name
            labeltxt = sanitize(labeltxt)
            self.nodes[name] = DotNode(
                name, labeltxt=labeltxt, shaded=shaded, color=color)

    def add_edge(
            self,
            src: str,
            tgt: str,
            labeltxt: Optional[str] = None) -> None:
        self.add_node(src)
        self.add_node(tgt)
        if not (src, tgt) in self.edges:
            if labeltxt is None:
                labeltxt = ""
            labeltxt = sanitize(labeltxt)
            self.edges[(src, tgt)] = DotEdge(src, tgt, labeltxt)

    def add_cluster(
            self,
            name: str,
            edges: Set[Tuple[str, str]],
            style: Optional[str] = None,
            nodestyle: Optional[str] = None,
            color: str = "lightgrey",
            nodecolor: str = "white") -> None:
        cluster = DotCluster(name)
        for (src, tgt) in edges:
            cluster.add_edge(src, tgt)
        self._clusters.append(cluster)

    def set_top_bottom(self) -> None:
        self.rankdir = 'TB'

    def set_left_to_right(self) -> None:
        self.rankdir = 'LR'

    def set_same_rank(self, nodes: List[str]) -> None:
        result: List[str] = []
        for n in nodes:
            if n.startswith("0x") or "-" in n:
                result.append('"' + n + '"')
            elif "(" in n or ")" in n:
                result.append('"' + n + '"')
            else:
                result.append(n)
        self.samerank.append(result)

    def __str__(self) -> str:
        lines: List[str] = []
        if self.subgraph:
            lines.append("subgraph cluster_" + self.name + "{")
            lines.append('fontsize="24";')
            lines.append('label="' + self.name + '";')
            lines.append("penwidth=0;")
        else:
            lines.append('digraph ' + '"' + self.name + '" {')
        for c in self._clusters:
            lines.append(str(c))
        lines.append(
            'edge [fontname="FreeSans", fontsize="24", '
            + 'labelfontname="FreeSans",labelfontsize="24"]')
        lines.append(
            'node [fontname="FreeSans", fontsize="24", shape="record"]')
        lines.append('rankdir=' + self.rankdir)
        for n in self.nodes:
            lines.append(str(self.nodes[n]))
        for e in self.edges:
            lines.append(str(self.edges[e]))
        for r in self.samerank:
            lines.append("{rank=same; " + "; ".join(r) + "}")
        lines.append(' }')
        return '\n'.join(lines)
