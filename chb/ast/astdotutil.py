# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs, LLC
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

import subprocess

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

nodecolors: Dict[str, str] = {
    "stmt": "aqua",
    "instr": "cornflowerblue",
    "lval": "darkolivegreen1",
    "var": "aquamarine",
    "expr": "darkorange",
    "cst": "gold"
}


class ASTDotNode:

    def __init__(
            self,
            name: str,
            labeltxt: Optional[str] = None,
            color: Optional[str] = None,
            shaded: bool = False) -> None:
        self._name = name
        self._labeltxt = labeltxt
        self._shaded = shaded
        self._color = color

    @property
    def name(self) -> str:
        return self._name

    @property
    def label(self) -> str:
        if self._labeltxt is None:
            return self.name
        else:
            return self._labeltxt

    @property
    def color(self) -> str:
        if self._color is None:
            return '.7 .3 1.0'
        else:
            return self._color

    def __str__(self) -> str:
        quote = '"'
        nodelabel = 'label="' + self.label + '"'
        if self.color is None:
            color = '.7 .3 1.0'
        else:
            color = self.color
        return (
            quote
            + self.name
            + quote
            + ' ['
            + nodelabel
            + 'style=filled,color="' + color + '"'
            + '];')


class ASTDotEdge:

    def __init__(self, src: str, tgt: str, labeltxt: Optional[str] = None) -> None:
        self._src = src
        self._tgt = tgt
        self._labeltxt = labeltxt

    @property
    def src(self) -> str:
        return self._src

    @property
    def tgt(self) -> str:
        return self._tgt

    @property
    def label(self) -> Optional[str]:
        return self._labeltxt

    def __str__(self) -> str:
        quote = '"'
        if self.label is None:
            attrs = ';'
        else:
            attrs = ' [ label="' + self.label + '" ];'
        return (
            quote + self.src + quote + ' -> ' + quote + self.tgt + quote + attrs)


class ASTDotGraph:

    def __init__(
            self,
            name: str,
            samerank: List[str] = ["instr"],
            maxrank: List[str] = ["var"]) -> None:
        self._name = name
        self._nodes: Dict[str, ASTDotNode] = {}
        self._edges: Dict[Tuple[str, str], ASTDotEdge] = {}
        self._samerank: List[str] = samerank
        self._maxrank: List[str] = maxrank

    @property
    def name(self) -> str:
        return self._name

    @property
    def nodes(self) -> Dict[str, ASTDotNode]:
        return self._nodes

    @property
    def edges(self) -> Dict[Tuple[str, str], ASTDotEdge]:
        return self._edges

    @property
    def samerank(self) -> List[str]:
        """Return name fragment filter strings to add same rank directives."""

        return self._samerank

    @property
    def maxrank(self) -> List[str]:
        """Return name fragment filter strings to add max rank directives."""

        return self._maxrank

    @property
    def samerank_directives(self) -> List[str]:
        result: List[str] = []
        for fragment in self.samerank:
            sr: List[str] = []
            for node in self.nodes.values():
                if fragment in node.name:
                    sr.append(node.name)
            if len(sr) > 0:
                result.append('{rank=same; "' + '"; "'.join(sr) + '";}')
        return result

    @property
    def maxrank_directives(self) -> List[str]:
        result: List[str] = []
        for fragment in self.maxrank:
            mr: List[str] = []
            for node in self.nodes.values():
                if fragment in node.name:
                    mr.append(node.name)
            if len(mr) > 0:
                result.append('{rank=max; "' + '"; "'.join(mr) + '";}')
        return result

    def add_node(
            self,
            name: str,
            labeltxt: Optional[str] = None,
            color: Optional[str] = None) -> None:
        if name not in self.nodes:
            self._nodes[name] = ASTDotNode(name, labeltxt=labeltxt, color=color)

    def add_edge(
            self,
            src: str,
            tgt: str,
            labeltxt: Optional[str] = None) -> None:
        if not (src, tgt) in self.edges:
            self._edges[(src, tgt)] = ASTDotEdge(src, tgt, labeltxt=labeltxt)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append('digraph ' + '"ast" {')
        lines.append(
            'node [fontname="FreeSans", fontsize="24", shape="record"]')
        lines.append('rankdir=LR')
        for n in self.nodes:
            lines.append(str(self.nodes[n]))
        for e in self.edges:
            lines.append(str(self.edges[e]))
        for sr in self.samerank_directives:
            lines.append(sr)
        for mr in self.maxrank_directives:
            lines.append(mr)
        lines.append(' }')
        return '\n'.join(lines)


def print_dot(
        filename: str,
        g: "ASTDotGraph") -> str:
    dotfilename = filename + ".dot"
    pdffilename = filename + ".pdf"

    # write graph to dot format
    with open(dotfilename, "w") as fp:
        fp.write(str(g))

    # convert dot file to pdf
    cmd = ["dot", "-Tpdf", "-o", pdffilename, dotfilename]
    try:
        subprocess.call(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("Error in processing dot file: " + dotfilename)
        print(e.output)
        print(e.args)
        exit(1)
    return pdffilename
