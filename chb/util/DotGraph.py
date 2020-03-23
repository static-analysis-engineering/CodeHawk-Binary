# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
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

max_label_length = 64

def sanitize(s):
    if not s is None:
        return s.replace('>','\>').replace('"','\\"').replace('%','\%')

class DotNode(object):

    def __init__(self,name,labeltxt=None,color=None,shaded=False):
        self.name = name
        self.labeltxt = labeltxt
        self.shaded = shaded
        self.color = color
        self.addquotes = True

    def set_label(self,s): self.label = s
    def set_color(self,c): self.color = c
    def set_shaded(self): self.shaded = True

    def __str__(self):
        quote = '"' if self.addquotes else ''
        if self.labeltxt is None:
            labeltxt = ''
        elif len(self.labeltxt) > max_label_length:
            # suppress labels that are too long
            labeltxt =  'label="' + self.name + '\\n...."'
        else:
            labeltxt = 'label="' + self.labeltxt + '"'
        if self.shaded:
            shadetxt = 'style=filled,color=".7 .3 1.0"'
        elif not self.color is None:
            shadetxt = 'style=filled,color="' + self.color + '"'
        else:
            shadetxt = 'style=filled,color=".7 .3 1.0"'
        return (quote + self.name + quote + ' [' + labeltxt + ',' + shadetxt + '];')

class DotEdge(object):

    def __init__(self,src,tgt,labeltxt=None):
        self.src = src
        self.tgt = tgt
        self.bidirectional = False
        self.labeltxt = labeltxt
        self.addquotes = True

    def set_label(self,s): self.label = s

    def __str__(self):
        quote = '"' if self.addquotes else ''
        if self.labeltxt is None:
            attrs = ''
        else:
            attrs = ' [ label="' + self.labeltxt + '" ];'
        return (quote + self.src + quote + ' -> ' + quote + self.tgt + quote + attrs)
        

class DotGraph(object):

    def __init__(self,name):
        self.name = name
        self.nodes = {}
        self.edges = {}
        self.rankdir = 'TB'

    def add_node(self,name,labeltxt=None,shaded=False,color=None):
        if not name in self.nodes:
            labeltxt=sanitize(labeltxt)
            self.nodes[name] = DotNode(name,labeltxt=labeltxt,shaded=shaded,color=color)

    def add_edge(self,src,tgt,labeltxt=None):
        self.add_node(src)
        self.add_node(tgt)
        if not (src,tgt) in self.edges:
            labeltxt=sanitize(labeltxt)
            self.edges[(src,tgt)] = DotEdge(src,tgt,labeltxt)

    def set_top_bottom(self): self.rankdir = 'TB'

    def __str__(self):
        lines = []
        lines.append('digraph ' + '"' + self.name + '" {')
        lines.append('edge [fontname="FreeSans",fontsize="24", ' +
                         'labelfontname="FreeSans",labelfontsize="24"]')
        lines.append('node [fontname="FreeSans",fontsize="24",shape="record"]')
        lines.append('rankdir=' + self.rankdir)
        for n in self.nodes: lines.append(str(self.nodes[n]))
        for e in self.edges: lines.append(str(self.edges[e]))
        lines.append(' }')
        return '\n'.join(lines)
    
