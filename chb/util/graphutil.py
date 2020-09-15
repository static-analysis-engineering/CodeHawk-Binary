# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
import time

class SearchTimeoutException(Exception):

    def __init__(self,timespent):
        self.timespent = timespent

    def __str__(self):
        return 'timeout at ' + str(self.timespent)

class DirectedGraph(object):

    def __init__(self,nodes,edges):
        self.nodes = nodes
        self.edges = edges    # adjacency list: n -> [ n ]
        self.paths = []
        self.maxtime = None
        self.starttime = 0.0

    def find_paths_aux(self,src,dst,visited,path,depth=0):
        visited[src] = True
        path.append(src)
        if not dst and (not src in self.edges):
            self.paths.append(path[:])
        elif src == dst:
            self.paths.append(path[:])
        elif src in self.edges:
            for d in self.edges[src]:
                if not visited[d]:
                    self.find_paths_aux(d,dst,visited,path,depth+1)
        path.pop()
        visited[src] = False
        if self.maxtime:
            timespent = time.time() - self.starttime
            if timespent > self.maxtime:
                raise SearchTimeoutException(timespent)

    def find_paths(self,src,dst=None,maxtime=None):
        self.starttime = time.time()
        self.maxtime = maxtime
        visited = {}
        for n in self.nodes:
            visited[n] = False
        try:
            self.find_paths_aux(src,dst,visited,[])
        except SearchTimeoutException as e:
            print(str(e))
