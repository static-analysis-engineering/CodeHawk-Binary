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

import os
import subprocess


def print_dot(path,filename,g):
    filename = filename + '_' + g.name
    dotfilename = os.path.join(path,filename + '.dot')
    pdffilename = os.path.join(path,filename + '.pdf')
    with open(dotfilename,'w') as fp:
        fp.write(str(g))
    cmd = [ 'dot', '-Tpdf', '-o', pdffilename, dotfilename ]
    try:
        subprocess.call(cmd,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print('Error in processing dot file: ' + dotfilename)
        print(e.output)
        print(e.args)
        exit(1)
    return pdffilename        

def save_dot(path,filename,g):
    filename = filename + '_' + g.name
    dotfilename = os.path.join(path,filename + '.dot')
    with open(dotfilename,'w') as fp:
        fp.write(str(g))

def save_svg(path,filename,g):
    filename = filename + '_' + g.name
    dotfilename = os.path.join(path,filename + '.dot')
    svgfilename = os.path.join(path,filename + '.svg')
    with open(dotfilename,'w') as fp:
        fp.write(str(g))
    cmd = [ 'dot', '-Tsvg', '-o', svgfilename, dotfilename ]
    subprocess.call(cmd,stderr=subprocess.STDOUT)
