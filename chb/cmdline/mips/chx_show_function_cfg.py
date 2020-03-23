# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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
"""Script to create a function control flow graph in dot format.

This script allows the creation of a function control flow graph in dot
format, and converted to pdf. The dot and pdf file are saved in the
same directory as the executable. Command-line options are provided
to decorate the edges of the control flow graph with branch predicates,
and nodes with calls if present.
"""

import argparse
import json
import os

import chb.util.fileutil as UF
import chb.util.dotutil as UD
import chb.app.AppAccess as AP
import chb.graphics.DotCfg as DC

from chb.util.DotGraph import DotGraph

# resulting dot/pdf file are stored in the 'path' directory

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable')
    parser.add_argument('faddr',help='address of function')
    parser.add_argument('--predicates',help='add branch predicates',action='store_true')
    parser.add_argument('--calls',help='add calls to nodes',action='store_true')
    parser.add_argument('--json',help='save cfg in json format',action='store_true')
    args = parser.parse_args()
    return args    

if __name__ == '__main__':

    args = parse()
    try:
        (path,filename) = UF.get_path_filename('mips-elf',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename,mips=True)
    functionnames = app.userdata.get_function_names()
    def has_function_name(faddr): return functionnames.has_function_name(faddr)
    def get_function_name(faddr): return functionnames.get_function_name(faddr)

    if app.has_function(args.faddr):
        f = app.get_function(args.faddr)
        if f is None:
            print('\n **** Unable to find function ' + faddr + ' *****\n\n')
            exit(1)

        graphname = 'cfg_' + args.faddr
        dotcfg = DC.DotCfg(graphname,
                               f,
                               looplevelcolors=["#FFAAAAFF","#FF5555FF","#FF0000FF"],
                               showpredicates=args.predicates,
                               showcalls=args.calls,mips=True)

        functionname = args.faddr
        if has_function_name(args.faddr):
            functionname = functionname +  ' (' + get_function_name(args.faddr) + ')'
        pdffilename = UD.print_dot(app.path,filename,dotcfg.build())
        print('~' * 80)
        print('Control flow graph for ' + functionname + ' has been saved in '
                  + pdffilename)
        print('~' * 80)

        if args.json:
            jsonsave = {}
            jsonsave['path'] = path
            jsonsave['filename'] = filename
            jsonsave['function'] = args.faddr
            jsonfilename = filename + '_' + graphname + '.json'
            jsonfilename = os.path.join(path,jsonfilename)
            jsonsave['cfg'] = dotcfg.to_json()
            with open(jsonfilename,'w') as fp:
                json.dump(jsonsave,fp,sort_keys=True,indent=3)
            

