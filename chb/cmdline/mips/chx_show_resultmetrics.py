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
"Prints analysis statistics for the functions in this executable."""

import argparse

import chb.util.fileutil as UF
import chb.app.AppAccess as AP


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable')
    parser.add_argument('--nocallees',help='indicate function without callees',
                            action='store_true')
    parser.add_argument('--sortbytime',help='sort results by analysis  time',
                            action='store_true')
    args = parser.parse_args()
    return args


if __name__ == '__main__':

    args = parse()
    try:
        (path,filename) = UF.get_path_filename('mips-elf',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.XHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename,mips=True)
    metrics = app.get_result_metrics()

    print(metrics.header_to_string())

    if args.sortbytime:
        for f in sorted(metrics.get_function_results(),key=lambda(f):(f.get_time(),f.faddr)):
            print(f.metrics_to_string(shownocallees=args.nocallees))

    else:
        for f in sorted(metrics.get_function_results(),key=lambda(f):(f.get_espp(),f.faddr)):
            print(f.metrics_to_string(shownocallees=args.nocallees))
    
    print(metrics.disassembly_to_string())
    print(metrics.analysis_to_string())
