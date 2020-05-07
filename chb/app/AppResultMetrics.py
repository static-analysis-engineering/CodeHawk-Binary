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


import xml.etree.ElementTree as ET

import chb.util.fileutil as UF

from chb.app.AppResultFunctionMetrics import AppResultFunctionMetrics

disassembly_attributes = [
    "instrcount",
    "unknown",
    "functioncount",
    "coverage"
    ]

analysis_attributes = [
    "datetime",
    "espp",
    "readsp",
    "writesp",
    "unrjumps",
    "calls",
    "unrcalls",
    "nosummaries",
    "dllcalls",
    "inlinedcalls",
    "analysistime",
    "iterations"
    ]

class AppResultMetrics(object):

    def __init__(self,app,xnode,xheader):
        self.app = app
        self.xresults = xnode
        self.xheader = xheader
        self.functiontotals = self.xresults.find('function-totals')
        self.disassembly = self.xresults.find('disassembly')
        self.functions = {}

    def get_name(self):
        return self.app.filename

    def get_date_time(self):
        return self.xheader.get('time')

    def get_stable(self):
        return self.xresults.find.get('stable')

    def get_analysis_time(self):
        return self.xresults.get('time')

    def get_run_count(self):
        return self.xresults.find('runs').find('run').get('index')

    def get_esp(self):
        return float(self.functiontotals.find('prec').get('esp'))

    def get_reads(self):
        return float(self.functiontotals.find('prec').get('reads'))

    def get_writes(self):
        return float(self.functiontotals.find('prec').get('writes'))

    def get_calls(self):
        return int(self.functiontotals.find('calls').get('count','0'))

    def get_unresolved_calls(self):
        return int(self.functiontotals.find('calls').get('unr','0'))

    def get_dll_calls(self):
        return int(self.functiontotals.find('calls').get('dll','0'))

    def get_application_calls(self):
        return int(self.functiontotals.find('calls').get('app','0'))

    def get_inlined_calls(self):
        return int(self.functiontotals.find('calls').get('inlined','0'))

    def get_static_dll_calls(self):
        return int(self.functiontotals.find('calls').get('staticdll','0'))

    def get_wrapped_calls(self):
        return int(self.functiontotals.find('calls').get('wrapped','0'))

    def get_unresolved_jumps(self):
        return int(self.functiontotals.find('jumps').get('unr','0'))

    def get_no_sum(self):
        return int(self.functiontotals.find('calls').get('no-sum',0))

    def get_instr_count(self):
        return int(self.disassembly.get('instrs'))

    def get_function_count(self):
        return int(self.disassembly.get('functions'))

    def get_unknown_instrs(self):
        return int(self.disassembly.get('unknown-instrs','0'))

    def get_pcoverage(self):
        return float(self.disassembly.get('pcoverage'))

    def get_fn_instr_counts(self):
        self._initializefunctions()
        result = []
        for fn in self.functions:
            result.append(int(self.functions[fn].get_instrs()))
        return result

    def get_fn_esp_precisions(self,mininstructioncount=0):
        self._initializefunctions()
        result = []
        for fn in self.functions:
            instrcount = int(self.functions[fn].get_instrs())
            if instrcount >= mininstructioncount:
                result.append(float(self.functions[fn].get_espp()))
        return result

    def get_runtime_loads(self):
        result = {}
        for f in self.disassembly.find('imports').findall('import'):
            if 'loaded' in f.attrib:
                name = f.get('name')
                if not name in result: result[name] = 0
                result[name] += int(f.get('count'))
        return result

    def get_imported_dll_functions(self):
        result = {}
        for f in self.disassembly.find('imports').findall('import'):
            if not 'loaded' in f.attrib:
                name = f.get('name')
                if not name in result: result[name] = 0
                result[name] += int(f.get('count'))
        return result

    def get_function_results(self):
        self._initialize_functions()
        return self.functions.values()

    def get_function_metrics(self,f):
        self._initialize_functions()
        if f in self.functions:
            return self.functions[f]

    def iter(self,f):
        for fn in self.get_function_results(): f(fn)

    def get_names(self):
        names = {}
        def f(fn):
            if fn.has_name():
                name = fn.get_name()
                if not name in names: names[name] = []
                names[name].append(fn.faddr)
        self.iter(f)
        return names

    def as_dictionary(self):
        result = {}
        result['name'] = self.get_name()
        result['functions'] = {}
        def f(fn): result['functions'][fn.faddr] = fn.as_dictionary()
        self.iter(f)
        result['disassembly'] = self.disassembly_as_dictionary()
        result['analysis'] = self.analysis_as_dictionary()
        return result

    def disassembly_as_dictionary(self):
        localetable = UF.get_locale_tables(categories=[ "ResultMetrics" ])
        result = {}
        '''
        for p in disassembly_attributes:
            result[p] = {}
            result[p]['heading'] = localetable['disassembly'][p]
        '''
        result['instrcount'] = self.get_instr_count()
        result['unknown'] = self.get_unknown_instrs()
        result['functioncount'] = self.get_function_count()
        result['coverage'] = self.get_pcoverage()
        return result

    def disassembly_to_string(self):
        lines = []
        lines.append('-' * 80)
        lines.append('Disassembly Summary')
        lines.append('-' * 80)
        lines.append('Instruction count: ' + str(self.get_instr_count()).rjust(8))
        lines.append('Unknown instrs   : ' + str(self.get_unknown_instrs()).rjust(8))
        lines.append('Function count   : ' + str(self.get_function_count()).rjust(8))
        lines.append('Function coverage: ' + str(self.get_pcoverage()).rjust(8) + '%')
        lines.append('-' * 80)
        return '\n'.join(lines)

    def analysis_as_dictionary(self):
        localetable = UF.get_locale_tables(categories=[ "ResultMetrics" ])
        result = {}
        '''
        for p in analysis_attributes:
            result[p] = {}
            result[p]['heading'] = localetable['analysis'][p]
        '''
        result['datetime'] = self.get_date_time()
        result['espp'] = self.get_esp()
        result['readsp'] = self.get_reads()
        result['writesp'] = self.get_writes()
        result['unrjumps'] = self.get_unresolved_jumps()
        result['calls'] = self.get_calls()
        result['unrcalls'] =  self.get_unresolved_calls()
        result['nosummaries'] = self.get_no_sum()
        result['dllcalls'] = self.get_dll_calls()
        result['inlinedcalls'] = self.get_inlined_calls()
        result['analysistime'] = self.get_analysis_time()
        result['iterations'] = self.get_run_count()
        return result

    def summary(self):
        result = self.analysis_as_dictionary()
        result.update(self.disassembly_as_dictionary())
        return result

    def analysis_to_string(self):
        lines = []
        lines.append('-' * 80)
        lines.append('Analysis Summary')
        lines.append('-' * 80)
        lines.append('Esp precision   : ' + str(self.get_esp()).rjust(8) + '%')
        lines.append('Reads precision : ' + str(self.get_reads()).rjust(8) + '%')
        lines.append('Writes precision: ' + str(self.get_writes()).rjust(8) + '%')
        lines.append('Unresolved jumps: ' + str(self.get_unresolved_jumps()).rjust(8))
        lines.append('Calls           : ' + str(self.get_calls()).rjust(8))
        lines.append('Unresolved calls: ' + str(self.get_unresolved_calls()).rjust(8))
        lines.append('No summaries    : ' + str(self.get_no_sum()).rjust(8))
        lines.append('Dll calls       : ' + str(self.get_dll_calls()).rjust(8))
        lines.append('Static dll calls: ' + str(self.get_static_dll_calls()).rjust(8))
        lines.append('Inlined calls   : ' + str(self.get_inlined_calls()).rjust(8))
        lines.append('Wrapped calls   : ' + str(self.get_wrapped_calls()).rjust(8))
        lines.append('Analysis time   : ' + str(self.get_analysis_time()).rjust(8) + ' secs')
        lines.append('Iterations      : ' + str(self.get_run_count()).rjust(8))
        lines.append('-' * 80)
        return '\n'.join(lines)

    def header_to_string(self,space='   '):
        lines  = []
        lines.append('-' * 80)
        lines.append('function   ' + space + 'esp'.center(6) + space
                        + 'reads'.center(6) + space
                        + 'writes'.center(6) + space
                        + 'unrc'.center(6) + space
                        + 'blocks'.center(6) + space
                        + 'instrs'.center(6) + space
                        + 'time'.center(8))
        lines.append('-' * 80)
        return '\n'.join(lines)
    
    def _initialize_functions(self):
        if len(self.functions) > 0: return
        for f in self.xresults.find('functions').findall('fn'):
            self.functions[f.get('a')] = AppResultFunctionMetrics(self,f)
                                    
