# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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

from typing import Any, Callable, Dict, List, Optional

from chb.app.AppResultFunctionMetrics import AppResultFunctionMetrics

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF


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


class AppResultMetrics:

    def __init__(
            self,
            filename: str,
            xnode: ET.Element,
            xheader: ET.Element) -> None:
        self._filename = filename
        self.xnode = xnode
        self.xheader = xheader
        self._functiontotals: Optional[ET.Element] = None
        self._calls: Optional[ET.Element] = None
        self._jumps: Optional[ET.Element] = None
        self._precision: Optional[ET.Element] = None
        self._disassembly: Optional[ET.Element] = None
        self._functions: Dict[str, AppResultFunctionMetrics] = {}
        self._imports: Optional[ET.Element] = None
        self._ccmetrics: Optional[ET.Element] = None

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def fns_included(self) -> List[str]:
        incnode = self.xnode.find("fns-included")
        if incnode is None:
            return []
        addrs = incnode.get("addrs")
        if addrs is None:
            return []
        else:
            return addrs.split(",")

    @property
    def fns_excluded(self) -> List[str]:
        excnode = self.xnode.find("fns-excluded")
        if excnode is None:
            return []
        addrs = excnode.get("addrs")
        if addrs is None:
            return []
        else:
            return addrs.split(",")

    def functions(self) -> Dict[str, AppResultFunctionMetrics]:
        if len(self._functions) == 0:
            fxnode = self.xnode.find("functions")
            if fxnode is None:
                raise UF.CHBError("Functions element missing from resultmetrics")
            else:
                for f in fxnode.findall("fn"):
                    addr = f.get("a")
                    if addr is None:
                        raise UF.CHBError(
                            "Address missing from function in resultmetrics")
                    else:
                        self._functions[addr] = AppResultFunctionMetrics(f)
        return self._functions

    @property
    def functiontotals(self) -> ET.Element:
        if self._functiontotals is None:
            self._functiontotals = self.xnode.find("function-totals")
            if self._functiontotals is None:
                raise UF.CHBError("Function totals missing from resultmetrics")
        return self._functiontotals

    @property
    def calls(self) -> ET.Element:
        if self._calls is None:
            self._calls = self.functiontotals.find("calls")
            if self._calls is None:
                raise UF.CHBError(
                    "Calls missing from function totals in resultmetrics")
        return self._calls

    @property
    def jumps(self) -> ET.Element:
        if self._jumps is None:
            self._jumps = self.functiontotals.find("jumps")
            if self._jumps is None:
                raise UF.CHBError(
                    "Jumps missing from function totals in resultmetrics")
        return self._jumps

    @property
    def precision(self) -> ET.Element:
        if self._precision is None:
            self._precision = self.functiontotals.find("prec")
            if self._precision is None:
                raise UF.CHBError(
                    "Aggregate precision is missing from resultmetrics")
        return self._precision

    @property
    def cc_metrics(self) -> ET.Element:
        if self._ccmetrics is None:
            self._ccmetrics = self.functiontotals.find("cc")
            if self._ccmetrics is None:
                raise UF.CHBError(
                    "CC metrics is missing from resultmetrics")
        return self._ccmetrics

    @property
    def disassembly(self) -> ET.Element:
        if self._disassembly is None:
            self._disassembly = self.xnode.find("disassembly")
            if self._disassembly is None:
                raise UF.CHBError("Disassembly is missing from resultmetrics")
        return self._disassembly

    @property
    def imports(self) -> ET.Element:
        if self._imports is None:
            self._imports = self.disassembly.find("imports")
            if self._imports is None:
                raise UF.CHBError(
                    "Imports is missing from disassembly in resultmetrics")
        return self._imports

    @property
    def date_time(self) -> str:
        r = self.xheader.get("time")
        if r is not None:
            return r
        else:
            raise UF.CHBError("Time is missing from header resultmetrics header")

    @property
    def stable(self) -> str:
        r = self.xnode.get("stable")
        if r is not None:
            return r
        else:
            raise UF.CHBError("Stable is missing from resultmetrics")

    @property
    def analysis_time(self) -> str:
        r = self.xnode.get("time")
        if r is not None:
            return r
        else:
            raise UF.CHBError("Analysis time is missing from resultmetrics")

    @property
    def run_count(self) -> int:
        xruns = self.xnode.find("runs")
        if xruns is not None:
            xrun = xruns.find("run")
            if xrun is not None:
                r = xrun.get("index")
                if r is not None:
                    return int(r)
                else:
                    raise UF.CHBError("Index of run is missing from resultmetrics")
            else:
                raise UF.CHBError("Run is missing from resultmetrics")
        else:
            raise UF.CHBError("Runs is missing from resultmetrics")

    @property
    def esp_precision(self) -> float:
        r = self.precision.get("esp")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Esp precision is missing from resultmetrics")

    @property
    def reads_precision(self) -> float:
        r = self.precision.get("reads")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Reads precision is missing from resultmetrics")

    @property
    def writes_precision(self) -> float:
        r = self.precision.get("writes")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Writes precision is missing from resultmetrics")

    @property
    def cc_instructions(self) -> int:
        r = self.cc_metrics.get("instrs")
        if r is not None:
            return int(r)
        else:
            raise UF.CHBError("CC-metric instructions missing from resultmetrics")

    @property
    def cc_associated(self) -> int:
        r = self.cc_metrics.get("assoc")
        if r is not None:
            return int(r)
        else:
            raise UF.CHBError("CC-metric associated missing from resultmetrics")

    @property
    def cc_predicate(self) -> int:
        r = self.cc_metrics.get("test")
        if r is not None:
            return int(r)
        else:
            raise UF.CHBError("CC-metric test missing from resultmetrics")

    @property
    def calls_count(self) -> int:
        return int(self.calls.get("count", "0"))

    @property
    def unresolved_calls(self) -> int:
        return int(self.calls.get("unr", "0"))

    @property
    def dll_calls(self) -> int:
        return int(self.calls.get("dll", "0"))

    @property
    def so_calls(self) -> int:
        return int(self.calls.get("so", "0"))

    @property
    def app_calls(self) -> int:
        return int(self.calls.get("app", "0"))

    @property
    def application_calls(self) -> int:
        return int(self.calls.get("app", "0"))

    @property
    def inlined_calls(self) -> int:
        return int(self.calls.get("inlined", "0"))

    @property
    def static_dll_calls(self) -> int:
        return int(self.calls.get("staticdll", "0"))

    @property
    def wrapped_calls(self) -> int:
        return int(self.calls.get("wrapped", "0"))

    @property
    def unresolved_jumps(self) -> int:
        return int(self.jumps.get("unr", "0"))

    @property
    def no_summary(self) -> int:
        return int(self.calls.get("no-sum", "0"))

    @property
    def instruction_count(self) -> int:
        return int(self.disassembly.get('instrs', "0"))

    @property
    def function_count(self) -> int:
        return int(self.disassembly.get('functions', "0"))

    @property
    def unknown_instructions(self) -> int:
        return int(self.disassembly.get('unknown-instrs', '0'))

    @property
    def pcoverage(self) -> float:
        return float(self.disassembly.get('pcoverage', "0.0"))

    def time_share(self, count: int) -> Dict[str, float]:
        """Return a list of the most time-intensive functions with %time."""

        topfns = sorted(self.functions().values(), key=lambda f: f.time)[-count:]
        totaltime = float(self.analysis_time)
        result: Dict[str, float] = {}
        for f in topfns:
            result[f.faddr] = f.time / totaltime
        return result

    def get_fn_instr_counts(self) -> List[int]:
        result: List[int] = []
        for fn in self.functions():
            result.append(self.functions()[fn].instruction_count)
        return result

    def get_fn_esp_precisions(self, mininstructioncount: int = 0) -> List[float]:
        result: List[float] = []
        for fn in self.functions():
            instrcount = int(self.functions()[fn].instruction_count)
            if instrcount >= mininstructioncount:
                result.append(float(self.functions()[fn].espp))
        return result

    def get_runtime_loads(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for f in self.imports.findall('import'):
            if 'loaded' in f.attrib:
                name = f.get('name')
                if name is not None:
                    result.setdefault(name, 0)
                    result[name] += int(f.get("count", "0"))
        return result

    def get_imported_dll_functions(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for f in self.imports.findall('import'):
            if 'loaded' not in f.attrib:
                name = f.get('name')
                if name is not None:
                    result.setdefault(name, 0)
                    result[name] += int(f.get("count", "0"))
        return result

    def get_function_results(self) -> List[AppResultFunctionMetrics]:
        return list(self.functions().values())

    def get_function_metrics(self, f: str) -> AppResultFunctionMetrics:
        if f in self.functions():
            return self.functions()[f]
        else:
            raise UF.CHBError("Function " + f + " not found")

    def iter(self, f: Callable[[AppResultFunctionMetrics], None]) -> None:
        for fn in self.get_function_results():
            f(fn)

    def get_names(self) -> Dict[str, List[str]]:
        """Return a mapping from function names to function addresses."""

        names: Dict[str, List[str]] = {}

        def f(fn: AppResultFunctionMetrics) -> None:
            if fn.has_name():
                name = fn.name
                names.setdefault(name, [])
                names[name].append(fn.faddr)

        self.iter(f)
        return names

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["instructions"] = int(self.instruction_count)
        content["unknowninstrs"] = int(self.unknown_instructions)
        content["functions"] = int(self.function_count)
        content["functioncoverage"] = float(self.pcoverage)
        content["espprecision"] = self.esp_precision
        content["readsprecision"] = self.reads_precision
        content["writesprecision"] = self.writes_precision
        content["unresolvedjumps"] = self.unresolved_jumps
        content["calls"] = self.calls_count
        content["unresolvedcalls"] = self.unresolved_calls
        content["appcalls"] = self.app_calls
        content["so-calls"] = self.so_calls
        content["no-summaries"] = self.no_summary
        content["analysistime"] = float(self.analysis_time)
        content["iterations"] = self.run_count
        content["analysisdate"] = self.date_time
        content["fns-excluded"] = self.fns_excluded
        return JSONResult("analysisstats", content, "ok")

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result['name'] = self.filename
        result['functions'] = {}

        def f(fn: AppResultFunctionMetrics) -> None:
            result['functions'][fn.faddr] = fn.as_dictionary()

        self.iter(f)
        result['disassembly'] = self.disassembly_as_dictionary()
        result['analysis'] = self.analysis_as_dictionary()
        return result

    def disassembly_as_dictionary(self) -> Dict[str, Any]:
        localetable = UF.get_locale_tables(categories=["ResultMetrics"])
        result: Dict[str, Any] = {}
        result['instrcount'] = self.instruction_count
        result['unknown'] = self.unknown_instructions
        result['functioncount'] = self.function_count
        result['coverage'] = self.pcoverage
        return result

    def disassembly_to_string(self) -> str:
        lines: List[str] = []
        lines.append('-' * 80)
        lines.append('Disassembly Summary')
        lines.append('-' * 80)
        lines.append('Instruction count: ' + str(self.instruction_count).rjust(8))
        lines.append('Unknown instrs   : ' + str(self.unknown_instructions).rjust(8))
        lines.append('Function count   : ' + str(self.function_count).rjust(8))
        lines.append('Function coverage: ' + str(self.pcoverage).rjust(8) + '%')
        lines.append('-' * 80)
        return '\n'.join(lines)

    def analysis_as_dictionary(self) -> Dict[str, Any]:
        localetable = UF.get_locale_tables(categories=["ResultMetrics"])
        result: Dict[str, Any] = {}
        result['datetime'] = self.date_time
        result['espp'] = self.esp_precision
        result['readsp'] = self.reads_precision
        result['writesp'] = self.writes_precision
        result['unrjumps'] = self.unresolved_jumps
        result['calls'] = self.calls_count
        result['unrcalls'] = self.unresolved_calls
        result['nosummaries'] = self.no_summary
        result['appcalls'] = self.app_calls
        result['dllcalls'] = self.dll_calls
        result['so-calls'] = self.so_calls
        result['inlinedcalls'] = self.inlined_calls
        result['analysistime'] = self.analysis_time
        result['iterations'] = self.run_count
        return result

    def summary(self) -> Dict[str, Any]:
        result = self.analysis_as_dictionary()
        result.update(self.disassembly_as_dictionary())
        return result

    def analysis_to_string(self) -> str:
        lines: List[str] = []
        lines.append('-' * 80)
        lines.append('Analysis Summary')
        lines.append('-' * 80)
        lines.append(
            'Esp precision   : ' + str(self.esp_precision).rjust(8) + '%')
        lines.append(
            'Reads precision : ' + str(self.reads_precision).rjust(8) + '%')
        lines.append(
            'Writes precision: ' + str(self.writes_precision).rjust(8) + '%')
        lines.append(
            'Unresolved jumps: ' + str(self.unresolved_jumps).rjust(8))
        lines.append(
            "Cc connected    : "
            + (str(self.cc_associated)
               + " / "
               + str(self.cc_instructions)).rjust(8))
        lines.append(
            "Cc predicate    : "
            + (str(self.cc_predicate)
               + " / "
               + str(self.cc_instructions)).rjust(8))
        lines.append('Calls           : ' + str(self.calls_count).rjust(8))
        lines.append("App calls       : " + str(self.app_calls).rjust(8))
        lines.append('Unresolved calls: ' + str(self.unresolved_calls).rjust(8))
        lines.append('No summaries    : ' + str(self.no_summary).rjust(8))
        lines.append('Dll calls       : ' + str(self.dll_calls).rjust(8))
        lines.append("SO calls        : " + str(self.so_calls).rjust(8))
        lines.append('Static dll calls: ' + str(self.static_dll_calls).rjust(8))
        lines.append('Inlined calls   : ' + str(self.inlined_calls).rjust(8))
        lines.append('Wrapped calls   : ' + str(self.wrapped_calls).rjust(8))
        lines.append(
            'Analysis time   : ' + str(self.analysis_time).rjust(8) + ' secs')
        lines.append('Iterations      : ' + str(self.run_count).rjust(8))
        lines.append('-' * 80)
        return '\n'.join(lines)

    def header_to_string(self, space: str = "   ") -> str:
        lines: List[str] = []
        lines.append('-' * 80)
        lines.append(
            'function   '
            + space
            + 'esp'.center(6)
            + space
            + 'reads'.center(6)
            + space
            + 'writes'.center(6)
            + space
            + 'unrc'.center(6)
            + space
            + 'blocks'.center(6)
            + space
            + 'instrs'.center(6)
            + space
            + 'time'.center(8))
        lines.append('-' * 80)
        return '\n'.join(lines)
