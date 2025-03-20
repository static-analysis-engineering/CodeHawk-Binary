# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
import xml.etree.ElementTree as ET
import zipfile

from typing import Dict, List, Mapping, Optional, Sequence, Set, TYPE_CHECKING

from chb.models.DllEnumDefinitions import DllEnumDefinitions, DllEnumValue
from chb.models.DllFunctionSummary import DllFunctionSummary
from chb.models.DllFunctionSummaryLibrary import DllFunctionSummaryLibrary
from chb.models.DllFunctionSummaryRef import DllFunctionSummaryRef
from chb.models.FunctionSummary import FunctionSummary
from chb.models.FunctionSummaryLibrary import FunctionSummaryLibrary
from chb.models.JniFunctionSummary import JniFunctionSummary
from chb.models.JniFunctionSummaryLibrary import JniFunctionSummaryLibrary
from chb.models.SOFunctionSummary import SOFunctionSummary
from chb.models.SOFunctionSummaryLibrary import SOFunctionSummaryLibrary

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.ModelsAccess import ModelsAccess


class SummaryCollection:
    """Represents all summary entities in a single zip file."""

    def __init__(
            self,
            models: "ModelsAccess",
            zipfilename: str) -> None:
        self._models = models
        self._zipfilename = zipfilename
        self._zipfile = zipfile.ZipFile(self.zipfilename, "r")
        self._filenames: List[str] = []
        self._directorynames: List[str] = []
        self._dlls: List[str] = []
        self._dlllibraries: Dict[str, DllFunctionSummaryLibrary] = {}
        self._solibraries: Dict[str, SOFunctionSummaryLibrary] = {}
        self._jnilibraries: Dict[str, JniFunctionSummaryLibrary] = {}
        self._dllenumdefinitions: Dict[str, DllEnumDefinitions] = {}

    @property
    def models(self) -> "ModelsAccess":
        return self._models

    @property
    def zipfile(self) -> zipfile.ZipFile:
        return self._zipfile

    @property
    def zipfilename(self) -> str:
        return self._zipfilename

    @property
    def filenames(self) -> List[str]:
        if len(self._filenames) == 0:
            for info in self.zipfile.infolist():
                self._filenames.append(info.filename)
        return self._filenames

    @property
    def directorynames(self) -> Sequence[str]:
        if len(self._directorynames) == 0:
            result: Set[str] = set([])
            for f in self.filenames:
                result.add(os.path.dirname(f))
            self._directorynames = list(result)
        return self._directorynames

    @property
    def enumdefinitions(self) -> Mapping[str, DllEnumDefinitions]:
        if len(self._dllenumdefinitions) == 0:
            for filename in self.filenames:
                if os.path.dirname(filename) == "constants":

                    # extract enum name from filename
                    basename = os.path.basename(filename)
                    enumname = ""
                    if basename.endswith("_constants.xml"):
                        enumname = basename[:-14]
                    elif basename.endswith("_flags.xml"):
                        enumname = basename[:-10]
                    elif basename.endswith("_types.xml"):
                        enumname = basename[:-10]
                    else:
                        continue
                    try:
                        xnode = self._get_summary_xnode(
                            filename, "symbolic-constants")
                        self._dllenumdefinitions[enumname] = DllEnumDefinitions(
                            self, enumname, xnode)
                    except Exception:
                        print("Problem with loading " + filename)
                        continue
                    else:
                        continue
        return self._dllenumdefinitions

    @property
    def dlllibraries(self) -> Mapping[str, DllFunctionSummaryLibrary]:
        if len(self._dlllibraries) == 0:
            for d in self.directorynames:
                if d.endswith("_dll") or d.endswith("_drv"):
                    self._dlllibraries[d[:-4]] = DllFunctionSummaryLibrary(
                        self, d, d[:-4])
        return self._dlllibraries

    @property
    def solibraries(self) -> Mapping[str, SOFunctionSummaryLibrary]:
        if len(self._solibraries) == 0:
            if "so_functions" in self.directorynames:
                self._solibraries[
                    "so_functions"] = SOFunctionSummaryLibrary(
                        self, "so_functions", "so_functions")
        return self._solibraries

    @property
    def dlls(self) -> Sequence[str]:
        if len(self._dlls) == 0:
            for d in self.directorynames:
                if d.endswith("_dll") or d.endswith("_drv"):
                    self._dlls.append(d[:-4])
        return self._dlls

    def has_dll_enum_definition(self, name: str) -> bool:
        return name in self.enumdefinitions

    def has_dll_enum_value(self, name: str, v: int) -> bool:
        if name in self.enumdefinitions:
            return self.enumdefinitions[name].has_name(v)
        return False

    def dll_enum_value(self, name: str, v: int) -> str:
        if self.has_dll_enum_value(name, v):
            return self.enumdefinitions[name].get_name(v)
        else:
            raise UF.CHBError("No name found for type "
                              + name
                              + " and value "
                              + str(v))

    def enum_constant(self, name: str, v: int) -> str:
        if self.has_dll_enum_value(name, v):
            return self.dll_enum_value(name, v)
        else:
            return str(v)

    def dll_enum_definition(self, name: str) -> Mapping[str, DllEnumValue]:
        if self.has_dll_enum_definition(name):
            return self.enumdefinitions[name].constants
        return {}

    def has_so_functions(self) -> bool:
        return "so_functions" in self.solibraries

    def has_dll(self, dll: str) -> bool:
        return dll in self.dlllibraries

    def has_dll_function_summary(self, dll: str, fname: str) -> bool:
        if dll in self.dlllibraries or self.has_dll(dll):
            return self.dlllibraries[dll].has_function_summary(fname)
        else:
            return False

    def has_so_function_summary(self, fname: str) -> bool:
        if self.has_so_functions():
            return self.solibraries["so_functions"].has_function_summary(fname)
        return False

    def dll_function_summary(self, dll: str, fname: str) -> FunctionSummary:
        if dll in self.dlllibraries:
            return self.dlllibraries[dll].function_summary(fname)
        else:
            raise UF.CHBError("No function summary found for " + dll + ":" + fname)

    def so_function_summary(self, fname: str) -> FunctionSummary:
        return self.solibraries["so_functions"].function_summary(fname)

    def all_function_summaries_in_dll(self, dll: str) -> Sequence[FunctionSummary]:
        if self.has_dll(dll):
            return self.dlllibraries[dll].all_function_summaries()
        else:
            return []

    def all_so_function_summaries(self) -> Sequence[FunctionSummary]:
        if self.has_so_functions():
            return self.solibraries["so_functions"].all_function_summaries()
        else:
            return []

    def retrieve_function_summary(
            self,
            flib: FunctionSummaryLibrary,
            fname: str) -> Optional[FunctionSummary]:
        if flib.is_dll:
            return self.retrieve_dll_function_summary(flib, fname)
        elif flib.is_shared_object:
            return self.retrieve_so_function_summary(flib, fname)
        elif flib.is_jni:
            return self.retrieve_jni_function_summary(flib, fname)
        else:
            raise UF.CHBError("Library type of " + flib.name + " not recognized")

    def retrieve_ref_function_summary_xnode(
            self, kind: str, libname: str, fname: str) -> ET.Element:
        if kind == "dll":
            return self.retrieve_ref_dll_function_summary_xnode(libname, fname)
        elif kind == "so":
            return self.retrieve_ref_so_function_summary_xnode(libname, fname)
        elif kind == "jni":
            return self.retrieve_ref_jni_function_summary_xnode(libname, fname)
        else:
            raise UF.CHBError("Reference kind not recognized: "
                              + kind
                              + " for function summary "
                              + fname)

    def retrieve_all_function_summaries(
            self,
            flib: FunctionSummaryLibrary) -> List[FunctionSummary]:
        libdir = flib.directory
        result: List[FunctionSummary] = []
        for filename in self.filenames:
            if (
                    os.path.dirname(filename) == libdir
                    and filename.endswith(".xml")
                    and not filename.endswith("_ordinal_table.xml")):
                xnode = self._get_summary_xnode(filename, flib.libfun_xmltag)
                if flib.is_dll:
                    xname = xnode.get("name")
                    if xname:
                        xreferto = xnode.find("refer-to")
                        if xreferto is not None:
                            dllsumref = DllFunctionSummaryRef(flib, xname, xnode)
                            result.append(dllsumref)
                        else:
                            dllsum = DllFunctionSummary(flib, xname, xnode)
                            result.append(dllsum)
                if flib.is_shared_object:
                    xname = xnode.get("name")
                    if xname:
                        sosum = SOFunctionSummary(flib, xname, xnode)
                        result.append(sosum)

        return result

    def retrieve_dll_function_summary(
            self,
            dll: FunctionSummaryLibrary,
            fname: str) -> Optional[FunctionSummary]:
        filename = os.path.join(dll.directory, fname + ".xml")
        if filename in self.filenames:
            xnode = self._get_summary_xnode(filename, "libfun")
            xreferto = xnode.find("refer-to")
            if xreferto is not None:
                return DllFunctionSummaryRef(dll, fname, xnode)
            else:
                return DllFunctionSummary(dll, fname, xnode)
        else:
            return None

    def retrieve_ref_dll_function_summary_xnode(
            self, dll: str, fname: str) -> ET.Element:
        filename = os.path.join(dll + "_dll", fname + ".xml")
        if filename in self.filenames:
            return self._get_summary_xnode(filename, "libfun")
        else:
            raise UF.CHBError("Reference file not found for dll "
                              + dll
                              + " and function "
                              + fname)

    def retrieve_so_function_summary(
            self,
            sofunctions: FunctionSummaryLibrary,
            fname: str) -> Optional[FunctionSummary]:
        filename = os.path.join("so_functions", fname + ".xml")
        if filename in self.filenames:
            xnode = self._get_summary_xnode(filename, "libfun")
            return SOFunctionSummary(sofunctions, fname, xnode)
        else:
            return None

    def retrieve_ref_so_function_summary_xnode(
            self, flib: str, fname: str) -> ET.Element:
        filename = os.path.join("so_functions", fname + ".xml")
        if filename in self.filenames:
            return self._get_summary_xnode(filename, "libfun")
        else:
            raise UF.CHBError("Reference file not found for so function "
                              + fname)

    def retrieve_jni_function_summary(
            self,
            jnilib: FunctionSummaryLibrary,
            index: str) -> Optional[FunctionSummary]:
        filename = os.path.join("jni", "jni_" + index + ".xml")
        if filename in self.filenames:
            xnode = self._get_summary_xnode(filename, "jnifun")
            return JniFunctionSummary(jnilib, index, xnode)
        else:
            return None

    def retrieve_ref_jni_function_summary_xnode(
            self, flib: str, fname: str) -> ET.Element:
        # requires more elaborate matching
        raise UF.CHBError("Retrieval of jni references not implemented yet")

    def _get_summary_xnode(self, filename: str, tag: str) -> ET.Element:
        zfile = self.zipfile.read(filename).decode('utf-8')
        try:
            xnode = ET.fromstring(str(zfile)).find(tag)
        except ET.ParseError as e:
            raise UF.CHBError("Parse error in file summary file "
                              + filename
                              + ": "
                              + str(e))
        except UnicodeEncodeError as e:
            raise UF.CHBError('Unicode error in summary file '
                              + filename
                              + ": "
                              + str(e))
        if xnode:
            return xnode
        else:
            raise UF.CHBError('Unable to load summary for '
                              + filename
                              + ": "
                              + tag
                              + " not found")
