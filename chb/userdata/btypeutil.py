# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Utilities related to c data types."""

import xml.etree.ElementTree as ET

from typing import Any, Dict, List, Union

import chb.userdata.UserBType as T

import chb.util.fileutil as UF


named_type_sizes = {
    "char": 1,
    "clock_t": 4,
    "int": 4,
    "timeval": 8,
    "uchar": 1,
    "uint8_t": 1,
    "uint32_t": 4,
    "uint64_t": 8
    }

opaque_types = [
    "FILE", "void"
]

user_type_store = T.UserBTypeStore(named_type_sizes)


def align(offset: int, size: int) -> int:
    if offset % size == 0:
        return offset
    else:
        return ((offset // size) * size) + size


def function_summary_to_xml(
        node: ET.Element, name: str, fsummary: Dict[str, Any]) -> None:
    fintfnode = ET.Element("api")
    fintfnode.set("cc", "cdecl")
    fintfnode.set("adj", "0")
    fintfnode.set("name", name)
    semnode = ET.Element("semantics")
    apidocnode = ET.Element("apidoc")
    docnode = ET.Element("documentation")
    docnode.append(apidocnode)
    node.extend([fintfnode, semnode, docnode])
    registers = ["R0", "R1", "R2", "R3"]
    count = 0
    fnargs = fsummary["args"]
    if len(fnargs) > 4:
        regargs = fnargs[:4]
        stackargs = fnargs[4:]
    else:
        regargs = fnargs
        stackargs = []
    for a in regargs:
        pnode = ET.Element("par")
        fintfnode.append(pnode)
        pnode.set("name", a["name"])
        pnode.set("loc", "register")
        pnode.set("reg", registers[count])
        ptnode = ET.Element("type")
        pnode.append(ptnode)
        try:
            mk_user_btype(a["type"]).to_xml(ptnode)
        except UF.CHBError as e:
            raise UF.CHBError(
                "Error in function-summary-to-xml " + name + ": " + str(e))
        count += 1
    count += 1
    for a in stackargs:
        pnode = ET.Element("par")
        fintfnode.append(pnode)
        pnode.set("name", a["name"])
        pnode.set("loc", "stack")
        pnode.set("nr", str(count))
        ptnode = ET.Element("type")
        pnode.append(ptnode)
        try:
            mk_user_btype(a["type"]).to_xml(ptnode)
        except UF.CHBError as e:
            raise UF.CHBError(
                "Error in function-summary-to-xml " + name + ": " + str(e))
        count += 1
    if "returntype" in fsummary:
        rnode = ET.Element("returntype")
        fintfnode.append(rnode)
        try:
            mk_user_btype(fsummary["returntype"]).to_xml(rnode)
        except UF.CHBError as e:
            raise UF.CHBError(
                "Error in function-summary-to-xml " + name + ": " + str(e))


def mk_user_btype(d: Union[str, Dict[str, Any]]) -> T.UserBType:
    if isinstance(d, str) or "name" in d:
        name: str = d if isinstance(d, str) else d["name"]
        if name in opaque_types:
            return T.UserNamedBType(name)
        elif user_type_store.has_size_of(name):
            size = user_type_store.size_of(name)
            return T.UserNamedBType(name, size=size)
        else:
            raise UF.CHBError("Cannot determine size of named type " + name)
    elif "key" in d:
        if d["key"] == "ptr":
            if "tgt" in d:
                try:
                    return T.UserPointerBType(mk_user_btype(d["tgt"]))
                except UF.CHBError as e:
                    raise UF.CHBError("Error in pointer target type: " + str(e))
            else:
                raise UF.CHBError("Expected tgt field for pointer type")
        elif d["key"] == "struct":
            if "fields" in d:
                return T.UserStructBType(mk_field_infos(d["fields"]))
            else:
                raise UF.CHBError("Expected fields field for struct type")
        elif d["key"] == "array":
            if "tgt" in d and "size" in d:
                try:
                    return T.UserArrayBType(mk_user_btype(d["tgt"]), d["size"])
                except UF.CHBError as e:
                    raise UF.CHBError("Error in array target type: " + str(e))
            else:
                raise UF.CHBError("Expected tgt and size for array type")
        else:
            raise UF.CHBError("Key " + d["key"] + " not recognized for btype")
    else:
        raise UF.CHBError("Expected name or key field in btype")


def mk_field_infos(
        fields: List[Dict[str, Any]]) -> List[T.UserStructBFieldInfo]:
    """Create a list of fieldinfos for struct fields, including offsets.

    Each field dictionary is expected to have a name and type field. If type size
    cannot be determined automatically, a size field should be present as well.

    Offsets are computed based on type sizes and natural alignment (that is, a
    2-byte type is 2-aligned, a 4-byte type is 4-aligned etc.). If there is more
    padding (e.g., 1 or 2-byte types are 4-byte aligned), offsets should be
    included as well.
    """
    offset = 0
    result: List[T.UserStructBFieldInfo] = []
    for f in fields:
        name = f["name"]
        try:
            btype = mk_user_btype(f["type"])
        except UF.CHBError as e:
            raise UF.CHBError(
                "Error in parsing struct field " + name + ": " + str(e))

        if "size" in f:
            size = f["size"]
        elif btype.has_size():
            size = btype.size
        else:
            raise UF.CHBError(
                "size of struct field cannot be determined for " + name)

        if "offset" in f:
            offset = f["offset"]
        else:
            offset = align(offset, size)

        bfieldinfo = T.UserStructBFieldInfo(name, btype, offset, size)
        result.append(bfieldinfo)

        offset += size
    return result


def mk_struct(fields: List[Dict[str, Any]]) -> T.UserStructBType:
    fieldinfos = mk_field_infos(fields)
    return T.UserStructBType(fieldinfos)
