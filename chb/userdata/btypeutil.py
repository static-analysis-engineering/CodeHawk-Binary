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
    "clock_t": 4,
    "int": 4,
    "uchar": 1,
    "uint8_t": 1
    }


def align(offset: int, size: int) -> int:
    if offset % size == 0:
        return offset
    else:
        return ((offset // size) * size) + size


def struct_fields_to_xml(node: ET.Element, fields: List[Dict[str, Any]]) -> None:
    """Add <field> elements to a given <fields> node.

    Each field dictionary is expected to have a name and type field. If type size
    cannot be determined automatically, a size field should be present as well.

    Offsets are computed based on type sizes and natural alignment (that is, a
    2-byte type is 2-aligned, a 4-byte type is 4-aligned etc.). If there is more
    padding (e.g., 1 or 2-byte types are 4-byte aligned), offsets should be
    included as well.
    """

    offset = 0
    for f in fields:
        fnode = ET.Element("field")
        node.append(fnode)
        btype = f["type"]

        fnode.set("name", f["name"])
        btype = f["type"]
        tnode = ET.Element("type")
        fnode.append(tnode)
        tnode.text = btype

        if "size" in f:
            size = f["size"]
        elif btype in named_type_sizes:
            size = named_type_sizes[btype]
        else:
            raise UF.CHBError(
                "Size of struct field cannot be determined: " + f["name"])

        if "offset" in f:
            offset = f["offset"]
        else:
            offset = align(offset, size)

        fnode.set("size", str(size))
        fnode.set("offset", str(offset))
        offset += size


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
    for a in fsummary["args"]:
        pnode = ET.Element("par")
        fintfnode.append(pnode)
        pnode.set("name", a["name"])
        pnode.set("loc", "register")
        pnode.set("reg", registers[count])
        ptnode = ET.Element("type")
        pnode.append(ptnode)
        mk_user_btype(a["type"]).to_xml(ptnode)
        count += 1
    if "returntype" in fsummary:
        rnode = ET.Element("returntype")
        fintfnode.append(rnode)
        mk_user_btype(fsummary["returntype"]).to_xml(rnode)


def mk_user_btype(d: Union[str, Dict[str, Any]]) -> T.UserBType:
    if isinstance(d, str):
        return T.UserNamedBType(d)
    elif "name" in d:
        return T.UserNamedBType(d["name"])
    elif "key" in d:
        if d["key"] == "ptr":
            if "tgt" in d:
                return T.UserPointerBType(mk_user_btype(d["tgt"]))
            else:
                raise UF.CHBError("Expected tgt field for pointer type")
        elif d["key"] == "struct":
            if "fields" in d:
                return T.UserStructBType(mk_field_infos(d["fields"]))
            else:
                raise UF.CHBError("Expected fields field for struct type")
        elif d["key"] == "array":
            if "tgt" in d and "size" in d:
                return T.UserArrayBType(mk_user_btype(d["tgt"]), d["size"])
            else:
                raise UF.CHBError("Expected tgt and size for array type")
        else:
            raise UF.CHBError("Key " + d["key"] + " not recognized for btype")
    else:
        raise UF.CHBError("Expected name or key field in btype")


def mk_field_infos(
        fields: List[Dict[str, Any]]) -> List[T.UserStructBFieldInfo]:
    offset = 0
    result: List[T.UserStructBFieldInfo] = []
    for f in fields:
        btype = f["type"]
        name = f["name"]

        if "size" in f:
            size = f["size"]
        elif btype in named_type_sizes:
            size = named_type_sizes[btype]
        else:
            raise UF.CHBError(
                "size of struct field cannot be determined for " + name)

        if "offset" in f:
            offset = f["offset"]
        else:
            offset = align(offset, size)

        bfieldinfo = T.UserStructBFieldInfo(name, mk_user_btype(btype), offset)
        result.append(bfieldinfo)

        offset += size
    return result
