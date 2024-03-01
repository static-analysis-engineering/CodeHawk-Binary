# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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
"""Common schemas used throughout the binary analyzer python api."""

from typing import Any, Dict, List, Optional, TYPE_CHECKING, Union


def prop_kind(names: List[str]) -> Dict[str, Union[str, List[str]]]:
    kprop: Dict[str, Union[str, List[str]]] = {}
    kprop["type"] = "string"
    kprop["enum"] = names
    return kprop


def prop_set(
        names: List[str]) -> Dict[
            str, Union[str, Dict[str, Union[str, List[str]]]]]:
    kprop: Dict[str, Union[str, Dict[str, Union[str, List[str]]]]] = {}
    kitems: Dict[str, Union[str, List[str]]] = {}
    kprop["type"] = "array"
    kprop["items"] = kitems = {}
    kitems["type"] = "string"
    kitems["enum"] = names
    return kprop


def txtrep() -> Dict[str, str]:
    t: Dict[str, str] = {}
    t["type"] = "string"
    t["description"] = "suggested textual representation"
    return t


def refdef(name: str) -> Dict[str, str]:
    r: Dict[str, str] = {}
    r["$ref"] = "#/$defs/" + name
    # r["$ref"] = name + ".json"
    return r


def strtype(desc: Optional[str] = None) -> Dict[str, str]:
    s: Dict[str, str] = {}
    s["type"] = "string"
    if desc is not None:
        s["description"] = desc
    return s


def strtupletype(
        tag1: str, tag2: str, desc: Optional[str] = None) -> Dict[str, Any]:
    s: Dict[str, Any] = {}
    s["type"] = "object"
    if desc is not None:
        s["description"] = desc
    s["properties"] = {}
    s["properties"][tag1] = strtype()
    s["properties"][tag2] = strtype()
    return s


def intvalue(desc: Optional[str] = None) -> Dict[str, Optional[str]]:
    v: Dict[str, Optional[str]] = {}
    v["type"] = "integer"
    if desc is not None:
        v["description"] = desc
    return v


stackpointeroffset = {
    "name": "stackpointeroffset",
    "title": "stackpointer offset",
    "description": (
        "value or range of values of the stack pointer "
        + "relative to the value at the function entry, "
        + "as determined by the analysis, or unknown"),
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "typically used for unknown value",
            "required": ["kind", "txtrep"],
            "properties": {
                "kind": prop_kind(["unb-itv"]),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "single (usually negative) value",
            "required": ["kind", "value", "txtrep"],
            "properties": {
                "kind": prop_kind(["civ"]),
                "value": intvalue(),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "closed interval specified by minimum and maximum value"),
            "required": ["kind", "lb", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind(["itv"]),
                "lb": intvalue(desc="lower-bound of offset value"),
                "ub": intvalue(desc="upper-bound of offset value"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": ("right open interval specified by lower bound"),
            "required": ["kind", "lb", "txtrep"],
            "properties": {
                "kind": prop_kind(["lb-itv"]),
                "lb": intvalue(desc="lower-bound on offset value"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "descripotion": ("left open interval specified by upper bound"),
            "required": ["kind", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind(["ub-itv"]),
                "ub": intvalue(desc="upper-bound on offset value"),
                "txtrep": txtrep()
            }
        }
    ]
}


assemblyinstruction = {
    "name": "assemblyinstruction",
    "title": "assembly instruction",
    "description": (
        "Single assembly instruction at a given address within a function "
        + "annotated with analysis information"),
    "type": "object",
    "required": ["addr", "bytes", "opcode", "annotation"],
    "properties": {
        "addr": {
            "type": "array",
            "description": (
                "list of context addresses within the function "
                + "instruction address last"),
            "items": strtype(desc="hex address")
        },
        "stackpointer": refdef("stackpointeroffset"),
        "bytes": strtype(
            desc="hexadecimal representation of the instruction bytes"),
        "opcode": {
            "type": "array",
            "description": (
                "standard assembly instruction representation, possibly broken in "
                + "opcode part and operands part for better formatting"),
            "items": strtype()
        },
        "annotation": strtype(
            desc="representation of instruction semantics using invariants")
    }
}


assemblyblock = {
    "name": "assemblyblock",
    "title": "assembly block",
    "description": (
        "Range of instructions within a function that form a basic block"),
    "type": "object",
    "required": ["startaddr", "endaddr"],
    "properties": {
        "startaddr": strtype(
            desc="hexaddress of the first instruction of the block"),
        "endaddr": strtype(
            desc=(
                "hexaddress of the (syntactically) last instruction of the "
                + "block. Note that this would be the address of the delay "
                + "slot for a MIPS assembly block, which is not the last "
                + "instruction to be executed")),
        "instructions": {
            "type": "array",
            "description": "list of assembly instructions contained in the block",
            "items": refdef("assemblyinstruction")
        }
    }
}


assemblyfunction = {
    "name": "assemblyfunction",
    "title": "assembly function",
    "description": ("Collection of basic blocks that make up a function"),
    "type": "object",
    "properties": {
        "name": strtype(
            desc=(
                "(optional) name of the function from symbol information "
                + "or user-provided")),
        "faddr": strtype(
            desc=(
                "hexaddress of function entry point. Note that this address "
                + "is not necessarily the lowest address of the function.")),
        "md5hash": strtype(
            desc=(
                "md5 hash of the hex-encoded bytes of the function instructions")),
        "basicblocks": {
            "type": "array",
            "description": ("list of basic blocks included in the function"),
            "items": refdef("assemblyblock")
        }
    }
}


cfgnode = {
    "name": "cfgnode",
    "title": "node in a control flow graph identified by its hex starting address",
    "description": "All information associated with a node in the cfg",
    "type": "object",
    "required": ["baddr", "code"],
    "properties": {
        "baddr": strtype(
            desc=("hexaddress of the first instruction in the basic block")),
        "code": refdef("assemblyblock"),
        "nesting-level": intvalue(
            desc="loop depth of the node in the control flow graph")
    }
}


cfgedge = {
    "name": "cfgedge",
    "title": "control flow graph edge",
    "description": "Directed edge between two control flow graph nodes",
    "type": "object",
    "required": ["src", "tgt", "kind"],
    "properties": {
        "src": strtype("block address of source node"),
        "tgt": strtype("block address of target node"),
        "kind": {
            "type": "string",
            "description": (
                "true/false indicates conditional branch, table indicates jumptable, "
                + "single indicates an edge always taken"),
            "enum": ["true", "false", "table", "single"]
        },
        "predicate": refdef("xexpression")
    }
}


controlflowgraph = {
    "name": "controlflowgraph",
    "title": "control flow graph",
    "description": ("Graph representation of the control flow of a function"),
    "type": "object",
    "properties": {
        "name": strtype(
            desc=(
                "(optional) name of the function from symbol information "
                + " or user-provided")),
        "faddr": strtype(
            desc=(
                "hexaddress of function entry point. Note that this address "
                + " is not necessarily the lowest address of the function.")),
        "md5hash": strtype(
            desc=(
                "md5 hash of the hex-encoded bytes of the function instructions")),
        "nodes": {
            "type": "array",
            "description": ("list of basic block nodes constituting the function"),
            "items": refdef("cfgnode")
        },
        "edges": {
            "type": "array",
            "description": ("list of edges between the nodes"),
            "items": refdef("cfgedge")
        }
    }
}


memoryoffset = {
    "name": "memoryoffset",
    "title": "memory offset",
    "description": "(possibly symbolic) offset in bytes from a memory base",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "no offset",
            "required": ["kind"],
            "properties": {
                "kind": prop_kind(["none"])
            }
        },
        {
            "type": "object",
            "description": "constant numerical offset",
            "required": ["kind", "value", "txtrep"],
            "properties": {
                "kind": prop_kind(["cv"]),
                "value": intvalue(desc="offset value in bytes"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "constant numerical offset with suboffset",
            "required": ["kind", "value", "suboffset", "txtrep"],
            "properties": {
                "kind": prop_kind(["cvo"]),
                "value": intvalue(desc="offset value in bytes"),
                "suboffset": {"$ref": "#"},
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "index offset with variable and element size",
            "required": ["kind", "ixvar", "elsize", "txtrep"],
            "properties": {
                "kind": prop_kind(["iv"]),
                "ixvar": refdef("xvariable"),
                "elsize": intvalue(desc="size of element indexed"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "index offset with suboffset",
            "required": ["kind", "ixvar", "elsize", "suboffset", "txtrep"],
            "properties": {
                "kind": prop_kind(["ivo"]),
                "ixvar": refdef("xvariable"),
                "elsize": intvalue(desc="size of element indexed"),
                "suboffset": {"$ref": "#"},
                "txtrep": txtrep()
            }
        }
    ]
}


memorybase = {
    "name": "memorybase",
    "title": "memory base",
    "description": "(symbolic) pointer to base of memory region",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "known base: function stack frame or global",
            "required": ["stack"],
            "properties": {
                "stack": {
                    "type": "string",
                    "enum": ["local", "allocated", "realigned", "global"]
                }
            }
        },
        {
            "type": "object",
            "description": "pointer contained in fixed-value variable",
            "required": ["ptrvar"],
            "properties": {
                "ptrvar": refdef("xvariable")
            }
        },
        {
            "type": "object",
            "description": "global base or unknown",
            "required": ["other"],
            "properties": {
                "other": {
                    "type": "string",
                    "enum": ["global", "unknown"]
                }
            }
        }
    ]
}


auxvariable = {
    "name": "auxvariable",
    "title": "auxiliary variable",
    "description": "variable with a fixed symbolic value",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "value of the register upon function entry",
            "required": ["kind", "register", "txtrep"],
            "properties": {
                "kind": prop_kind(["irv"]),
                "register": strtype(desc="name of register"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "auxiliary variable for register single-assignment",
            "required": ["kind", "register", "address", "txtrep"],
            "properties": {
                "kind": prop_kind(["ssa"]),
                "register": strtype(desc="name of register"),
                "address": strtype(desc="address of register assignment"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "value of memory location upon function entry",
            "required": ["kind", "memvar", "txtrep"],
            "properties": {
                "kind": prop_kind(["imv"]),
                "memvar": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "value of variable frozen at test location",
            "required": ["kind", "testaddr", "jumpaddr", "testvar", "txtrep"],
            "properties": {
                "kind": prop_kind(["ftv"]),
                "testaddr": strtype(desc="hex address of test location"),
                "jumpaddr": strtype(desc="hex address of conditional branch"),
                "testvar": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "value of return value from a function call",
            "required": ["kind", "callsite", "calltarget", "txtrep"],
            "properties": {
                "kind": prop_kind(["frv"]),
                "callsite": strtype(desc="hexaddress of function call site"),
                "calltarget": strtype(desc="name of function called"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "memory address",
            "required": ["kind", "base", "offset", "txtrep"],
            "properties": {
                "kind": prop_kind(["ma"]),
                "base": refdef("memorybase"),
                "offset": refdef("memoryoffset"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "symbolic representation of expression",
            "required": ["kind", "expr", "txtrep"],
            "properties": {
                "kind": prop_kind(["svx"]),
                "expr": refdef("xexpression"),
                "txtrep": txtrep()
            }
        }
    ]
}


xconstant = {
    "name": "xconstant",
    "title": "constant value",
    "description": "constant value in expression",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "integer constant",
            "required": ["kind", "value"],
            "properties": {
                "kind": prop_kind(["icst"]),
                "value": intvalue()
            }
        },
        {
            "type": "object",
            "description": "integer constant string address",
            "required": ["kind", "value", "stringref"],
            "properties": {
                "kind": prop_kind(["strcst"]),
                "value": intvalue(),
                "stringref": strtype(desc="string at numerical address")
            }
        }
    ]
}


xvariable = {
    "name": "xvariable",
    "title": "variable",
    "description": "variable with or without denotation",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "temporary variable without denotation",
            "required": ["kind", "temp", "txtrep"],
            "properties": {
                "kind": prop_kind(["temp"]),
                "temp": strtype(),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "memory variable",
            "required": ["kind", "base", "offset", "size", "txtrep"],
            "properties": {
                "kind": prop_kind(["memvar"]),
                "base": refdef("memorybase"),
                "offset": refdef("memoryoffset"),
                "size": intvalue(desc="size of variable in bytes"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "register variable",
            "required": ["kind", "register", "txtrep"],
            "properties": {
                "kind": prop_kind(["regvar"]),
                "register": strtype(desc="name of register"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "variable with a fixed (possibly symbolic) value",
            "required": ["kind", "fxdval", "txtrep"],
            "properties": {
                "kind": prop_kind(["fxd"]),
                "fxdval": refdef("auxvariable"),
                "txtrep": txtrep()
            }
        }
    ]
}


xexpression = {
    "name": "xexpression",
    "title": "symbolic expression",
    "description": "native representation expression",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "constant expression",
            "required": ["kind", "cst", "txtrep"],
            "properties": {
                "kind": prop_kind(["xcst"]),
                "cst": refdef("xconstant"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "variable",
            "required": ["var", "txtrep"],
            "properties": {
                "kind": prop_kind(["xvar"]),
                "var": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "compound expression",
            "required": ["kind", "operator", "operands", "txtrep"],
            "properties": {
                "kind": prop_kind(["xop"]),
                "operator": strtype(desc="operation performed"),
                "operands": {
                    "type": "array",
                    "description": "list of operands (usually one or two)",
                    "items": {"$ref": "#/$defs/xexpression"}
                },
                "txtrep": txtrep()
            }
        }
    ]
}


linearequality = {
    "name": "linearequality",
    "title": "linear equality",
    "description": "linear equality of the form sum(a_i . x_i) = c",
    "type": "object",
    "required": ["constant", "coeffs", "factors", "txtrep"],
    "properties": {
        "constant": intvalue(desc="constant factor"),
        "coeffs": {
            "type": "array",
            "items": intvalue(desc="coefficient a_i (may be 0)")
        },
        "factors": {
            "description": "factors x_i",
            "type": "array",
            "items": refdef("xvariable")
        },
        "txtrep": txtrep()
    }
}


nonrelationalvalue = {
    "name": "nonrelationalvalue",
    "title": "non-relational value",
    "description": "symbolic constant",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "numeric value",
            "required": ["kind", "value", "txtrep"],
            "properties": {
                "kind": prop_kind(["iv"]),
                "value": intvalue(desc="constant singleton value"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "closed range of values",
            "required": ["kind", "lb", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind(["itv"]),
                "lb": intvalue(desc="lowerbound (inclusive) of range"),
                "ub": intvalue(desc="upperbound (inclusive) of range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "lower-bounded, half-open range of values",
            "required": ["kind", "lb", "txtrep"],
            "properties": {
                "kind": prop_kind(["lb-itv"]),
                "lb": intvalue(desc="lowerbound of half-open range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "upper-bounded, half-open range of values",
            "required": ["kind", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind(["ub-itv"]),
                "ub": intvalue(desc="upperbound of half-open range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "base with numeric constant offset",
            "required": ["kind", "base", "value", "txtrep"],
            "properties": {
                "kind": prop_kind(["b-civ"]),
                "base": strtype(desc="symbolic base address"),
                "value": intvalue(desc="offset (in bytes) from base address"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "base with bounded range of numeric offsets",
            "required": ["kind", "base", "lb", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind(["b-itv"]),
                "base": strtype(desc="symbolic base address"),
                "lb": intvalue(desc=(
                    "lowerbound (inclusive) of offset range (in bytes)")),
                "ub": intvalue(desc=(
                    "upperbound (inclusive) of offset range (in bytes)")),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "half-open range of address values",
            "required": ["kind", "base", "lb", "txtrep"],
            "properties": {
                "kind": prop_kind(["b-lb-itv"]),
                "base": strtype(desc="name of a base variable"),
                "lb": intvalue(desc="lower-bound of the range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "half-open range of values",
            "required": ["kind", "base", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind(["b-ub-itv"]),
                "base": strtype(desc="name of a base variable"),
                "ub": intvalue(desc="upper-bound of the range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "base only with unbounded interval",
            "required": ["kind", "txtrep"],
            "properties": {
                "kind": prop_kind(["b-unb"]),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "symbolic expression",
            "required": ["kind", "sym-expr", "txtrep"],
            "properties": {
                "kind": prop_kind(["sx"]),
                "sym-expr": refdef("xexpression"),
                "txtrep": txtrep()
            }
        }
    ]
}


invariantfact = {
    "name": "invariantfact",
    "title": "invariant fact",
    "description": (
        "Assertion about the state at a particular program location (address)"),
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": (
                "assertion that location is unreachable, with domain that "
                + "reached that conclusion"),
            "required": ["kind", "domain", "txtrep"],
            "properties": {
                "kind": prop_kind(["unr"]),
                "domain": strtype(desc="domain with bottom result"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "variable has or does not have the same value as the value at "
                "function entry"),
            "required": [
                "kind", "relation", "var", "initval", "txtrep"],
            "properties": {
                "kind": prop_kind(["ival"]),
                "relation": {
                    "type": "string",
                    "enum": ["equals", "not-equals"]
                },
                "var": refdef("xvariable"),
                "initval": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "relationship between value of testvariable at test location "
                + "and jump location (for evaluation of branch predicate)"),
            "required": [
                "kind", "testaddr", "jumpaddr", "testvar", "testval", "txtrep"],
            "properties": {
                "kind": prop_kind(["tst"]),
                "testaddr": strtype(
                    desc="hex address of instruction setting the condition codes"),
                "jumpaddr": strtype(
                    desc="hex address of conditional branch instruction"),
                "testvar": refdef("xvariable"),
                "testval": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "variable equality with non-relational value",
            "required": ["kind", "nrv", "var", "nrv", "txtrep"],
            "properties": {
                "kind": prop_kind(["nrv"]),
                "var": refdef("xvariable"),
                "nrv": refdef("nonrelationalvalue"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "location is unreachable; name of domain indicates the abstract "
                + "domain that reaches this conclusion"),
            "required": ["kind", "domain", "txtrep"],
            "properties": {
                "kind": prop_kind(["unr"]),
                "domain": strtype(desc="domain that signals unreachability"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": ("linear equality over program variables"),
            "required": ["kind", "lineq", "txtrep"],
            "properties": {
                "kind": prop_kind(["lineq"]),
                "lineq": refdef("linearequality"),
                "txtrep": txtrep()
            }
        }
    ]
}


locationinvariant = {
    "name": "locationinvariant",
    "title": "location invariant",
    "description": ("All invariant facts associated with a location"),
    "type": "object",
    "properties": {
        "location": strtype(
            desc=(
                "instruction hexaddress at which the assertions hold before "
                + "execution of the instruction at that address")),
        "invariants": {
            "type": "array",
            "items": refdef("invariantfact"),
            "description": "list of invariants that hold at this location"
        }
    }
}


functioninvariants = {
    "name": "functioninvariants",
    "description": ("All invariant facts associated with all locations in a function"),
    "type": "object",
    "properties": {
        "invariants": {
            "type": "array",
            "items": refdef("locationinvariant")
        }
    }
}


sectionheaderdata = {
    "name": "sectionheaderdata",
    "title": "section header data",
    "description": "name, address and size of an ELF section",
    "properties": {
        "name": strtype(desc="name of the section"),
        "vaddr": strtype(desc="virtual address of section (in hex)"),
        "size": strtype(desc="size, in bytes, of section (in memory) (in hex)")
    }
}


xfilepath = {
    "name": "xfilepath",
    "title": "path and filename of a binary",
    "description": "path and filename of a binary",
    "required": ["path", "filename"],
    "properties": {
        "path": strtype(),
        "filename": strtype()
    }
}


xcomparison = {
    "name": "xcomparison",
    "title": "binary comparison",
    "description": "Structural differences between two binaries",
    "type": "object",
    "required": ["file1", "file2"],
    "properties": {
        "file1": refdef("xfilepath"),
        "file2": refdef("xfilepath"),
        "newsections": {
            "type": "array",
            "description": (
                "name, address and size of sections added in patched file"),
            "items": refdef("sectionheaderdata")
        },
        "missingsections": {
            "type": "array",
            "description": "names of sections removed compared to original file",
            "items": strtype(desc="section name")
        },
        "thumb-switchpoints": {
            "type": "array",
            "description": (
                "list of thumb switchpoints addede to userdata of patched file"),
            "items": strtype(desc="switch-point (in CodeHawk form)")
        },
        "newcode": {
            "type": "array",
            "description": (
                "start and end address of newly added chunks of code in "
                + "patched file"),
            "items": {
                "type": "object",
                "description": (
                    "start and end virtual address of new code region (hex)"),
                "properties": {
                    "startaddr": strtype(),
                    "endaddr": strtype()
                }
            }
        },
        "section-differences": {
            "type": "array",
            "description": (
                "list of differences in size or starting address of existing "
                + "sections"),
            "items": {
                "type": "object",
                "description": "difference in size or virtual address",
                "properties": {
                    "name": strtype(desc="name of the section"),
                    "vaddr1": strtype(
                        desc="virtual address of section in original binary"),
                    "vaddr2": strtype(
                        desc="virtual address of section in patched binary"),
                    "size1": strtype(
                        desc="size (in hex) of section in original binary"),
                    "size2": strtype(
                        desc="size (in hex) of section in patched binary")
                }
            }
        }
    }
}

# ------------------------------------------- instruction comparison

instructioncomparison = {
    "name": "instructioncomparison",
    "title": "instruction-level comparison",
    "description": (
        "syntactic and semantic comparison of corresponding instructions "
        + "corresponding functions in two binaries"),
    "type": "object",
    "required": ["iaddr1", "iaddr2"],
    "properties": {
        "iaddr1": strtype("hex address of instruction in block1"),
        "iaddr2": strtype("hex address of instruction in block2"),
        "changes": prop_set([])
    }
}

# ---------------------------------------------------- block comparison

blocksemanticcomparison = {
    "name": "blocksemanticcomparison",
    "title": "summary of semantic changes in two corresponding blocks",
    "description": "summary of semantic changes in two corresponding blocks",
    "type": "object",
    "properties": {
        "changes": prop_set(["I/O"])
    }
}


blockcomparison = {
    "name": "blockcomparison",
    "title": "block-level comparison between two basic blocks",
    "description": (
        "syntactic and semantic comparison between two matching blocks "
        + "in fn1 and fn2"),
    "type": "object",
    "required": ["baddr1", "baddr2"],
    "properties": {
        "baddr1": strtype("hex address of block in function1"),
        "baddr2": strtype("hex address of block in function2"),
        "lev-distance": intvalue(
            "levenshtein distance between block1 and block2 instruction bytes"),
        "changes": prop_set(["instructioncount", "bytecount"]),
        "matches": prop_set(["instructioncount", "bytecount"]),
        "semantic-comparison": refdef("blocksemanticcomparison"),
        "instruction-insertions": {
            "type": "array",
            "description": (
                "list of addresses of instructions inserted in fn2"),
            "items": strtype("hex address of instruction in fn2")
        },
        "instruction-deletions": {
            "type": "array",
            "description": (
                "list of addresses of instructions deleted in fn2"),
            "items": strtype("hex address instruction in fn1")
        },
        "instruction-substitutions": {
            "type": "array",
            "description": (
                "list of instruction transformations from fn1 to fn2"),
            "items": refdef("instructioncomparison")
        }
    }
}


xedgedetail = {
    "name": "xedgedetail",
    "title": "Edge that is associated with a block expansion",
    "description": "Edge that is associate with a block expansion",
    "type": "object",
    "required": ["src", "tgt"],
    "properties": {
        "src": strtype("hex address of source block"),
        "tgt": strtype("hex address of target block"),
        "role": prop_kind([
            "exit-edge",
            "return-edge"
        ])
    }
}


xblockdetail = {
    "name": "xblockdetail",
    "title": "Basic block that belongs to a block expansion",
    "description": "Basic block that belongs to a block expansion",
    "type": "object",
    "required": ["baddr", "role"],
    "properties": {
        "baddr": strtype("hex address of basic block"),
        "role": prop_kind([
            "split-block-pre",
            "split-block-post",
            "trampoline-setup",
            "trampoline-payload",
            "trampoline-decision",
            "trampoline-takedown",
            "trampoline-breakout"
        ])
    }
}


blockexpansion = {
    "name": "blockexpansion",
    "title": "Expansion of single block into multiple block",
    "description": (
        "Expansion of single block in fn1 into multiple blocks in fn2"),
    "type": "object",
    "required": ["kind"],
    "properties": {
        "baddr1": strtype("hex address of block in fn1 expanded in fn2"),
        "kind": prop_kind(["trampoline"]),
        "xblocks": {
            "type": "array",
            "description": "list of blocks added and their role",
            "items": refdef("xblockdetail")
        },
        "xedges": {
            "type": "array",
            "description": "list of edges added",
            "items": refdef("xedgedetail")
        }
    }
}

# ---------------------------------------------------- function comparison

cfgedgecomparison = {
    "name": "cfgedgecomparison",
    "title": "Substitution of a single edge in fn1 to a single edge in fn2",
    "description": "Substitution of a single edge in fn1 to a single edge in fn2",
    "type": "object",
    "properties": {
        "src1": strtype("hex source address in fn1"),
        "src2": strtype("hex source address in fn2"),
        "tgt1": strtype("hex target address in fn1"),
        "tgt2": strtype("hex target address in fn2")
    }
}


cfgcomparison = {
    "name": "cfgcomparison",
    "title": "cfgs of original and patched function",
    "description": "cfgs of original and patched function marked with changes",
    "type": "object",
    "properties": {
        "similarity": prop_kind(["automorphic", "isomorphic"]),
        "changes": prop_set(["trampoline", "blockcount", "connectivity"]),
        "cfg1": refdef("controlflowgraph"),
        "cfg2": refdef("controlflowgraph"),
        "block-insertions": {
            "type": "array",
            "description": ("list of addresses of new blocks in fn2"),
            "items": strtype("hex address of block in fn2")
        },
        "block-deletions": {
            "type": "array",
            "description": ("list of addresses of blocks removed from fn1"),
            "items": strtype("hex address of block in fn1")
        },
        "block-substitutions": {
            "type": "array",
            "description": ("list of block transformations from fn1 to fn2"),
            "items": refdef("blockcomparison")
        },
        "block-expansions": {
            "type": "array",
            "description": ("list of blocks transformed into multiple blocks"),
            "items": refdef("blockexpansion")
        },
        "edge-insertions": {
            "type": "array",
            "description": ("list of edges inserted in cfg2"),
            "items": strtupletype("src", "dst")
        },
        "edge-deletions": {
            "type": "array",
            "description": ("list of edges in cfg1 removed in cfg2"),
            "items": strtupletype("src", "dst")
        },
        "edge-substitutions": {
            "type": "array",
            "description": ("list of edges transformations from cf1 to cfg2"),
            "items": refdef("cfgedgecomparison")
        }
    }
}


functionsemanticcomparison = {
    "name": "functionsemanticcomparison",
    "title": "Function semantic changes",
    "description": "Representation of semantic changes between two versions",
    "type": "object",
    "properties": {
        "changes": prop_set(["restrictions"])
    }
}


localvarscomparison = {
    "name": "localvarscomparison",
    "title": "comparison of two corresponding variables in function 1 and 2",
    "description": (
        "comparison of local variables of fn1 and fn2"),
    "type": "object",
    "properties": {
        "matches": prop_set([]),
        "changes": prop_set([])
    }
}


functioncomparison = {
    "name": "functioncomparison",
    "title": "function-level comparison",
    "description": (
        "syntactic and semantic comparsion of matching functions in app1 and app2"),
    "$comment": "JSONFunctionComparison.JSONFunctionComparison",
    "type": "object",
    "required": ["faddr1", "faddr2"],
    "properties": {
        "faddr1": strtype("hex address of function1 in file1"),
        "faddr2": strtype("hex address of function2 in file2"),
        "name1": strtype("symbolic name of function1 in file1"),
        "name2": strtype("symbolic name of function2 in file2"),
        "changes": prop_set(["blockcount", "cfg-structure"]),
        "matches": prop_set(["blockcount", "cfg-structure"]),
        "cfg-comparison": refdef("cfgcomparison"),
        "localvars-comparison": refdef("localvarscomparison"),
        "semantic-comparison": refdef("functionsemanticcomparison")
    }
}

# ------------------------------------------------ application comparison

functionadded = {
    "name": "functionadded",
    "title": "New function added to app 2",
    "description": "New function added to app 2",
    "type": "object",
    "properties": {
        "faddr": strtype("hex address of new function")
    }
}


globalvarcomparison = {
    "name": "globalvarcomparison",
    "title": "comparison of global variable in app1 and app2",
    "description": "comparison of global variable in app1 and app2",
    "type": "object",
    "properties": {
        "gaddr": strtype("hex address of global variable in app1"),
        "name": strtype("name of global variable"),
        "moved-to": strtype("address of global variable in app2")
    }
}


callgraphcomparison = {
    "name": "callgraphcomparison",
    "title": "comparison of callgraphs of app1 and app2",
    "description": "comparison of callgraphs of app1 and app2",
    "type": "object",
    "properties": {
        "changes": prop_set(["new call"])
    }
}


binarycomparison = {
    "name": "binarycomparison",
    "title": "comparison of app1 and app2 at the binary level",
    "description": "comparison of app1 and app2 at the binary level",
    "type": "object",
    "properties": {
        "changes": prop_set(["new section"])
    }
}


appmd5comparison = {
    "name": "appmd5comparison",
    "title": "syntactic check of functions changed",
    "description": (
        "raw listing of function address/md5 pairs to enable syntactic "
        + "comparison"),
    "type": "object",
    "properties": {
        "file1": {
            "type": "array",
            "description": "function address / md5 pairs for file1",
            "items": strtupletype(
                "faddr", "md5", "md5 of syntactic assembly function string")
            },
        "file2": {
            "type": "array",
            "description": "function address / md5 pairs for file2",
            "items": strtupletype(
                "faddr", "md5", "md5 of syntactic assembly function string")
            }
        }
    }


appcomparison = {
    "name": "appcomparison",
    "title": "application comparison",
    "description": "syntactic and semantic comparison of two binaries",
    "$comment": "JSONAppComparison.JSONAppComparison",
    "type": "object",
    "required": ["file1", "file2", "functions-compared"],
    "properties": {
        "file1": refdef("xfilepath"),
        "file2": refdef("xfilepath"),
        "changes": prop_set(["functioncount"]),
        "matches": prop_set(["functioncount"]),
        "functions-compared": {
            "type": "array",
            "description": (
                "list of hex addresses of functions that were compared"),
            "items": strtype("hex address of function compared")
        },
        "functions-changed": {
            "type": "array",
            "description": (
                "list of relational analyses at the function level"),
            "items": refdef("functioncomparison")
        },
        "functions-added": {
            "type": "array",
            "description": ("list of functions added to file 2"),
            "items": refdef("functionadded")
        },
        "functions-removed": {
            "type": "array",
            "description": ("list of functions removed from file 1"),
            "items": strtype("hex address of function removed")
        },
        "callgraph-comparison": refdef("callgraphcomparison"),
        "globalvars-compared": {
            "type": "array",
            "description": (
                "list of hex addresses of global variables analyzed"),
            "items": strtype("hex address of global variable analyzed")
        },
        "globalvars-changed": {
            "type": "array",
            "description": ("list of changes in global variables"),
            "items": refdef("globalvarcomparison")
        },
        "binary-comparison": refdef("binarycomparison"),
        "app-md5-comparison": refdef("appmd5comparison")
    }
}


callgraphnode = {
    "name": "callgraphnode",
    "title": "callgraph node",
    "$comment": "JSONCallgraph.JSONCallgraphNode",
    "type": "object",
    "required": ["name"],
    "properties": {
        "name": strtype("unique identification of node"),
        "label": strtype("text to be shown on node representation"),
        "type": strtype("optional type that characterizes the node")
    }
}


callgraphedge = {
    "name": "callgraphedge",
    "title": "callgraph edge",
    "$comment": "JSONCallgraph.JSONCallgraphEdge",
    "type": "object",
    "requires": ["src", "tgt"],
    "properties": {
        "src": strtype("source node name"),
        "tgt": strtype("target node name"),
        "type": strtype("optional type that characterizes the edge")
    }
}


callgraph = {
    "name": "callgraph",
    "title": "callgraph",
    "description": "(partial) callgraph",
    "$comment": "JSONCallgraph.JSONCallgraph",
    "type": "object",
    "required": ["nodes", "edges"],
    "properties": {
        "nodes": {
            "type": "array",
            "items": refdef("callgraphnode")
        },
        "edges": {
            "type": "array",
            "items": refdef("callgraphedge")
        }
    }
}


callsitetgtparameter = {
    "name": "callsitetgtparameter",
    "title": "callsite target function parameter",
    "description": "callsite target function parameter",
    "$comment": "JSONCallsiteRecords.JSONCallsiteTgtParameter",
    "type": "object",
    "required": [],
    "properties": {
        "name": strtype("name of parameter"),
        "roles": {
            "type": "array",
            "description": "roles that the parameter plays in execution",
            "items": strtype("name of precondition and role therein")
        }
    }
}


callsitetgtfunction = {
    "name": "callsitetgtfunction",
    "title": "callsite target function",
    "description": "specification of target function of callsites",
    "$comment": "JSONCallsiteRecords.JSONCallsiteTgtFunction",
    "type": "object",
    "required": ["name", "parameters"],
    "properties": {
        "name": strtype("name or hex address of function called"),
        "parameters": {
            "type": "array",
            "description": "parameters of the target function",
            "items": refdef("callsitetgtparameter")
        },
        "varargs": "bool"
    }
}


callsiteargument = {
    "name": "callsiteargument",
    "title": "callsite argument",
    "description": "argument value of call to target function",
    "$comment": "JSONCallsiteRecords.JSONCallsiteArgument",
    "type": "object",
    "required": ["name", "value"],
    "properties": {
        "name": strtype("name of parameter"),
        "value": strtype("text representation of argument value"),
        "roles": {
            "type": "array",
            "description":
            ("role values in accordance with the the roles specified in the "
             + "callsite target function"),
            "items": strtupletype(
                "rn", "rv", desc="role name and role value")
        }
    }
}


callsiterecord = {
    "name": "callsiterecord",
    "title": "callsite record",
    "description": "callsite instance with location and arguments",
    "$comment": "JSONCallsiteRecords.JSONCallsiteRecord",
    "type": "object",
    "required": ["faddr", "iaddr", "arguments"],
    "properties": {
        "faddr": strtype("hex address of calling function"),
        "iaddr": strtype("hex address of callsite"),
        "arguments": {
            "type": "array",
            "description": "list of arguments with which target function is called",
            "items": refdef("callsiteargument")
        },
        "cgpath": refdef("callgraph")
    }
}


callsiterecords = {
    "name": "callsiterecords",
    "title": "callsite records",
    "description": "list of calls to a particular function",
    "$comment": "JSONCallsiteRecords.JSONCallsiteRecords",
    "type": "object",
    "required": ["tgt-function", "callsites"],
    "properties": {
        "function-names": {
            "type": "array",
            "items": strtupletype(
                "addr",
                "name",
                desc="list of hex address - name mappings for functions referenced")
        },
        "cgpath-src": strtype("hex address of source function for callgraph path"),
        "tgt-function": refdef("callsitetgtfunction"),
        "callsites": {
            "type": "array",
            "description": "list of sites at which function is called",
            "items": refdef("callsiterecord")
        }
    }
}
