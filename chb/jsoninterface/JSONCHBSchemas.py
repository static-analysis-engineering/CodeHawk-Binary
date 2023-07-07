# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
    return r


def strtype(desc: Optional[str] = None) -> Dict[str, str]:
    s: Dict[str, str] = {}
    s["type"] = "string"
    if desc is not None:
        s["description"] = desc
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
        "instr1": refdef("assemblyinstruction"),
        "instr2": refdef("assemblyinstruction")
    }
}


instructionaddedinfo = {
    "name": "instructionaddedinfo",
    "title": "information about added instruction",
    "description": (
        "information about assembly instruction added to function2 not mapped "
        + "to an instruction in function1"),
    "type": "object",
    "required": ["iaddr"],
    "properties": {
        "iaddr": strtype("hex address of instruction in function2"),
        "instr": refdef("assemblyinstruction"),
        "invariants": refdef("locationinvariant")
    }
}


instructionremovedinfo = {
    "name": "instructionremovedinfo",
    "title": "information about an instruction that was removed",
    "description": (
        "information about an assembly instruction that is in function1, but "
        + "is not mapped to any instruction in function2"),
    "type": "object",
    "required": ["iaddr"],
    "properties": {
        "iaddr": strtype("hex address of instruction in function1"),
        "instr": refdef("assemblyinstruction"),
        "invariants": refdef("locationinvariant")
    }
}


blockcomparisondetails = {
    "name": "blockcomparisondetails",
    "title": "detailed comparison between two blocks",
    "description": "detailed comparison between two blocks",
    "type": "object",
    "properties": {
        "instruction-comparisons": {
            "type": "array",
            "description": "list of instruction comparisons",
            "items": refdef("instructioncomparison")
        },
        "instructions-added": {
            "type": "array",
            "description": "list of instructions added to the block",
            "items": refdef("instructionaddedinfo")
        },
        "instructions-removed": {
            "type": "array",
            "description": "list of instructions removed from the block",
            "items": refdef("instructionremovedinfo")
        }
    }
}


blockinstructionmappedsummary = {
    "name": "blockinstructionmappedsummary",
    "title": "summary of changes between two mapped instructions in function1 and function2",
    "description": (
        "summary of changes between two mapped instructions in function1 and function2"),
    "type": "object",
    "properties": {
        "iaddr": strtype("hex address of instruction in function1"),
        "changes": prop_set([
            "iaddr",
            "bytes",
            "invariants"]),
        "matches": prop_set([
            "iaddr",
            "bytes",
            "invariants"]),
        "moved-to": strtype("(optional) address of instruction in function 2")
    }
}


blockinstructionscomparisonsummary = {
    "name": "blockinstructionscomparisonsummary",
    "title": "summary of comparison between corresponding instructions",
    "description": "summary of comparison between corresponding instructions",
    "type": "object",
    "properties": {
        "changes": prop_set(["instructioncount", "predicate"]),
        "block-instructions-mapped": {
            "type": "array",
            "description": "liost of instructions mapped one-to-one in block1 and block2",
            "items": refdef("blockinstructionmappedsummary")
        },
        "block-instructions-added": {
            "type": "array",
            "description": "list of instructions in block2 but not in block1",
            "items": strtype("hex address of instruction in block2")
        },
        "block-instructions-removed": {
            "type": "array",
            "description": "list of instructions in block1 but not in block2",
            "items": strtype("hex address of instruction in block1")
        }
    }
}


blocksemanticscomparisonsummary = {
    "name": "blocksemanticscomparisonsummary",
    "title": "summary of semantic changes in two corresponding blocks",
    "description": "summary of semantic changes in two corresponding blocks",
    "type": "object",
    "properties": {
        "changes": prop_set(["I/O"])
    }
}


blockcomparisonsummary = {
    "name": "blockcomparisonsummary",
    "title": "summary of changes in two corresponding blocks",
    "description": "summary of changes in two corresponding blocks",
    "type": "object",
    "properties": {
        "block-instructions-comparison-summary": (
            refdef("blockinstructionscomparisonsummary")),
        "block-semantics-comparison-summary": (
            refdef("blocksemanticscomparisonsummary"))
    }
}


blockcomparison = {
    "name": "blockcomparison",
    "title": "block-level comparison between two basic blocks",
    "description": (
        "block-level comparison between two corresponding blocks in two functions"),
    "type": "object",
    "required": ["baddr1", "baddr2"],
    "properties": {
        "baddr1": strtype("hex address of block in function1"),
        "baddr2": strtype("hex address of block in function2"),
        "lev-distance": intvalue(
            "levenshtein distance between block1 and block2 instruction bytes"),
        "changes": prop_set(["instructioncount", "bytecount"]),
        "matches": prop_set(["instructioncount", "bytecount"]),
        "block-comparison-summary": refdef("blockcomparisonsummary"),
        "block-comparison-details": refdef("blockcomparisondetails")
    }
}


cfgblockmappingitem = {
    "name": "cfgblockmappingitem",
    "title": "relationship between block in cfg1 and block(s) in cfg2",
    "description": "relationship between block in cfg1 and block(s) in cfg2",
    "type": "object",
    "properties": {
        "matches": prop_set(["md5", "instructioncount"]),
        "changes": prop_set(["md5", "trampoline-insertion", "instructioncount"]),
        "cfg1-block-addr": strtype("hex address of block in cfg1"),
        "cfg2-blocks": {
            "type": "array",
            "description": "list of blocks address in cfg2 mapped to block in cfg1",
            "items": {
                "type": "object",
                "description": "block address and role",
                "properties": {
                    "cfg2-block-addr": strtype("hex address of block in cfg2"),
                    "role": prop_kind([
                        "single-mapped",
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
        }
    }
}


cfgcomparison = {
    "name": "cfgcomparison",
    "title": "cfgs of original and patched function",
    "description": "cfgs of original and patched function marked with changes",
    "type": "object",
    "properties": {
        "changes": prop_set(["trampoline"]),
        "cfg1": refdef("controlflowgraph"),
        "cfg2": refdef("controlflowgraph"),
        "cfg-block-mapping": {
            "type": "array",
            "description": "mapping of blocks in cfg1 and sets of blocks in cfg2",
            "items": refdef("cfgblockmappingitem")
        }
    }
}


cfgcomparisons = {
    "name": "cfgcomparisons",
    "title": "list of cfg comparisons",
    "description": "list of cfg comparisons",
    "type": "object",
    "properties": {
        "functions-changed": {
            "type": "array",
            "description": "list of cfg comparisons for functions changed",
            "items": refdef("cfgcomparison")
        }
    }
}

cfgcomparisonsummary = {
    "name": "cfgcomparisonsummary",
    "title": "summary of changes to the cfg",
    "description": "summary of changes to the cfg",
    "type": "object",
    "properties": {
        "cfg-mapping": prop_kind(["automorphic"]),
        "changes": prop_set(["trampoline"])
    }
}


functionvariablescomparisonsummary = {
    "name": "functionvariablescomparisonsummary",
    "title": "summary of changes in the function's variables",
    "description": "summary of changes in the function's variables",
    "type": "object",
    "properties": {
        "changes": prop_set(["stacklayout"])
    }
}


functionblockmappedsummary = {
    "name": "functionblockmappedsummary",
    "title": "summary of changes between two mapped blocks in function1 and function2",
    "description": (
        "summary of changes between two mapped blocks in function1 and function2"),
    "type": "object",
    "properties": {
        "baddr": strtype("hex address of block in function1"),
        "changes": prop_set([
            "baddr",
            "md5",
            "instructioncount",
            "bytecount"]),
        "matches": prop_set([
            "baddr",
            "md5",
            "instructioncount",
            "bytecount"]),
        "moved-to": strtype("(optional) address of block in function2")
    }
}


functionblockscomparisonsummary = {
    "name": "functionblockscomparisonsummary",
    "title": "summary of changes in the function's basic blocks",
    "description": "summary of changes in the funciton's basic blocks",
    "$comment": "JSONFunctionSummary.JSONFunctionBlocksComparisonSummary",
    "type": "object",
    "properties": {
        "changes": prop_set(["blockcount", "trampoline-inline"]),
        "matches": prop_set(["blockcount", "md5"]),
        "function-blocks-mapped": {
            "type": "array",
            "description": "list of blocks mapped one-to-one in function1 and function2",
            "items": refdef("functionblockmappedsummary")
        },
        "function-blocks-added": {
            "type": "array",
            "description": "list of blocks in function2 but not in function1",
            "items": strtype("hex address of basic block in function2")
        },
        "function-blocks-removed": {
            "type": "array",
            "description": "list of blocks in function1 but not in function2",
            "items": strtype("hex address of basic block in function1")
        }
    }
}


functioncomparisonsummary = {
    "name": "functioncomparisonsummary",
    "title": "summary of function comparison",
    "description": "summary of changes in corresponding functions in two binaries",
    "$comment": "JSONFunctionComparison.JSONFunctionComparisonSummary",
    "type": "object",
    "properties": {
        "cfg-comparison-summary": refdef("cfgcomparisonsummary"),
        "function-variables-comparison-summary": refdef(
            "functionvariablescomparisonsummary"),
        "function-blocks-comparison-summary": refdef(
            "functionblockscomparisonsummary")
    }
}


functioncomparisondetails = {
    "name": "functioncomparisondetails",
    "title": "details of function comparison",
    "description": "details of the comparison between two corresponding functions",
    "type": "object",
    "properties": {
        "block-comparisons": {
            "type": "array",
            "description": "detailed comparison of all mapped blocks with changes",
            "items": refdef("blockcomparison")
        }
    }
}


functioncomparison = {
    "name": "functioncomparison",
    "title": "function-level comparison",
    "description": (
        "syntactic and semantic comparsion of corresponding functions in two binaries"),
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
        "function-comparison-summary": refdef("functioncomparisonsummary"),
        "function-comparison-details": refdef("functioncomparisondetails")
    }
}


callgraphcomparisonsummary = {
    "name": "callgraphcomparisonsummary",
    "title": "summary of changes in the callgraph",
    "description": "summary of changes in the callgraph",
    "$comment": "JSONAppComparison.JSONCallgraphComparisonSummary",
    "properties": {
        "changes": prop_set(["redirect"])
    }
}


globalscomparisonsummary = {
    "name": "globalscomparisonsummary",
    "title": "summary of changes in global variables",
    "description": "summary of changes in global variables",
    "$comment": "JSONAppComparison.JSONGlobalsComparisonSummary",
    "properties": {
        "changes": prop_set(["address-change"])
    }
}


appfunctionmappedsummary = {
    "name": "appfunctionmappedsummary",
    "title": "summary of changes in a mapped function from file1 to file2",
    "description": "summary of changes in a mapped function from file1 to file2",
    "$comment": "JSONAppComparison.JSONFunctionMappedSummary",
    "type": "object",
    "required": ["faddr"],
    "properties": {
        "faddr": strtype("hex address of function in file1"),
        "name": strtype("name of function in file1"),
        "changes": prop_set([
            "faddr",
            "md5",
            "blockcount",
            "instructioncount",
            "bytecount",
            "cfg:not-automorphic"]),
        "matches": prop_set([
            "faddr",
            "md5",
            "cfg-automorphic",
            "blockcount",
            "instructioncount",
            "bytecount"]),
        "moved-to": strtype("(optional) address in file2, if different"),
    }
}


appfunctionscomparisonsummary = {
    "name": "appfunctionscomparisonsummary",
    "title": "summary of changes in individual functions",
    "description": "summary of changes in individual functions",
    "$comment": "JSONAppComparison.JSONAppFunctionsComparisonSummary",
    "type": "object",
    "properties": {
        "changes": prop_set(["functioncount", "trampoline"]),
        "app-functions-mapped": {
            "type": "array",
            "description": "list of functions mapped one-to-one in file1 and file2",
            "items": refdef("appfunctionmappedsummary")
        },
        "app-functions-added": {
            "type": "array",
            "description": "list of addresses of functions in file2 not present in file1",
            "items": strtype("hex function address in file2")
        },
        "app-functions-removed": {
            "type": "array",
            "description": "list of addresses of functions in file1 not present in file2",
            "items": strtype("hex function address in file1")
        }
    }
}


appcomparisonsummary = {
    "name": "appcomparisonsummary",
    "title": "summary of application comparison",
    "description": "summary of syntactic and semantic comparison of two binaries",
    "$comment": "JSONAppComparison.JSONAppComparisonSummary",
    "type": "object",
    "required": ["functions-comparison-summary"],
    "properties": {
        "callgraph-comparison-summary": refdef("callgraphcomparisonsummary"),
        "globals-comparison-summary": refdef("globalscomparisonsummary"),
        "app-functions-comparison-summary": refdef("appfunctionscomparisonsummary")
    }
}


appcomparisondetails = {
    "name": "appcomparisondetails",
    "title": "details of application comparison",
    "description": "details of comparison between two binaries",
    "type": "object",
    "properties": {
        "function-comparisons": {
            "type": "array",
            "description": "detailed comparison of all mapped functions with changes",
            "items": refdef("functioncomparison")
        },
        "function-comparisons-omitted": {
            "type": "array",
            "description": (
                "list of hex addresses of functions changed without details"),
            "items": strtype("hex address of function in file1")
        }
    }
}


appcomparison = {
    "name": "appcomparison",
    "title": "application comparison",
    "description": "syntactic and semantic comparison of two binaries",
    "$comment": "JSONAppComparison.JSONAppComparison",
    "type": "object",
    "required": ["file1", "file2", "app-summary"],
    "properties": {
        "file1": refdef("xfilepath"),
        "file2": refdef("xfilepath"),
        "changes": prop_set(["functioncount"]),
        "matches": prop_set(["functioncount"]),
        "app-comparison-summary": refdef("appcomparisonsummary"),
        "app-comparison-details": refdef("appcomparisondetails")
    }
}

"""
remove:
- appcomparisonsummary
- callgraphcomparisonsummary
- globalscomparisonsummary
- appfunctionscomparisonsummary
- appfunctionmappedsummary
- functioncomparisonsummary
- cfgcomparisonsummary
- functionvariablescomparisonsummary
- functionblockscomparisonsummary
- functionblockmappedsummary
- blockcomparisonsummary
- blockinstructionscomparisonsummary
- blocksemanticscomparisonsummary
- blockinstructionmappedsummary

keep/rename:
- appcomparisondetails
- functioncomparison
- functioncomparisondetails
- blockcomparison
- blockcomparisondetails
- instructioncomparison
- instructionaddedinfo
- instructionremovedinfo

recreate:
- in app context:
  - callgraphcomparison
  - globalscomparison

- in function context:
  - cfgcomparison
  - variablescomparison
  - semanticscomparison

- in block context
  - blocksemanticscomparison

combine into:
- appcomparison:
    - functioncomparison[]
    - functionadded[]
    - functionremoved[]
    - callgraphcomparison
    - globalvarcomparison[]
    - bincomparison

- functioncomparison:
    - blockcomparison[]
    - cfgcomparison
    - trampolineanalysis
    - variablecomparison[]
    - funsemanticscomparison

- blockcomparison:
    - instructioncomparison[]
    - instructionadded[]
    - instructionremoved[]
    - vertexcomparison
    - blocksemanticscomparison

- instructioncomparison
    - bytecomparison
    - instrsemanticscomparison

- functionadded:
    - hex address
    - assertion[]
    - remark[]

- functionremoved:
    - hex address
    - assertion[]
    - remark[]

callgraphcomparison:
    - changes: {callredirect}

globalvarcomparison:
    - hex address
    - type
    - name
    - changes: {moved}

bincomparison
    - changes: {elfheader, elfsection}

cfgcomparison:
    - changes: {trampoline-insert, blockcount, blockconnectivity}
    - trampolinedata

variablescomparison
    - name
    - location
    - type

funsemanticscomparison
    - changes: {}

vertextcomparison:
    - incomingchanged
    - outgoingchanged
    - newimcoming
    - newoutgoing

blocksemanticscomparison
    - changes: {precondition, postcondition, external}

instrsemanticscomparison
    - invariantschanged
"""
