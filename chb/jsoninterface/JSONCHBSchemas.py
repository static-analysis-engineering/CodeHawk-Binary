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

from typing import Any, Dict, TYPE_CHECKING


stackpointeroffset = {
    "name": "stackpointeroffset",
    "title": "stackpointer offset",
    "description": ("value or range of values of the stack pointer "
                    + "relative to the value at the function entry, "
                    + "as determined by the analysis, or unknown"),
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "typically used for unknown value",
            "properties": {
                "novalue": {
                    "type": "string",
                    "enum": ["unbounded", "not-analyzed"]
                }
            }
        },
        {
            "type": "object",
            "description": "single (usually negative) value",
            "properties": {
                "value": {
                    "type": "number",
                }
            }
        },
        {
            "type": "object",
            "description": ("closed interval specified by minimum and "
                            + "maximum value"),
            "properties": {
                "range": {
                    "type": "array",
                    "items": {
                        "type": "number"
                    }
                }
            }
        },
        {
            "type": "object",
            "description": ("right open interval specified by lower bound"),
            "properties": {
                "lowerbound": {
                    "type": "number"
                }
            }
        },
        {
            "type": "object",
            "descripotion": ("left open interval specified by upper bound"),
            "properties": {
                "upperbound": {
                    "type": "number"
                }
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
    "properties": {
        "addr": {
            "type": "array",
            "description": ("list of context addresses within the function "
                            + "instruction address last"),
            "items": {
                "type": "string",
                "description": "hex address"
            }
        },
        "stackpointer": {
            "$ref": "stackpointeroffset"
        },
        "bytes": {
            "type": "string",
            "description": (
                "hexadecimal representation of bytes constituting the instruction"),
        },
        "opcode": {
            "type": "array",
            "description": (
                "standard assembly instruction representation, possibly broken in "
                + "opcode part and operands part for better formatting"),
            "items": {
                "type": "string"
            }
        },
        "annotation": {
            "type": "string",
            "description": (
                "representation of instruction semantics using analysis results")
        }
    }
}


assemblyblock = {
    "name": "assemblyblock",
    "title": "assembly block",
    "description": (
        "Range of instructions within a function that form a basic block"),
    "type": "object",
    "properties": {
        "startaddr": {
            "type": "string",
            "description": "hexaddress of the first instruction of the block"
        },
        "endaddr": {
            "type": "string",
            "description": (
                "hexaddress of the (syntactically) last instruction of the "
                + "block. Note that this would be the address of the delay "
                + "slot for a MIPS assembly block, which is not the last "
                + "instruction to be executed")
        },
        "instructions": {
            "type": "array",
            "description": "list of assembly instructions contained in the block",
            "items": {
                "$ref": "assemblyinstruction"
            }
        }
    }
}


assemblyfunction = {
    "name": "assemblyfunction",
    "title": "assembly function",
    "description": ("Collection of basic blocks that make up a function"),
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": (
                "(optional) name of the function from symbol information "
                + "or user-provided")
        },
        "faddr": {
            "type": "string",
            "description": (
                "hexaddress of function entry point. Note that this address "
                + "is not necessarily the lowest address of the function.")
        },
        "md5hash": {
            "type": "string",
            "description": (
                "md5 hash of the hex-encoded bytes of the function instructions")
        },
        "basicblocks": {
            "type": "array",
            "description": ("list of basic blocks included in the function"),
            "items": {
                "$ref": "assemblyblock"
            }
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
            "description": "constant numerical offset",
            "properties": {
                "offsetvalue": {
                    "type": "number",
                    "description": "offset value in bytes"
                },
                "suboffset": {
                    "$ref": "memoryoffset"
                }
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
            "properties": {
                "ptrvar": {
                    "$ref": "xvariable"
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
            "properties": {
                "register": {
                    "type": "string",
                    "description": "name of register"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "value of memory location upon function entry",
            "properties": {
                "memvar": {
                    "$ref": "xvariable"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "value of return value from a function call",
            "properties": {
                "callsite": {
                    "type": "string",
                    "description": "hexaddress of function call site"
                },
                "calltarget": {
                    "type": "string",
                    "description": (
                        "name of the function called that returned the value")
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested text representation"
                }
            }
        },
        {
            "type": "object",
            "description": "value of variable frozen at test location",
            "properties": {
                "testaddr": {
                    "type": "string",
                    "description": "hex address of test location"
                },
                "jumpaddr": {
                    "type": "string",
                    "description": "hex address of conditional branch"
                },
                "testvar": {
                    "$ref": "xvariable"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
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
            "properties": {
                "value": {
                    "type": "number",
                    "description": "numerical value"
                },
                "stringref": {
                    "type": "string",
                    "description": "(optional) string at numerical address"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
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
            "properties": {
                "temp": {
                    "type": "string"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "variable with a fixed (possibly symbolic) value",
            "properties": {
                "fixed-value": {
                    "$ref": "auxvariable"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "memory variable",
            "properties": {
                "base": {
                    "$ref": "memorybase"
                },
                "offset": {
                    "$ref": "memoryoffset"
                },
                "size": {
                    "type": "number",
                    "description": "(optional) size of variable in bytes"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "register variable",
            "properties": {
                "register": {
                    "type": "string",
                    "description": "name of register"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
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
            "properties": {
                "cst": {
                    "$ref": "xconstant"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "variable",
            "properties": {
                "var": {
                    "$ref": "xvariable"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "compound expression",
            "properties": {
                "operator": {
                    "type": "string",
                    "description": "operation performed"
                },
                "operands": {
                    "type": "array",
                    "description": "list of operands (usually one or two)",
                    "items": {
                        "$ref": "xexpression"
                    }
                }
            }
        }
    ]
}


linearequality = {
    "name": "linearequality",
    "title": "linear equality",
    "description": "linear equality of the form sum(a_i . x_i) = c",
    "type": "object",
    "properties": {
        "constant": {
            "type": "int",
            "description": "constant factor"
        },
        "coefficients": {
            "type": "array",
            "items": {
                "type": "int",
                "description": "coefficient a_i (may be 0)"
            }
        },
        "factors": {
            "description": "factors x_i",
            "type": "array",
            "items": {
                "$ref": "xvariable"
            }
        }
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
            "description": "range of values",
            "properties": {
                "base": {
                    "type": "string",
                    "description": "(optional) name of a base variable"
                },
                "lowerbound": {
                    "type": "number",
                    "description": "(optional) lower-bound of the range"
                },
                "upperbound": {
                    "type": "number",
                    "description": "(optional) upper-bound of the range"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "symbolic expression",
            "properties": {
                "sym-expr": {
                    "$ref": "xexpression"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
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
                "variable has or does not have the same value as the value at "
                "function entry"),
            "properties": {
                "relation": {
                    "type": "string",
                    "enum": ["equals", "not-equals"]
                },
                "var": {
                    "$ref": "xvariable"
                },
                "initial-value": {
                    "$ref": "auxvariable"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": (
                "relationship between value of testvariable at test location "
                + "and jump location (for evaluation of branch predicate)"),
            "properties": {
                "testaddr": {
                    "type": "string",
                    "description": (
                        "hex address of instruction setting the condition codes")
                },
                "jumpaddr": {
                    "type": "string",
                    "description": (
                        "hex address of conditional branch instruction")
                },
                "testvar": {
                    "$ref": "xvariable"
                },
                "testval": {
                    "$ref": "xvariable"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
            }
        },
        {
            "type": "object",
            "description": "variable equality with symbolic expression",
            "properties": {
                "var": {
                    "$ref": "xvariable"
                },
                "symbolic-value": {
                    "$ref": "nonrelationalvalue"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual represention"
                }
            }
        },
        {
            "type": "object",
            "description": (
                "location is unreachable; name of domain indicates the abstract "
                + "domain that reaches this conclusion"),
            "properties": {
                "unreachable": {
                    "type": "string"
                }
            }
        },
        {
            "type": "object",
            "description": ("linear equality over program variables"),
            "properties": {
                "lineq": {
                    "$ref": "linearequality"
                },
                "txtrep": {
                    "type": "string",
                    "description": "suggested textual representation"
                }
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
        "location": {
            "type": "string",
            "description": (
                "instruction hexaddress at which the assertions hold before "
                + "execution of the instruction at that address")
        },
        "invariants": {
            "type": "array",
            "items": {
                "$ref": "invariantfact"
            },
            "description": ("list of invariants that hold at this location")
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
            "items": {
                "$ref": "locationinvariant"
            }
        }
    }
}
