# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs
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

from typing import Any, cast, Dict

from chb.simulation.SimMemory import SimMemory, SimMemoryByteLink

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF


def json_to_simval(d: Dict[str, Any]) -> SV.SimValue:
    id = d["i"]

    # SimValue (generic, covers all cases with jsonval implementation)
    if id == "x":
        return SSV.SimSymbolicValue(0, defined=False)

    # SimByteValue
    elif id == "b":
        if "d" in d:
            data = d["d"]
            v: int = data.get("v", 0)
            defined: bool = data.get("d", True)
            return SV.SimByteValue(v, defined)
        else:
            return SV.SimByteValue(0)

    # SimDoubleWordValue
    elif id == "d":
        if "d" in d:
            data = d["d"]
            v = data.get("v", 0)
            defined = data.get("d", True)
            b1defined: bool = data.get("db1", True)
            b2defined: bool = data.get("db2", True)
            b3defined: bool = data.get("db3", True)
            b4defined: bool = data.get("db4", True)
            return SV.SimDoubleWordValue(
                v,
                defined=defined,
                b1defined=b1defined,
                b2defined=b2defined,
                b3defined=b3defined,
                b4defined=b4defined)
        else:
            return SV.SimDoubleWordValue(0)

    # SimGlobalAddress
    elif id == "sga":
        data = d["d"]
        modulename: str = data.get("m", "?")
        offset = cast(SV.SimDoubleWordValue, json_to_simval(data["o"]))
        return SSV.SimGlobalAddress(modulename, offset)

    # SimReturnAddress
    elif id == "sra":
        data = d["d"]
        modulename = data.get("m", "?")
        functionaddr: str = data["f"]
        offset = cast(SV.SimDoubleWordValue, json_to_simval(data["o"]))
        return SSV.SimReturnAddress(modulename, functionaddr, offset)

    # SimMemoryByteLink
    elif id == "bl":
        data = d["d"]
        linkedto = cast(SSV.SimSymbolicValue, json_to_simval(data["l"]))
        position: int = cast(int, data["p"])
        return SimMemoryByteLink(linkedto, position)

    else:
        raise UF.CHBError("No deserialization implemented yet for id = " + id)


def byte_from_dw(dw: SV.SimDoubleWordValue, pos: int, bigendian: bool = False) -> int:
    if dw.is_defined:
        if bigendian:
            if pos == 0:
                return dw.byte4
            elif pos == 1:
                return dw.byte3
            elif pos == 2:
                return dw.byte2
            elif pos == 3:
                return dw.byte1
            else:
                raise UF.CHBError("Illegal dw position: " + str(pos))
        else:
            if pos == 0:
                return dw.byte1
            elif pos == 1:
                return dw.byte2
            elif pos == 2:
                return dw.byte3
            elif pos == 3:
                return dw.byte4
            else:
                raise UF.CHBError("Illegal dw position: " + str(pos))
    else:
        return 0


def jsonmem_to_byte_sequence(d: Dict[str, Any]) -> Dict[int, int]:
    """Converts a serialized simulation memory object into a address-byte-value map"""

    result: Dict[int, int] = {}
    for a in d["m"]:
        simval: SV.SimValue = json_to_simval(d["m"][a])
        addr = int(a)
        if simval.is_membyte_link:
            bytelink = cast(SimMemoryByteLink, simval)
            linkedto = bytelink.linkedto
            pos = bytelink.position
            if linkedto.is_address:
                linkedto = cast(SSV.SimAddress, linkedto)
                result[addr] = byte_from_dw(linkedto.offset, pos)
            else:
                result[addr] = -1
        elif simval.is_literal and simval.is_defined:
            simliteral = cast(SV.SimLiteralValue, simval)
            result[addr] = simliteral.value
        else:
            result[addr] = -1
    return result
