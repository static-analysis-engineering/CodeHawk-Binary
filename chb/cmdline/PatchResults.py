# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2025  Aarno Labs, LLC
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
"""Describes the structure of a patch applied to a function.

The patch results file is a json file produced by the patcher that describes
the components of a patch and their locations in the patched executable.

The purpose of the patch results file is to inform the analyzer about the
structure of the patch to facilitate a better lifting and to enable proper
validation of the various components.

The main access point for the patch results data is through the PatchParticulars
class, which also collects validation results for the patch.

The PatchParticulars class file also contains a detailed description of the
structure of the different kinds of patches and their respective requirements:

chb/relational/PatchParticulars.py


"""
import json

from typing import Any, Dict, List, Optional

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger


class PatchPayload:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d

    @property
    def offset(self) -> int:
        return self._d.get("offset", -1)

    @property
    def removed(self) -> int:
        return self._d.get("removed", 0)

    @property
    def inserted(self) -> int:
        return self._d.get("inserted", 0)

    @property
    def offsethex(self) -> str:
        return self._d.get("offsethex", "0x0")

    @property
    def vahex(self) -> str:
        return self._d.get("vahex", "0x0")

    def __str__(self) -> str:
        return (
            "Payload("
            + self.vahex
            + ", removed:"
            + str(self.removed)
            + ", inserted:"
            + str(self.inserted)
            + ")")


class PatchWrapper:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d

    @property
    def offset(self) -> int:
        return self._d.get("offset", -1)

    @property
    def removed(self) -> int:
        return self._d.get("removed", 0)

    @property
    def inserted(self) -> int:
        return self._d.get("inserted", 0)

    @property
    def offsethex(self) -> str:
        return self._d.get("offsethex", "0x0")

    @property
    def vahex(self) -> str:
        """Returns the hex start address of the wrapper."""

        return self._d.get("vahex", "0x0")

    def in_wrapper(self, addr: str) -> bool:
        """Returns true if addr is contained within the wrapper."""

        if addr.startswith("0x"):
            intva = int(self.vahex, 16)
            intaddr = int(addr, 16)
            return intva <= intaddr and intaddr < intva + self.inserted
        else:
            return False

    def __str__(self) -> str:
        return (
            "Wrapper("
            + self.vahex
            + ", removed:"
            + str(self.removed)
            + ", inserted:"
            + str(self.inserted)
            +" )")


class PatchDetails:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d

    def has_wrapper(self) -> bool:
        return "wrapper" in self._d

    @property
    def wrapper(self) -> PatchWrapper:
        return PatchWrapper(self._d.get("wrapper", {}))

    def has_payload(self) -> bool:
        return "payload" in self._d

    @property
    def payload(self) -> PatchPayload:
        return PatchPayload(self._d.get("payload", {}))

    @property
    def cases(self) -> List[str]:
        return self._d.get("cases", [])

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(str(self.wrapper))
        if self.payload is not None:
            lines.append("\nPayload:")
            lines.append(str(self.payload))
        lines.append("cases: [" + ", ".join(self.cases) + "]")
        return "\n".join(lines)


class PatchLabelOffsets:

    def __init__(self, d: Dict[str, Any], base: str) -> None:
        self._d = d
        self._base = base

    @property
    def base(self) -> str:
        """Returns the hex base address for the offsets."""

        return self._base

    def _convert_offset(self, offset: int) -> str:
        """Returns the virtual address corresponding to the offset."""

        return hex(offset + int(self.base, 16))

    def label_offset(self, label: str) -> int:
        return self._d.get(label, 0)

    def label_address(self, label: str) -> str:
        return self._convert_offset(self.label_offset(label))

    @property
    def case_fallthrough_jump(self) -> Optional[str]:
        label = "case_fallthrough_jump"
        if label in self._d:
            return self.label_address(label)
        return None

    @property
    def dispatch_offsets(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for name in self._d:
            if name.startswith("dispatch_"):
                result[name] = self._d[name]
        return result

    @property
    def dispatch_addresses(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for label in self._d:
            if label.startswith("dispatch_"):
                result[label] = self.label_address(label)
        return result


class PatchDestinations:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d

    @property
    def payload(self) -> str:
        return hex(self._d.get("payload", 0))

    @property
    def fallthrough(self) -> str:
        return hex(self._d.get("fallthrough", 0))

    def has_fallthrough(self) -> bool:
        return "fallthrough" in self._d

    @property
    def break_dst(self) -> str:
        return hex(self._d.get("break", 0))

    @property
    def continue_dst(self) -> str:
        return hex(self._d.get("continue", 0))

    @property
    def return_dst(self) -> str:
        return hex(self._d.get("return", 0))

    def __str__(self) -> str:
        lines: List = []
        lines.append("payload     : " + self.payload)
        lines.append("fallthrough : " + self.fallthrough)
        lines.append("break       : " + self.break_dst)
        lines.append("continue    : " + self.continue_dst)
        lines.append("return      : " + self.return_dst)
        return "\n".join(lines)


class PatchExtras:

    def __init__(self, d: Dict[str, Any], base: str) -> None:
        self._d = d
        self._base = base

    @property
    def base(self) -> str:
        return self._base

    def has_labeloffsets(self) -> bool:
        return "labeloffsets" in self._d

    @property
    def labeloffsets(self) -> PatchLabelOffsets:
        return PatchLabelOffsets(self._d.get("labeloffsets", {}), self.base)

    def has_destinations(self) -> bool:
        return "destinations" in self._d

    @property
    def case_fallthrough_jump(self) -> Optional[str]:
        if self.has_labeloffsets():
            return self.labeloffsets.case_fallthrough_jump
        return None

    @property
    def destinations(self) -> PatchDestinations:
        return PatchDestinations(self._d.get("destinations", {}))

    def has_fallthrough_destination(self) -> bool:
        return self.destinations.has_fallthrough()

    @property
    def dispatch_addresses(self) -> Dict[str, str]:
        return self.labeloffsets.dispatch_addresses

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\nLabel offsets")
        lines.append(str(self.labeloffsets))
        lines.append("\nDestinations")
        lines.append(str(self.destinations))
        return "\n".join(lines)


class PatchEvent:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d

    @property
    def event_type(self) -> str:
        return self._d["event"]

    @property
    def patchkind(self) -> str:
        return self._d["patchkind"]

    @property
    def logicalva(self) -> str:
        return self._d["logicalva"]

    @property
    def is_trampoline(self) -> bool:
        return self.patchkind == "Trampoline"

    @property
    def is_trampoline_pair_minimal_2_and_3(self) -> bool:
        return self.patchkind == "TrampolinePairMinimal2and3"

    @property
    def is_supported(self) -> bool:
        return (self.is_trampoline or self.is_trampoline_pair_minimal_2_and_3)

    def has_details(self) -> bool:
        return "details" in self._d

    @property
    def details(self) -> PatchDetails:
        return PatchDetails(self._d.get("details", {}))

    def has_extras(self) -> bool:
        return "extras" in self._d

    @property
    def extras(self) -> PatchExtras:
        base = self.wrapper.vahex
        return PatchExtras(self._d.get("extras", {}), base)

    def label_address(self, label: str) -> str:
        return self.extras.labeloffsets.label_address(label)

    @property
    def dispatch_addresses(self) -> Dict[str, str]:
        return self.extras.dispatch_addresses

    def has_wrapper(self) -> bool:
        return self.details.has_wrapper()

    @property
    def wrapper(self) -> PatchWrapper:
        return self.details.wrapper

    def in_wrapper(self, addr: str) -> bool:
        if self.has_wrapper():
            return self.wrapper.in_wrapper(addr)
        else:
            return False

    def has_payload(self) -> bool:
        return self.details.has_payload()

    @property
    def payload(self) -> PatchPayload:
        return self.details.payload

    @property
    def cases(self) -> List[str]:
        return self.details.cases

    def has_fallthrough_destination(self) -> bool:
        return self.extras.has_fallthrough_destination()

    @property
    def fallthrough_destination(self) -> Optional[str]:
        return self.extras.destinations.fallthrough

    @property
    def case_fallthrough_jump(self) -> Optional[str]:
        if self.has_wrapper():
            base = self.wrapper.vahex
            return self.extras.case_fallthrough_jump
        return None

    def __str__(self) -> str:
        lines: List[str] = []
        if self.has_wrapper():
            lines.append(str(self.wrapper))
        if self.has_payload():
            lines.append(str(self.payload))
        lines.append("Cases: " + ", ".join(self.cases))
        return "\n".join(lines)


class PatchResults:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d
        self._events: Optional[List[PatchEvent]] = None

    @property
    def events(self) -> List[PatchEvent]:
        if self._events is None:
            self._events = []
            for de in self._d["events"]:
                if de["category"] == "failure":
                    continue
                self._events.append(PatchEvent(de))
        return self._events

    @property
    def trampoline_payload_addresses(self) -> List[str]:
        return [str(e.payload.vahex) for e in self.events if e.has_payload()]

    @property
    def trampoline_addresses(self) -> List[Dict[str, str]]:
        result: List[Dict[str, str]] = []
        for e in self.events:
            r: Dict[str, str] = {}
            if e.is_trampoline:
                r["logicalva"] = e.logicalva
                r["kind"] = "trampoline"
                if e.has_payload():
                    r["payload"] = e.payload.vahex
                if e.has_wrapper():
                    r["wrapper"] = e.wrapper.vahex
                if e.has_fallthrough_destination() and e.fallthrough_destination:
                    r["fallthrough"] = e.fallthrough_destination
                if e.case_fallthrough_jump is not None:
                    r["fallthrough-jump"] = e.case_fallthrough_jump
                result.append(r)
            elif e.is_trampoline_pair_minimal_2_and_3:
                r["logicalva"] = e.logicalva
                r["kind"] = "trampoline-pair-minimal-2-and-3"
                if e.has_wrapper():
                    r["wrapper"] = e.wrapper.vahex
                if e.has_fallthrough_destination() and e.fallthrough_destination:
                    r["fallthrough"] = e.fallthrough_destination
                if e.case_fallthrough_jump is not None:
                    r["fallthrough-jump"] = e.case_fallthrough_jump
                result.append(r)
        return result


if __name__ == "__main__":

    with open("patch_description_file.json") as fp:
        pdata = json.load(fp)

    pd = PatchResults(pdata)
    print(str(pd.trampoline_payload_addresses))
