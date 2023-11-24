# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs, LLC
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
import json

from typing import Any, Dict, List, Optional

import chb.util.fileutil as UF


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
        return self._d.get("vahex", "0x0")


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
    def is_trampoline(self) -> bool:
        return self.patchkind == "Trampoline"

    def has_details(self) -> bool:
        return "details" in self._d

    def get_details(self) -> Optional[Dict[str, Any]]:
        return self._d.get("details")

    def has_wrapper(self) -> bool:
        details = self._d.get("details")
        if details is not None:
            if "wrapper" in details:
                wrapper = details.get("wrapper")
                return wrapper is not None
            else:
                return False
        else:
            return False

    @property
    def wrapper(self) -> PatchWrapper:
        details = self._d.get("details")
        if details is not None:
            wrapper = details.get("wrapper")
            if wrapper is not None:
                return PatchWrapper(wrapper)
            else:
                raise UF.CHBError("Patch event does not have a wrapper")
        else:
            raise UF.CHBError("Patch event does not have a wrapper")

    def has_payload(self) -> bool:
        details = self._d.get("details")
        if details is not None:
            if "payload" in details:
                payload = details.get("payload")
                return payload is not None
            else:
                return False
        else:
            return False

    @property
    def payload(self) -> PatchPayload:
        details = self._d.get("details")
        if details is not None:
            payload = details.get("payload")
            if payload is not None:
                return PatchPayload(payload)
            else:
                raise UF.CHBError("Patch event does not have a payload")
        else:
            raise UF.CHBError("Patch event does not have a payload")

    @property
    def cases(self) -> List[str]:
        details = self._d.get("details")
        if details is not None:
            return self._d.get("cases", [])
        else:
            return []

        
class PatchResults:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d
        self._events: Optional[List[PatchEvent]] = None

    @property
    def events(self) -> List[PatchEvent]:
        if self._events is None:
            self._events = []
            for de in self._d["events"]:
                self._events.append(PatchEvent(de))
        return self._events

    @property
    def trampoline_payload_addresses(self) -> List[str]:
        result: List[str] = []
        for e in self.events:
            if e.is_trampoline and e.has_payload():
                result.append(e.payload.vahex)
        return result

if __name__ == "__main__":

    with open("patch_description_file.json") as fp:
        pdata = json.load(fp)

    pd = PatchResults(pdata)
    print(str(pd.trampoline_payload_addresses))
