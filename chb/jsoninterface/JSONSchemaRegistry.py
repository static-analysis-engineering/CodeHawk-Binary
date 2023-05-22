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
"""Registry for json schemas that can be referred to by JSONResult objects."""

from typing import Any, Dict, List

import chb.jsoninterface.JSONCHBSchemas as S
from chb.jsoninterface.JSONSchema import JSONSchema

import chb.util.fileutil as UF


class JSONSchemaRegistry:

    def __init__(self) -> None:
        self._registry: Dict[str, JSONSchema] = {}

    @property
    def registry(self) -> Dict[str, JSONSchema]:
        return self._registry

    def add_schema(self, name: str, base: Dict[str, Any]) -> None:
        self._registry[name] = JSONSchema(name, base)
        
    def add_schema_defs(self, schema: JSONSchema) -> None:
        defs: Dict[str, Dict[str, Any]] = {}

        def aux(d: Dict[str, Any]) -> None:
            for key in d:
                if key == "properties":
                    for p in d[key]:
                        aux(d["properties"][p])
                elif key == "items":
                    aux(d["items"])
                elif key == "oneOf":
                    for choice in d[key]:
                        aux(choice)
                elif key == "$ref":
                    defname = d[key]
                    if defname in defs:
                        continue
                    elif self.has_definition(defname):
                        refschema = self.get_definition(defname)
                        defs[defname] = refschema.base_schema
                        aux(refschema.base_schema)
                        # for (refd, refdef) in refschema.defs.items():
                        #    if not refd in defs:
                        #        defs[refd] = refdef
                    else:
                        raise UF.CHBError(
                            "Reference to definition " + defname + " not found")

        aux(schema.base_schema)
        schema.set_defs(defs)

    def add_schemas_defs(self) -> None:
        for schema in self.registry.values():
            self.add_schema_defs(schema)

    def has_definition(self, name: str) -> bool:
        return name in self.registry

    def get_definition(self, name: str) -> JSONSchema:
        if name in self.registry:
            return self.registry[name]
        else:
            raise UF.CHBError("No schema definition found for " + name)


json_schema_registry: JSONSchemaRegistry = JSONSchemaRegistry()


chb_schemas: List[Dict[str, Any]] = [
    S.auxvariable,
    S.assemblyblock,
    S.assemblyfunction,
    S.assemblyinstruction,
    S.functioninvariants,
    S.invariantfact,
    S.linearequality,
    S.locationinvariant,
    S.memorybase,
    S.memoryoffset,
    S.nonrelationalvalue,
    S.stackpointeroffset,
    S.xconstant,
    S.xexpression,
    S.xvariable
]


for s in chb_schemas:
    json_schema_registry.add_schema(s["name"], s)
json_schema_registry.add_schemas_defs()
