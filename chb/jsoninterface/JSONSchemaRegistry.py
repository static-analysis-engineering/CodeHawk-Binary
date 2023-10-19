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

import json

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
                elif key in ["oneOf", "anyOf"]:
                    for choice in d[key]:
                        aux(choice)
                elif key == "$ref":
                    if d[key] == "#":
                        continue
                    defname: str = d[key][8:]
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
    S.appcomparison,
    S.auxvariable,
    S.assemblyblock,
    S.assemblyfunction,
    S.assemblyinstruction,
    S.binarycomparison,
    S.blockcomparison,
    S.blockexpansion,
    S.blocksemanticcomparison,
    S.callgraph,
    S.callgraphedge,
    S.callgraphnode,
    S.callgraphcomparison,
    S.callsiteargument,
    S.callsiterecord,
    S.callsiterecords,
    S.callsitetgtparameter,
    S.callsitetgtfunction,
    S.cfgcomparison,
    S.cfgedge,
    S.cfgedgecomparison,
    S.cfgnode,
    S.controlflowgraph,
    S.functionadded,
    S.functioncomparison,
    S.functioninvariants,
    S.functionsemanticcomparison,
    S.globalvarcomparison,
    S.instructioncomparison,
    S.invariantfact,
    S.linearequality,
    S.localvarscomparison,
    S.locationinvariant,
    S.memorybase,
    S.memoryoffset,
    S.nonrelationalvalue,
    S.sectionheaderdata,
    S.stackpointeroffset,
    S.xblockdetail,
    S.xcomparison,
    S.xedgedetail,
    S.xconstant,
    S.xexpression,
    S.xfilepath,
    S.xvariable
]


for s in chb_schemas:
    json_schema_registry.add_schema(s["name"], s)
json_schema_registry.add_schemas_defs()


def schema_metadata(name: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "description": "CodeHawk json result metadata",
        "type": "object",
        "required": ["status", "date", "time", "version"],
        "properties": {
            "status": {
                "type": "string",
                "enum": ["ok", "fail"],
                "description": "indication if data gathering was successful"
            },
            "date": {
                "type": "string",
                "format": "date",
                "description": "date (YYYY-MM-DD) of result"
            },
            "time": {
                "type": "string",
                "description": "time (HH:MM:SS) of result"
            },
            "schema": {
                "type": "string",
                "enum": [name],
                "description": "name of json result schema"
            },
            "version": {
                "type": "string",
                "description": "CodeHawk-Binary version number"
            },
            "reason": {
                "type": "string",
                "description": "Reason for failure"
            }
        }
    }
    return metadata


def save_schema(name: str, title: str) -> None:
    (schema, defs) = json_schema_registry.get_definition(name).to_json()
    filename = name + ".json"
    result: Dict[str, Any] = {}
    result["name"] = name
    result["title"] = title
    result["type"] = "object"
    result["required"] = ["meta"]
    result["properties"] = properties = {}
    properties["meta"] = schema_metadata(name)
    properties["content"] = schema
    if len(defs) > 0:
        result["$defs"] = defs
    with open(filename, "w") as fp:
        json.dump(result, fp, indent=2)
    print("Saved schema for " + name + " in file " + filename)


if __name__ == "__main__":

    save_schema(
        "appcomparison",
        "json result file for relational analysis")
    save_schema(
        "assemblyfunction",
        "json result file for an assembly function")
    save_schema(
        "controlflowgraph",
        "json result file for a control flow graph")
    save_schema(
        "functioninvariants",
        "json result file for the location invariants within a function")
    save_schema(
        "xcomparison",
        "json result file for the structural differences between two binaries")
    save_schema(
        "callsiterecords",
        "json result file for reporting callsites")
