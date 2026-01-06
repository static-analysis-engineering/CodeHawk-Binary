### Call targets

**Description**

In many cases the analyzer is able to resolve indirect function calls. For
those cases where automatic resolution of targets fails the user can supply
a list of targets explicitly in the userdata.

A call target may be specified in a number of ways depending on the kind of
target:
- *application function:* <code>app:\<function-address\></code>
- *shared-object function:* <code>so:\<function-name\></code>
- *java native interface:* <code>jni:\<jni-index\></code>
- *call-back table function:* <code>cba:\<call-back table address/>:\<offset\></code>

**Format**

A list of records of the following structure:
```
   {"fa":<function-address>,
    "ia":<instruction-address of call-site>,
    "tgts": [
       | {"app":<address of target application function>}
       | {"so":<name of target library function>}
       | {"jni": <index of java native function>}
       | {"cba": <address of call-back table>:<offset of function pointer in record>}
    ]
    }
```

**Example**

```
{
    "userdata": {
        ...
        "call-targets": [
            {"ia": "0x40d5dc",
             "fa": "0x40d510",
             "tgts": [{"cba": "0x4a5c30:8"}]
            },
            {"ia": "0x40a6a4",
             "fa": "0x409dd0",
             "tgts": [{"cba": "0x4a5910:12"}]
            },
            {"ia": "0x40aba8",
             "fa": "0x409dd0",
             "tgts": [{"cba": "0x4a5910:16"}]
            },
            {"ia": "0x40afd8",
             "fa": "0x409dd0",
             "tgts": [{"cba": "0x4a5910:20"}]
            },
            {"ia": "0x40b304",
             "fa": "0x40b288",
             "tgts": [{"app": "0x401018"}, {"app": "0x403200"}]
            },
            {"ia": "0x40c800",
             "fa": "0x40c780",
             "tgts": [{"so": "memcpy"}]
            }            
        ]
    }
}
```