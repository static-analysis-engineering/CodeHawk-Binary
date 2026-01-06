# Userdata

User data can improve analysis and decompilation. Userdata can be provided in two
ways: json files and C header files. This section describes the json files; C
header files are described here.


## Add userdata

Userdata files are passed to the analyzer via the command-line with the
command-line option <code>--hints</code>. Multiple userdata files can be
passed with this option. If data in multiple files conflict the data from
the last file passed is taken; previous version of the same data are
overwritten.

Some command that provide the <code>--hints</code> option include
```
> chkx analyze ... --hints ...
> chkx results ast ... --hints ...
> chkx relational prepare ... --hints ...
...
```

## Userdata file layout

Userdata format is json. The general layout of the json file is
```
{
    "userdata": {
        "<section-1>": { ... },
        "<section-2>": { ... },
        "<section-3>": { ... },
        ....
        "<section-n>": { ... }
     }
}
```
where <code>section-i</code> is the name of of a particular kind of userdata that is
supported. Each kind of userdata has its own format and meaning, as explained
below. It is recommended to add some additional top-level properties to the file,
such as a hash (e.g., md5 or sha256) to identify the binary to which the userdata
applies, or the name and release date of the binary. These additional properties,
however, are not enforced or used otherwise.

**Caution** The section names must be exact. Sections with misspelled names are
silently ignored. To check if a section was read correctly, inspect the file
<binary>.ch/u/<binary>_system_u.xml after initiating the analysis, to verify
the corresponding xml section that is passed to the back-end ocaml analyzer.


## Kinds of userdata

The kinds of userdata that can be passed to the analysis is varied and tends to
grow/change over time. Below is a list of the kinds of userdata currently
supported.

- **ARM-Thumb switch points** ([arm-thumb](userdata/arm-thumb.md)):
  A list of addresses where an ARM binary
  switches from ARM representation to Thumb-2 and v.v.

- **Call-back Tables** ([call-back-tables](userdata/call-back-tables.md)):
  A table of addresses
  mapped to the declared name of a call-back table in memory.

- **Call Targets for Indirect Calls** ([call-targets](userdata/call-targets.md)):
  A list of targets for indirect function calls.

- **Data Regions within Code** ([data-blocks](userdata/data-blocks.md)):
  A list of start and end addresses
  of regions within the code section that contain data.

- **Function Annotations** ([function-annotations](userdata/function-annotations.md)):
  Annotations with the aim to improve the quality of a decompilation to C, including
  names/types for register and stack variables.

- **Function Entry Points** ([function-entry-points](userdata/function-entry-points.md)):
  A list of addresses that are the start of a function.