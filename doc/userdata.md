# User Data

User data can improve analysis. The first time an executable is disassembled
the analyzer will create a directory [exe].chu/  with a template xml file for 
user data.
The user can add annotations and hints for the analysis to this
file to improve/correct the disassembly, assist in understanding of the code,
or to improve the analysis precision. 

Following are the types of data that can be added.

## General

### Function entry points
Function entry points are obtained from direct call instructions and, as much as
possible, extracted from data-flow analysis results for indirect calls. Additional
function entry points that are not recognized automatically can be manually added. 
Format:
```xml
<function-entry-points>
    <fe a="0x401000"/>
    <fe a="0x402010"/>
	....
</function-entry-points>
```

### Function names
Function names are extracted from symbols and export tables whenever available.
Additional function names can be manually added. Function names, whenever
available, will replace the address in reports and variable names. Format:
```xml
<function-names>
   <fn a="0x401050" n="foo"/>
   <fn a="0x401060" n="bar"/>
   ...
</function-names>
```

### Data blocks
The analyzer blocks out jump tables and other PE components that may reside in
code sections. There may, however, be additional data (e.g., strings) in the
code sections that is not recognized as such by the analyzer, which may disrupt
the disassembly. This data can be blocked out explicitly by adding data blocks
to the user data. Format:
```xml
<data-blocks>
   <db start="0x401000" end="0x401100"/>
   <db start="0x402000" end="0x402060"/>
   ...
</data-blocks>
```

### Non-returning functions
The analyzer generally propagates the fact that a function does not return.
Additional non-returning functions can be manually added. Format:
```xml
<non-returning-functions>
   <nr a="0x400300"/>
   <nr a="0x420010"/>
   ...
</non-returning-functions>
```

### Non-returning calls
In some cases functions may or may not return depending on the arguments or
the value of some global variable. The user can set a particular invocation
of the function as non-returning without making the function non-returning
for other invocations. Format:
```xml
<non-returning-calls>
   <nrc fa="0x4001000" ia="0x4001020"/>
   <nrc fa="0x4201000" ia="0x4201100"/>
   ...
</non-returning-calls>
```
where fa and ia indicate the address of the function and the address of
the call instruction within that function, respectively.


### Call targets
The user can explicitly identify the target of an unresolved indirect function
call, which can be either a library call (dll or shared object), application
function call, or jni (java native method) call. Format
```xml
<call-targets>
   <tgt fa="0x400100" ia="0x400110" ctag="dll" dll="kernel32.dll" name="GetProcAddress"/>
   <tgt fa="0x420100" ia="0x420200" ctag="app" appa="0x410100"/>
   <tgt fa="0x403000" ia="0x403100" ctag="jni" index="114"/>
   ...
</call-targets>
```
where fa and ia indicate the address of the function and the address of
the call instruction within that function, ctag specifies the type of
call (dll, app, or jni). In case of a dll call, the dll attribute and
name attribute specify the name of the dll and the name of the function;
in case of an application call, the appa attribute specifies the address
of the application function; in case of a jni call, the index attribute
specifies the jni-index of the function.


### Esp adjustments
In general stack-pointer adjustments after function calls (with stdcall convention)
are computed automatically by the analyzer based on library or application function
summaries. In some cases the analyzer does not compute the correct adjustment or
does not have sufficient information to compute the adjustment (defaulting to zero
in that case). For these cases an explicit stack-pointer adjustment can be added
by the user. Format:
```xml
<esp-adjustments>
   <esp-adj fa="0x401000" ia="0x401020" adj="4"/>
   <esp-adj fa="0x401000" ia-"0x401036" adj="32"/>
   ...
</esp-adjustments>
```
where fa and ia indicate the address of the function and the address of
the call instruction within that function, and adj specifies the number
of bytes that are to be added to the stack pointer after the call.


### Symbolic addresses
The user can associate addresses of global variables with names and types,
which will result in all references to those variables being replaced with
their names. Furthermore, for pointers to known struct types, field accesses
will be shown by name rather than by field offset. Format:
```xml
<symbolic-addresses>
   <syma a="0x450100" name="globalcounter" type="int" size="4"/>
   <syma a="0x450104" name="globalmsg" size="4">
       <type><ptr>char</ptr></type>
   </syma>
   ...	  
</symbolic-addresses>
```
where the a attribute indicates the address of the global variable, and
size indicates the size of the variable in bytes. The type can be specified
either by an attribute in case of a scalar type, or by a nested type
element.


### Structs
The user can list type names of application structs for which additional
layout information is provided in the *structs* directory. Format
```xml
<structs>
   <struct name="bufchain"/>
   <struct name="datacount"/>
   ...
</structs>
```
where the *structs* directory is expected to have the two files
```
   structs/<appname>_bufchain_struct_u.xml
   structs/<appname>_datacount_struct_u.xml
```
that specify the types and offsets of the  fields of these structs.


### Jump tables
For x86 files the analyzer is mostly able to identify all jump tables. For
MIPS files it may not be able to identify these automatically. In this case
the user can add the location and targets of jump tables explicitly, together
with the indirect jump instructions that refer to them. Format:
```xml
<jump-table-targets>
   <jt-tgt fa="0x401000" ia="0x401010" jta="0x450100"/>
   <jt-tgt fa="0x402400" ia="0x402440" jta="0x450800"/>
   ...
</jump-table-targets>
```
where fa and ia indicate the function address and instruction address of the
indirect jump instruction and jta indicates the start address of the jump
table. The jump table itself is expected to be found in the files:
```
   jumptables/<appname>_0x450100_jumptable_u.xml
   jumptables/<appname>_0x450800_jumptable_u.xml
```

