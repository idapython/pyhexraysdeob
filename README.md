# Emotet CFG Unflattening Proof Of Concept

This is a PoC of unflattening Emotet's Control Flow obfuscation. The malware uses Control Flow Flattening to conceal the program flow. This IDA Python module aims to unflatten and deobfuscate this obfuscation layer.

The base of this project is a fork of the pyhexraysdeob repo, which ports Rolf Rolles' HexRaysDeob project from C++ to python. 
Many ideas and algorithms included in this project were insipired and taken from the original project. The link to Rolf Rolles project
is linked below:

* [HexRaysDeob](https://github.com/RolfRolles/HexRaysDeob) 

## Pre Requirements

The code depends on the python port of the ida microcode api. The script was tested with following versions:

* Ida Pro Version 7.5
* At least Hexrays Decompiler Version v7.6.0.210427 
* IDAPython with Python3.6 interpreter

## Usage

Simply load the `emotet_unflatten.py` script via `File->Script File ..` in Ida Pro. Next, load the plugin by issueing the following commands in the interactive ida python window:

```python
unflattener = PLUGIN_ENTRY()
unflattener.run(0)
```

The script operates on microcode level, acting as a plugin for the hexrays decompiler. Each time you decompile a function, the script will attempt to unflatten the target function.

## Features

### Multiple Dispatchers

In Control Flow Flattening, a control flow dispatcher is responsible for determining which block gets executed next based on the value of the state variable. Sometimes, functions can have multiple dispatchers. Therefore we added the possibility to run the unflattening algorithm on multiple possible dispatchers. You can turn this feature on and off by using:

```python
# unflattener.RUN_MLTPL_DISPATCHERS = True
unflattener.RUN_MLTPL_DISPATCHERS = False
```

Per default, this feature is turned on.

### White Listing & Black Listing

Based on Rolf Rolles' code, the plugin tries to determine whether a function is control flow flattened or not. If yes, it will attempt to unflatten it. If not, the function will be added to a blacklist. Sometimes, the determination algorithm is error prone. Thus, we added a feature to add or remove functions to the white list manually. The plugin will always attempt to unflatten functions in the white list. See the command below for instructions on how to add to white list:

```python
# always needs virtual address as input
X.enforce_unflatten(0x1001ec5a)
```
