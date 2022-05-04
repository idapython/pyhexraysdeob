# Emotet CFG Unflattening Proof Of Concept

This is a PoC of unflattening Emotet's Control Flow obfuscation. The malware uses Control Flow Flattening to conceal the program flow. This IDA Python module aims to unflatten and deobfuscate this obfuscation layer.

The base of this project is a fork of the pyhexraysdeob repo, which ports Rolf Rolles' HexRaysDeob project from C++ to python. 
Many ideas and algorithms included in this project were insipired and taken from the original project. The link to Rolf Rolles project
is linked below:

* [HexRaysDeob](https://github.com/RolfRolles/HexRaysDeob) 

In the folder examples, you can see a comparisons between obfuscated and deobfuscated samples.

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

## Limitations & Known Issues

The purpose of this tool is to share our experience and results of attacking Emotet's Control Flow Flattening. In the current state, this solution is not able to deobfuscate all functions completely. Among the outstanding issues:

* The algorithm to detected nested dispatchers is simple. If turned off and your gut feeling tells you the decompiled output looks wrong, it is worth reinvestigating. Overall, we recommend researchers to always cross-check their results and not trust the output blindly.
* Conditional states are not handled by this tool.
* In some cases, we optimize away the `break` statement in a while loop. We are working on this issue. However, bear in mind that this issue exists when analysing an unflattened function 
* During development and evaluation, we experienced crashes. Thus, we recommend saving often and keeping a separate copy of the IDB file. When working with the tool, we usually keep two windows open. One solely to use with the tool, and one without unflattening activated. As explained above, another way to stabilize the tool is to turn if only on if you are looking at a particular function you want to unflatten.
* Our research and this tool is based on a previous version of Emotet than the one that is currently propagated by the threat actors (date: 2022-05-04). Thus, if you plan to run the tool on the newest version, the tool will not give you the results as described in the blog article. Below is a list of emotet hashes we have tested the tool on:

```

```

