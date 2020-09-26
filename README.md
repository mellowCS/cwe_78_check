# cwe_78_check
The CWE 78 Check contains a Ghidra script which analyses binaries for possible OS command injection based on a heuristical approach

# Use
To use the script, call the `start_analysis.py` script from the project's root directory. Below is an example:
```
python3 start_analysis.py --ghidra $HOME/ghidra_9.1.2_PUBLIC --import path/to/binary
```
Both of the flags in the example above are necessary since they tell the script where to find the local ghidra directory or ghidra server <br/> with `--ghidra/-g ` and where to find the binary to be analysed with `--import/-i`. <br/><br/>

The script will start Ghidra in headless mode and create a new project for the binary. Ghidra will then analyse the binary and after the analysis has finished, it will execute the script. After the check was executed, Ghidra will delete the project.

<br/>

# Development
In case you want to further continue the development of the CWE 78 check and do not wish to use the Ghidra Eclipse plugin, you can perform the following steps:

1. Open the terminal
2. Locate your local Ghidra installation and change into its root directory
3. Call `support/buildGhidraJar` which will put a `ghidra.jar` into Ghidra's root directory
4. Put the `ghidra.jar` into `cwe_78_check/lib/`.

This will enable the IDE to find all Ghidra internal classes and avoid a jungle of `import foo cannot be resolved errors`.

There is blog post about setting up a Ghidra development environment without using Eclipse which I will link here:
```
https://reversing.technology/2019/11/18/ghidra-dev-pt1.html
```

### Note:
I have put the `lib` directory into the `.gitignore` since the `ghidra.jar` contains more than a 100 MB of data.

<br/>

# How does the check work?

## Part 1

The check will first build two constructs which we will need to follow values through Ghidra's Pcode.


1. A map from system functions (e.g. system, execl) to the addresses at which they are called
2. A basic block graph where each block will contain two collections of addresses of source and destination blocks as well as their contents

## Part 2

Here I will explain the basic functionality using Pseudo Code. First we are going to look at the `findSourceOfSystemCallInput()` function which iterates over all system functions and addresses at which they are called using the map we built in `Part 1`. For each of those locations we build a block trace to the start of the program using the block graph and put the tracked values into the created storage.

```
0. function findSourceOfSystemCallInput()
1.     for function in SystemMap:
2.         get function's parameters;
3.         for address in called locations:
4.             create storage to track values;                 // registers and memory positions
5.             get block where function is called by address;
6.             buildTraceToProgramStart();
7.             add result to output;
8.     return output;
```

Now we are going to take a closer look at the `buildTraceToProgramStart()` function. This function is recursive and calls itself for each source block of the currently analysed block. For each block it also calls `getInputLocationAtBlockStart()` which tracks value from each OUT edge to each IN edge of the block. Further, in each call the storage is checked for constant values. If it only has constant values, the trace is stopped and the result is returned as we do not have to do anymore tracking. Also if there is no source block left, we reached the program start and are done.
```
0. function buildTraceToProgramStart()
2.     getInputLocationAtBlockStart();
3.     if storage is not constant:                  // constant storage means only constant values
4.         for source in current block's sources:
5.             if source block exists:
7.                 buildTraceToProgramStart();
8.         if there is no source block left:
9.             return;
10.    return;
```

The next function is `getInputLocationAtBlockStart()` which tracks values through one block. It takes compounds of Pcode instructions where each compound belongs to exactly one assembly instruction. It iterates backwards through these compounds and checks whether it contains in - or output objects that match the tracked objects. (e.g. if the register RAX is overwritten by some value, we have RAX as output object which we can match against the storage.). Due to these checks we can avoid analysing each individual Pcode instruction and just skip the compound if there are no interesting objects. We also skip the very first compound as the input parameter will only be altered before that.
```
0. function getInputLocationAtBlockStart()
1.     for each compound backwards:
2.         if first compound of first block: skip
3.         if first compound of latter block:
4.             checkIfCallIsOriginFunction();
5.         else:
6.             
```