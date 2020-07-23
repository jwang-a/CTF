# Accounting Accidents

## Index
*   [Index](#index)

*   [Problem Recap](#problem-recap)

*   [Solution](#solution)


## Problem Recap
This challenge provides a balanced binary tree, initializes some nodes, and then allows users to insert four arbitrary nodes into the tree.

Before inserting the nodes, it also reads a string onto one of the node, This read has length greater than buffer size, which creates a BOF and allows overwriting the function pointer stored in node.

Finally, after everything is done, the program calls function pointer stored in root node.

The program is compiled without PIE, and also provides a "win function" which prints out flag to user.

## Solution

Our target is pretty simple, hijack function pointer with BOF, and manage to nudge the hijacked node up to root by inserting new nodes and forcing the program to rebalance tree.

The "standard" way to do this challenge is by identifying the tree type(RBTree, AVLTree, AATree ...), and calculate exact inputs that rotates tree nodes as desired.

However, I am too lazy to do this, instead I just started manually fuzzing the inputs to search for a valid solution. This is when things started getting interesting.

First of all, the program had "prettyprint" function, which calls usleep() for each character printed, which makes fuzzing unbearably slow. My solution for this is to edit the STRTAB entry of usleep to "isnan", this successfully tricks program into retriving the isnan() function instead of usleep() function while doing runtime function linkage.

The second problem is the program never prints out the entire tree. So to check tree layout, I will have to manually open gdb and trace the nodes located on heap. Doing this once or twice is fine, but my patience gradually worn out at some point. I then recalled that there was this gdbscript thing that allows users to add custom commands to gdb. Though I have never wrote one before, it seemed pretty promising. Determined to learn something new, I looked up the gdb scripting manual and wrote a simple gdbscript that retrieves root node pointer from stack, and prints out the tree.

Finally, I prepared a wrapper script to make fuzzing easier. The rest is just trying all kinds of input based on how the tree, the fuzzed output is shown below.

```
user@localhost python3 fuzz.py 26 27 24 23
TREE : 

                +------(10)
        +------(20)
        |       +------(25)
+------(30)
        +------(40)
                +------(50)

==============
TREE : 

                +------(10)
        +------(20)
        |       +------(25)
        |               +------(26)
+------(30)
        +------(40)
                +------(50)

==============
TREE : 

                +------(10)
        +------(20)
        |       |       +------(25)
        |       +------(26)
        |               +------(27)
+------(30)
        +------(40)
                +------(50)

==============
TREE : 

                        +------(10)
                +------(20)
                |       +------(24)
        +------(25)
        |       +------(26)
        |               +------(27)
+------(30)
        +------(40)
                +------(50)

==============
TREE : 

                +------(10)
        +------(20)
        |       |       +------(23)
        |       +------(24)
+------(25)
        |       +------(26)
        |       |       +------(27)
        +------(30)
                +------(40)
                        +------(50)

==============
```

The decision to learn gdbscript turned out to be a right one. It wasn't long before I found a valid solution and got first blood on this chall.

Scripts for fuzzing & patching can be found in the same github repo as this writeup.

[Top](#accounting-accidents)
