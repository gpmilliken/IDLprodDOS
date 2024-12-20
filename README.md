## idlreset.c Novell Netware Intruder Detection Lock Out reset
### by George Milliken 1994
OpenNet Novell Netware 
```
Source files: 
idlreset.c
Attaches to the supervisor object, and does a reset WITHOUT the user having supervisor level privs

makeobj.c
Makes a "supervisor" class object in the NetWare bindery, run this once first

By    : George Milliken

Date  : 02/15/94

Version 1.00

Free Distribution, attribution mandatory, fees optional
```

_Notes from 12-10-2024_

This program does a really neat trick that was impossible in 1994. It allowed us to create a special object in the bindery and then delegate the authoirty to reset passwords to help desk users. They used a Visual Basic program that connected to that object and then performewd the password reset. This was a game changer for Wells Fargo Bank help desk. Prior to the program existing a large number of tellers and other people were locked out accidentally everydya and had to call the help desk. his program cut the call time and made the reset very easy becuase a low level non technical employee could reset a password.

Note in 1994 hardcoded passwords was not abnormal, and hackers were still reading 2600 magazine. The world was a much safer place than in 2024. Today, we know we should never hard code a password.

_Notes from 1994_

This program attempts to attach and login to another server under a
help desk ID.  Then perform a password reset on the Target User.

The purpose is to allow help desk personnel to reset intruder lock
outs without giving them a supervisor account the shell will login
can access.

You must create a WFBIDLRESET object of type 5 (1280 decimal, 0x500)
using the makeobj.exe

Passwords to the WFBIDLRESET object can be changed by deleting the
object using BINDEDIT and recreating it using makeobj with the new
password.
