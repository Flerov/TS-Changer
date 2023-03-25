# TS-Fucker
### Description
TestSigning mode is a boot configuration option in Windows that allows users to load and execute drivers and system files that have not been digitally signed by Microsoft.
### Usage
Put Machine into TestSigning - Mode >
TS-Fucker.exe 1

Put Machine out of TestSigning - Mode >
TS-Fucker.exe 0

### About
In my Project I abuse a security vulnerability inside of the appended dbutil_2_3.sys Driver to gain Read/Write Power
in order to alter the machines current state without having to restart the machine. < /br>
In order for the program to run the driver has to be loaded ie via ManualMapping or using the OSRLoader-Tool
