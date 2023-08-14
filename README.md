# TS-Changer
### Description
TestSigning mode is a boot configuration option in Windows that allows users to load and execute drivers and system files that have not been digitally signed by Microsoft.
### Usage
Put Machine into TestSigning - Mode >
TS-Fucker.exe 1

Put Machine out of TestSigning - Mode >
TS-Fucker.exe 0

### About
In my Project I abuse a security vulnerability inside of the appended dbutil_2_3.sys Driver to gain Read/Write Power
in order to alter the machines current state without having to restart the machine. <br>
In order for the program to run the driver has to be loaded ie via ManualMapping or using the OSRLoader-Tool. <br>
The Code will download a Symbols File for your current systems version in order to find the right places for the necessary modifications. <br>
Furthermore the Code will run on all System Versions that have not yet blocked the loading of the vulnerable driver.

### Demo
![Alt Text](https://github.com/Flerov/TS-Fucker/blob/Images/In-TS.png)
![Alt Text](https://github.com/Flerov/TS-Fucker/blob/Images/Out-TS.png)
