# AutomaticPoliciesForBPFContain
This program allows for the automatic generation of BPFContain policies based on the traced operations for a given program.

## Requirements

***TODO***

## Instructions

First, run `sudo bpftrace --unsafe traceSystemOperations.bt <arg> > <traceFile>` where `<arg>` represents the name of the program you wish to trace, and `<traceFile>` represents the name of the output file to save all of the traced operations to. **Note: ** `<traceFile>` should be a `.txt` file.

***TODO translation program instructions***