# AutomaticPoliciesForBPFContain
This program allows for the automatic generation of [BPFContain](https://github.com/willfindlay/bpfcontain-rs) policies based on the traced operations of a given program.

## Requirements

- Linux kernel version >= 5.10
    - Compiled kernel should include the following flags:
    ```
    CONFIG_BPF=y
    CONFIG_BPF_SYSCALL=y
    CONFIG_BPF_JIT=y
    CONFIG_HAVE_EBPF_JIT=y
    CONFIG_TRACEPOINTS=y
    CONFIG_BPF_LSM=y
    CONFIG_DEBUG_INFO=y
    CONFIG_DEBUG_INFO_BTF=y
    CONFIG_BPF_EVENTS=y
    ```
- bpftrace >= v0.13.1
- Python >= v3.8
    - Run `pip install -r requirements.txt` to install required Python modules.

## Instructions

The file `policyGenerator.py` can be used to run both the tracing and translation programs. 
- First, make sure you're using a root shell, which can be accomplished via. the following command: 
`sudo bash`

- Then, run: 
`python policyGenerator.py -c <traceFile> -o <policyFile> -p <program> -f <programPath> -t <traceTime>`
    - `<traceFile>` represents the name of the output (`.txt`) file that all traced operations are saved to.
    - `<policyFile>` represents the name of the output (`.yml`) file that will contain the generated security policy.
    - `<program>` is the name of the program to trace, and `<programPath>` is the full path to the program.
    - `<traceTime>` is the time in seconds, representing how long the program will be traced for.

The tracing and translation programs can also be run seperately. 
- First, run the tracing program using: 
`sudo bpftrace traceSystemOperations.bt <arg> > <traceFile>`
    - `<arg>` represents the name of the program you wish to trace, and `<traceFile>` represents the name of the output (`.txt`) file to save all of the traced operations to.

- Then, the translation program can be run to generate the [BPFContain](https://github.com/willfindlay/bpfcontain-rs) security policy using:
`python translateToPolicy.py -c <traceFile> -o <policyFile> -p <program> -f <programPath>`
    - `<traceFile>` represents the name of the (`.txt`) trace file generated in the previous step.
    - `<policyFile>` represents the name of the output (`.yml`) file that will contain the generated security policy.
    - `<program>` is the name of the program to trace, and `<programPath>` is the full path to the program.