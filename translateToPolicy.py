import re
import numpy as np
import argparse

class TraceFile():

    def __init__(self, fileName, procName, procPath) -> None:
        # Open the trace file
        with open(fileName) as f:
            traceLines = f.readlines()
        # Remove the first two lines as they are cmd output
        traceLines = traceLines[2:]
        # Split Signals, VFS calls, Pipes, Capabilities, Sockets, Numbered Devices, and filter by process
        self.vfsTraces = []
        self.sigTraces = []
        self.pipeTraces = []
        self.capTraces = []
        self.sockTraces = []
        self.numberedTraces = []
        for line in traceLines:
            if procName in line and 'VFS:' in line:
                self.vfsTraces.append(line)
            elif procName in line and 'Signal:' in line:
                self.sigTraces.append(line)
            elif procName in line and 'Pipe:' in line:
                self.pipeTraces.append(line)
            elif procName in line and 'Capability:' in line:
                self.capTraces.append(line)
            elif procName in line and 'Socket:' in line:
                self.sockTraces.append(line)
            elif 'Device:' in line:
                self.numberedTraces.append(line)
        # Set traced process name and path
        self.procName = procName
        self.procPath = procPath
        # Remove duplicates from VFS
        self.vfsTraces = list(set(self.vfsTraces))
        # Remove duplicates from Signals
        self.sigTraces = list(set(self.sigTraces))
        # Remove duplicates from Pipes
        self.pipeTraces = list(set(self.pipeTraces))
        # Remove duplicates from Capabilities
        self.capTraces = list(set(self.capTraces))
        # Remove duplicates from Sockets
        self.sockTraces = list(set(self.sockTraces))
        # Remove duplicates from Numbered Devices
        self.numberedTraces = list(set(self.numberedTraces))

class TraceToPolicy():

    def __init__(self, traceFile) -> None:
        self.outputPolicyStr = ""
        self.generate_policy_start(traceFile)
        self.generate_policy_allow(traceFile)
        self.generate_policy_restrict(traceFile)
        # TODO self.generate_policy_taint(traceFile)
    
    def generate_policy_start(self, traceFile):
        self.outputPolicyStr += f"name: {traceFile.procName}\n"
        self.outputPolicyStr += f"cmd: {traceFile.procPath}\n\ndefaultTaint: false\n\n"
    
    def generate_policy_allow(self, traceFile):
        self.outputPolicyStr += f"allow:\n"
        self.outputPolicyStr += self.generate_device_access(traceFile.vfsTraces, True)
        self.outputPolicyStr += self.generate_numbered_device_access(traceFile.numberedTraces, True)
        self.outputPolicyStr += self.generate_read_write_execute_modify_access(traceFile, True)
        # TODO Networking
        self.outputPolicyStr += self.generate_signals(traceFile.sigTraces, traceFile.procName, True)
        self.outputPolicyStr += self.generate_capabilities(traceFile.capTraces, traceFile.procName, True)
        self.outputPolicyStr += self.generate_ipc(traceFile.pipeTraces, traceFile.sockTraces, traceFile.procName, True)
    
    def generate_policy_restrict(self, traceFile):
        self.outputPolicyStr += f"deny:\n"
        self.outputPolicyStr += self.generate_device_access(traceFile.vfsTraces, False)
        self.outputPolicyStr += self.generate_numbered_device_access(traceFile.numberedTraces, False)
        self.outputPolicyStr += self.generate_read_write_execute_modify_access(traceFile, False)
        # TODO Networking
        self.outputPolicyStr += self.generate_signals(traceFile.sigTraces, traceFile.procName, False)
        self.outputPolicyStr += self.generate_capabilities(traceFile.capTraces, traceFile.procName, False)
        self.outputPolicyStr += self.generate_ipc(traceFile.pipeTraces, traceFile.sockTraces, traceFile.procName, False)
    
    def generate_policy_taint(self, traceFile):
        # TODO Implement a method for tainting
        return

    def generate_device_access(self, vfsTraces, allowBool):
        #0: stdin, 1: stdout, 2: stderr
        output_string = ""
        terminal_device = False
        null_device = False
        terminal_device_deny = False
        null_device_deny = False
        for t in vfsTraces:
            # Negative result = restrict
            if(not "Return: -" in t):
                if 'Path: /0' in t or 'Path: /1' in t or 'Path: /2' in t:
                    terminal_device = True
                if 'Path: /null' in t:
                    null_device = True
            else:
                if 'Path: /0' in t or 'Path: /1' in t or 'Path: /2' in t:
                    terminal_device_deny = True
                if 'Path: /null' in t:
                    null_device_deny = True
        if(allowBool):
            if terminal_device:
                output_string += "  - device: terminal\n"
            if null_device:
                output_string += "  - device: null\n"
        elif(not allowBool):
            if terminal_device_deny:
                output_string += "  - device: terminal\n"
            if null_device_deny:
                output_string += "  - device: null\n"
        return output_string + "\n"
    
    def generate_numbered_device_access(self, devTraces, allowBool):
        # Group 0 is the major number
        # Group 1 is the minor number
        # Group 2 is the flags
        # Group 3 is the return
        output_string = ""
        numdev_access_map = dict()
        numdev_regex = r"(?:Device: Type: [^,]*, Major: )([-0-9]+)(?:, Minor: )([-0-9]+)(?:, Flags: )([-0-9]+)(?:, Return: )([-0-9]+)"
        numdev_matches = [re.findall(numdev_regex, x)[0] for x in devTraces]
        for dev in numdev_matches:
            if(allowBool):
                if(int(dev[3]) >= 0):
                    decimalFlags = int(dev[2], 10)
                    ocatalNoPad = np.base_repr(decimalFlags, 8) # Decimal to octal
                    if(decimalFlags == 0):
                        octalFlagsPadded = np.base_repr(decimalFlags, 8, 8) # Pad with 8 if we have 0
                    else:
                        octalFlagsPadded = np.base_repr(decimalFlags, 8, 8-len(ocatalNoPad)) # Pad
                    # Add rights
                    if not dev[0] in numdev_access_map.keys():
                        if(octalFlagsPadded[7] == '0'):
                            # Read only
                            numdev_access_map[dev[0]] = ['r']
                        elif(octalFlagsPadded[7] == '3'):
                            # Access
                            numdev_access_map[dev[0]] = ['a']
                        elif(octalFlagsPadded[7] == '1'):
                            # Write only
                            numdev_access_map[dev[0]] = ['w']
                        elif(octalFlagsPadded[7] == '2'):
                            # Read and Write
                            numdev_access_map[dev[0]] = ['r','w']
                    else:
                        if(octalFlagsPadded[7] == '0') and not "r" in numdev_access_map[dev[0]]:
                            # Read only
                            numdev_access_map[dev[0]].append('r')
                        elif(octalFlagsPadded[7] == '3') and not "a" in numdev_access_map[dev[0]]:
                            # Access
                            numdev_access_map[dev[0]].append('a')
                        elif(octalFlagsPadded[7] == '1') and not "w" in numdev_access_map[dev[0]]:
                            # Write only
                            numdev_access_map[dev[0]].append('w')
                        elif(octalFlagsPadded[7] == '2') and not "r" in numdev_access_map[dev[0]] and not "w" in numdev_access_map[dev[0]]:
                            # Read and Write
                            numdev_access_map[dev[0]].append('r')
                            numdev_access_map[dev[0]].append('w')
            if(not allowBool):
                if(int(dev[3]) < 0):
                    decimalFlags = int(dev[2], 10)
                    ocatalNoPad = np.base_repr(decimalFlags, 8) # Decimal to octal
                    if(decimalFlags == 0):
                        octalFlagsPadded = np.base_repr(decimalFlags, 8, 8) # Pad with 8 if we have 0
                    else:
                        octalFlagsPadded = np.base_repr(decimalFlags, 8, 8-len(ocatalNoPad)) # Pad
                    # Add rights
                    if not dev[0] in numdev_access_map.keys():
                        if(octalFlagsPadded[7] == '0'):
                            # Read only
                            numdev_access_map[dev[0]] = ['r']
                        elif(octalFlagsPadded[7] == '3'):
                            # Access
                            numdev_access_map[dev[0]] = ['a']
                        elif(octalFlagsPadded[7] == '1'):
                            # Write only
                            numdev_access_map[dev[0]] = ['w']
                        elif(octalFlagsPadded[7] == '2'):
                            # Read and Write
                            numdev_access_map[dev[0]] = ['r','w']
                    else:
                        if(octalFlagsPadded[7] == '0') and not "r" in numdev_access_map[dev[0]]:
                            # Read only
                            numdev_access_map[dev[0]].append('r')
                        elif(octalFlagsPadded[7] == '3') and not "a" in numdev_access_map[dev[0]]:
                            # Access
                            numdev_access_map[dev[0]].append('a')
                        elif(octalFlagsPadded[7] == '1') and not "w" in numdev_access_map[dev[0]]:
                            # Write only
                            numdev_access_map[dev[0]].append('w')
                        elif(octalFlagsPadded[7] == '2') and not "r" in numdev_access_map[dev[0]] and not "w" in numdev_access_map[dev[0]]:
                            # Read and Write
                            numdev_access_map[dev[0]].append('r')
                            numdev_access_map[dev[0]].append('w')
        # Generate rules
        for devnum in numdev_access_map.keys():
            device_access = ''.join(numdev_access_map[devnum])
            output_string += "  - numberedDevice: {major: "+devnum+", access: "+device_access+"}\n"
        return output_string + "\n"
    
    def generate_read_write_execute_modify_access(self, traceFile, allowBool):
        path_access_map = dict()
        output_string = ""
        # Regex Strings - Group 0 is the path, Group 1 is the return
        read_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Read, Return: )([-0-9]+)"
        write_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Write, Return: )([-0-9]+)"
        access_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Access, Return: )([-0-9]+)"
        execute_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Execute, Return: )([-0-9]+)"
        modify_regex =  r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Modify, Return: )([-0-9]+)"
        # Regex Strings - Group 0 is the path, Group 1 is the flags in decimal, Group 2 is the return
        open_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Open, Flags: )([-0-9]+)(?:, Return: )([-0-9]+)"
        # Regex Strings - Group 0 is the path, Group 1 is the return
        rename_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Rename, Flags: [-0-9]+)(?:, Return: )([-0-9]+)"
        createdir_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: CreateDir, Return: )([-0-9]+)"
        remove_regex = r"(?:Path: )([^,]*)(?:, Program: "+traceFile.procName+r", Tid: [\d]*, Mode: Remove, Return: )([-0-9]+)"
        # Get all the paths read and written to by the program
        read_paths = []
        write_paths = []
        access_paths = []
        execute_paths = []
        modify_paths = []
        for line in traceFile.vfsTraces:
            if(allowBool):
                if len(re.findall(read_regex, line)):
                    # Check if it returned succesfully
                    if(int(re.findall(read_regex, line)[0][1]) >= 0):
                        read_paths.append(re.findall(read_regex, line)[0][0])
                elif len(re.findall(write_regex, line)):
                    if(int(re.findall(write_regex, line)[0][1]) >= 0):
                        write_paths.append(re.findall(write_regex, line)[0][0])
                elif len(re.findall(access_regex, line)):
                    if(int(re.findall(access_regex, line)[0][1]) >= 0):
                        access_paths.append(re.findall(access_regex, line)[0][0])            
                elif len(re.findall(execute_regex, line)):
                    if(int(re.findall(execute_regex, line)[0][1]) >= 0):
                        execute_paths.append(re.findall(execute_regex, line)[0][0])   
                elif len(re.findall(modify_regex, line)):
                    if(int(re.findall(modify_regex, line)[0][1]) >= 0):
                        modify_paths.append(re.findall(modify_regex, line)[0][0])
                elif len(re.findall(open_regex, line)):
                    if(int(re.findall(open_regex, line)[0][2]) >= 0):
                        # Parse the flags
                        decimalFlags = int(re.findall(open_regex, line)[0][1], 10)
                        ocatalNoPad = np.base_repr(decimalFlags, 8) # Decimal to octal
                        if(decimalFlags == 0):
                            octalFlagsPadded = np.base_repr(decimalFlags, 8, 8) # Pad with 8 if we have 0
                        else:
                            octalFlagsPadded = np.base_repr(decimalFlags, 8, 8-len(ocatalNoPad)) # Pad
                        if(octalFlagsPadded[7] == '0'):
                            # Read only
                            read_paths.append(re.findall(open_regex, line)[0][0])
                        elif(octalFlagsPadded[7] == '3'):
                            # Access
                            access_paths.append(re.findall(open_regex, line)[0][0])
                        elif(octalFlagsPadded[7] == '1'):
                            # Write only
                            write_paths.append(re.findall(open_regex, line)[0][0])
                        elif(octalFlagsPadded[7] == '2'):
                            # Read and Write
                            read_paths.append(re.findall(open_regex, line)[0][0])
                            write_paths.append(re.findall(open_regex, line)[0][0])
                elif len(re.findall(createdir_regex, line)):
                    if(int(re.findall(createdir_regex, line)[0][1]) >= 0):
                        # Write + Execute
                        write_paths.append(re.findall(createdir_regex, line)[0][0])
                        execute_paths.append(re.findall(createdir_regex, line)[0][0])
                elif len(re.findall(rename_regex, line)):
                    if(int(re.findall(rename_regex, line)[0][1]) >= 0):
                        # Write + Execute
                        write_paths.append(re.findall(rename_regex, line)[0][0])
                        execute_paths.append(re.findall(rename_regex, line)[0][0])  
                elif len(re.findall(remove_regex, line)):
                    if(int(re.findall(remove_regex, line)[0][1]) >= 0):
                        # Write + Execute + Access
                        write_paths.append(re.findall(remove_regex, line)[0][0])
                        execute_paths.append(re.findall(remove_regex, line)[0][0])
                        access_paths.append(re.findall(remove_regex, line)[0][0])
            if(not allowBool):
                if len(re.findall(read_regex, line)):
                    # Check if it returned succesfully
                    if(int(re.findall(read_regex, line)[0][1]) < 0):
                        read_paths.append(re.findall(read_regex, line)[0][0])
                elif len(re.findall(write_regex, line)):
                    if(int(re.findall(write_regex, line)[0][1]) < 0):
                        write_paths.append(re.findall(write_regex, line)[0][0])
                elif len(re.findall(access_regex, line)):
                    if(int(re.findall(access_regex, line)[0][1]) < 0):
                        access_paths.append(re.findall(access_regex, line)[0][0])            
                elif len(re.findall(execute_regex, line)):
                    if(int(re.findall(execute_regex, line)[0][1]) < 0):
                        execute_paths.append(re.findall(execute_regex, line)[0][0])   
                elif len(re.findall(modify_regex, line)):
                    if(int(re.findall(modify_regex, line)[0][1]) < 0):
                        modify_paths.append(re.findall(modify_regex, line)[0][0])
                elif len(re.findall(open_regex, line)):
                    if(int(re.findall(open_regex, line)[0][2]) < 0):
                        # Parse the flags
                        decimalFlags = int(re.findall(open_regex, line)[0][1], 10)
                        ocatalNoPad = np.base_repr(decimalFlags, 8) # Decimal to octal
                        if(decimalFlags == 0):
                            octalFlagsPadded = np.base_repr(decimalFlags, 8, 8) # Pad with 8 if we have 0
                        else:
                            octalFlagsPadded = np.base_repr(decimalFlags, 8, 8-len(ocatalNoPad)) # Pad
                        if(octalFlagsPadded[7] == '0'):
                            # Read only
                            read_paths.append(re.findall(open_regex, line)[0][0])
                        elif(octalFlagsPadded[7] == '3'):
                            # Access
                            access_paths.append(re.findall(open_regex, line)[0][0])
                        elif(octalFlagsPadded[7] == '1'):
                            # Write only
                            write_paths.append(re.findall(open_regex, line)[0][0])
                        elif(octalFlagsPadded[7] == '2'):
                            # Read and Write
                            read_paths.append(re.findall(open_regex, line)[0][0])
                            write_paths.append(re.findall(open_regex, line)[0][0])
                elif len(re.findall(createdir_regex, line)):
                    if(int(re.findall(createdir_regex, line)[0][1]) < 0):
                        # Write + Execute
                        write_paths.append(re.findall(createdir_regex, line)[0][0])
                        execute_paths.append(re.findall(createdir_regex, line)[0][0])
                elif len(re.findall(rename_regex, line)):
                    if(int(re.findall(rename_regex, line)[0][1]) < 0):
                        # Write + Execute
                        write_paths.append(re.findall(rename_regex, line)[0][0])
                        execute_paths.append(re.findall(rename_regex, line)[0][0])  
                elif len(re.findall(remove_regex, line)):
                    if(int(re.findall(remove_regex, line)[0][1]) < 0):
                        # Write + Execute + Access
                        write_paths.append(re.findall(remove_regex, line)[0][0])
                        execute_paths.append(re.findall(remove_regex, line)[0][0])
                        access_paths.append(re.findall(remove_regex, line)[0][0])
        # Add allowed/denied file operations for given paths
        for path in read_paths:
            path_access_map[path] = ["r"]
        for path in write_paths:
            if path in path_access_map.keys():
                if not "w" in path_access_map[path]:
                    path_access_map[path].append("w")
            else:
                path_access_map[path] = ["w"]
        for path in access_paths:
            if path in path_access_map.keys():
                if not "a" in path_access_map[path]:
                    path_access_map[path].append("a")
            else:
                path_access_map[path] = ["a"]
        for path in execute_paths:
            if path in path_access_map.keys():
                if not "x" in path_access_map[path]:
                    path_access_map[path].append("x")
            else:
                path_access_map[path] = ["x"]
        for path in modify_paths:
            if path in path_access_map.keys():
                if not "m" in path_access_map[path]:
                    path_access_map[path].append("m")
            else:
                path_access_map[path] = ["m"]
        # We handle these in the generate_device_access() method
        if '/null' in path_access_map.keys():
            del(path_access_map['/null'])
        if '/0' in path_access_map.keys():
            del(path_access_map['/0'])  
        if '/1' in path_access_map.keys():
            del(path_access_map['/1'])
        if '/2' in path_access_map.keys():
            del(path_access_map['/2'])
        # Format the output
        root_fs_bool = False
        for file_path in path_access_map.keys():
            if not (file_path == '/'):
                file_access = ''.join(path_access_map[file_path])
                output_string += "  - file: {path: "+file_path+", access: "+file_access+"}\n"
            else:
                root_fs_bool = True
        if(root_fs_bool):
            output_string += "\n"+r"  - fs: {pathname: /, access: "+''.join(path_access_map['/'])+"}\n"
        return output_string + "\n"
    
    def generate_signals(self, sigTraces, procName, allowBool):
        signal_list = [
            "sigChk","sigHup","sigInt","sigQuit","sigIll",
            "sigTrap","sigAbrt","sigBus","sigFpe","sigKill",
            "sigUsr1","sigSegv","sigUsr2","sigPipe","sigAlrm",
            "sigTerm","sigStkFlt","sigChld","sigCont","sigStop",
            "sigTstp","sigTtin","sigTtou","sigUrg","sigXcpu",
            "sigXfsz","sigVtAlrm","sigProf","sigWinch",
            "sigIo","sigPwr","sigSys"
        ]
        # Group 0 contains who sent the signal
        # Group 1 is the program recieving the signal
        # Group 2 is the signal number
        # Group 3 is the result
        pattern_string = r"(?:From: )([^,]*)(?:, To: )([^,]*)(?:, SigNum: )([^,]*)(?:, Return: )([-0-9]+)"
        process_signals = [re.findall(pattern_string, x)[0] for x in sigTraces]
        valid_or_invalid_signal_rules = dict()
        output_string = ""
        for sig in process_signals:
            if(allowBool):
                if sig[0] == procName and int(sig[3]) >= 0:
                    if not sig[1] in valid_or_invalid_signal_rules.keys():
                        valid_or_invalid_signal_rules[sig[1]] = [sig[2]]
                    elif not sig[2] in valid_or_invalid_signal_rules[sig[1]]:
                        valid_or_invalid_signal_rules[sig[1]].append(sig[2])
            elif(not allowBool):
                if sig[0] == procName and int(sig[3]) < 0:
                    if not sig[1] in valid_or_invalid_signal_rules.keys():
                        valid_or_invalid_signal_rules[sig[1]] = [sig[2]]
                    elif not sig[2] in valid_or_invalid_signal_rules[sig[1]]:
                        valid_or_invalid_signal_rules[sig[1]].append(sig[2])
        for k in valid_or_invalid_signal_rules.keys():
            output_signal_str = ', '.join([str(signal_list[int(v)]) for v in valid_or_invalid_signal_rules[k]])
            output_string += "  - signal: {"+ f"to: {k}, signals: [{output_signal_str}]"+"}\n"
        return output_string
    
    def generate_capabilities(self, capTraces, procName, allowBool):
        capbilitiy_list = [
            'chown', 'dacOverride', 'dacReadSearch', 'fOwner', 'fSetId', 'kill', 'setGid', 'setUid', 
            'setPCap', 'linuxImmutable', 'netBindService', 'netBroadcast', 'netAdmin', 'netRaw', 'ipcLock', 
            'ipcOwner', 'sysModule', 'sysRawio', 'sysChroot', 'sysPtrace', 'sysPacct', 'sysAdmin', 'sysBoot', 
            'sysNice', 'sysResource', 'sysTime', 'sysTtyConfig', 'mknod', 'lease', 'auditWrite', 'auditControl', 
            'setFCap', 'macOverride', 'macAdmin', 'sysLog', 'wakeAlarm', 'blockSuspend', 'auditRead', 'perfMon', 
            'bpf', 'checkpointRestore', 'any'
        ]
        # Group 0 is the signal number
        # Group 1 is the result
        pattern_string = r"(?:Capability: Program: "+procName+r", CapInt: )([^,]*)(?:.*Return: )([-0-9]+)"
        process_capabilties = [re.findall(pattern_string, x)[0] for x in capTraces]
        valid_cap_rules = dict()
        output_string = ""
        for cap in process_capabilties:
            if(allowBool):
                if int(cap[1]) >= 0:
                    if not procName in valid_cap_rules.keys():
                        valid_cap_rules[procName] = [cap[0]]
                    elif not cap[0] in valid_cap_rules[procName]:
                        valid_cap_rules[procName].append(cap[0])
            elif(not allowBool):
                if int(cap[1]) < 0:
                    if not procName in valid_cap_rules.keys():
                        valid_cap_rules[procName] = [cap[0]]
                    elif not cap[0] in valid_cap_rules[procName]:
                        valid_cap_rules[procName].append(cap[0])
        for k in valid_cap_rules.keys():
            output_signal_str = ', '.join([str(capbilitiy_list[int(v)]) for v in valid_cap_rules[k]])
            output_string += f"  - capability: [{output_signal_str}]\n"
        return  output_string + "\n"

    def generate_ipc(self, pipeTraces, sockTraces, procName, allowBool):
        valid_ipc_rules = dict()
        output_string = ""
        # Group 0 is the path
        # Group 1 is the operation (read/write)
        # Group 2 is the return
        pipe_pattern = r"(?:Pipe: Path: )([^,]*)(?:, Program: "+procName+r", Mode: )([^,]*)(?:, Return: )([-0-9]+)"
        process_pipes = [re.findall(pipe_pattern, x)[0] for x in pipeTraces]
        for pipe in process_pipes:
            if(allowBool):
                if int(pipe[2]) >= 0:
                    if not procName in valid_ipc_rules.keys():
                        # dont need IPC with root
                        if(not pipe[0] == '/'):
                            valid_ipc_rules[procName] = [pipe[0]]
                    elif not pipe[0] in valid_ipc_rules[procName] and not pipe[0] == '/':
                        valid_ipc_rules[procName].append(pipe[0])
            if(not allowBool):
                if int(pipe[2]) < 0:
                    if not procName in valid_ipc_rules.keys():
                        # dont need IPC with root
                        if(not pipe[0] == '/'):
                            valid_ipc_rules[procName] = [pipe[0]]
                    elif not pipe[0] in valid_ipc_rules[procName] and not pipe[0] == '/':
                        valid_ipc_rules[procName].append(pipe[0])
        # Group 0 is the receiving prog, Group 1 is the sending prog, Group 2 is the result
        socket_recv_pattern = r'(?:Socket: Program: )([^,]*)(?:, Mode: Recieve, From: )([^,]*)(?:, Return: )([-0-9]+)'
        # Group 0 is the sending prog, Group 1 is the receiving prog, Group 2 is the result
        socket_send_pattern = r'(?:Socket: Program: )([^,]*)(?:, Mode: Send, To: )([^,]*)(?:, Return: )([-0-9]+)'
        receiving_sockets = []
        sending_sockets = []
        for sock in sockTraces:
            if(re.findall(socket_recv_pattern, sock)):
                receiving_sockets.append(re.findall(socket_recv_pattern, sock)[0])
            elif(re.findall(socket_send_pattern, sock)):
                sending_sockets.append(re.findall(socket_send_pattern, sock)[0])
        # Loop through recv sockets
        for recv in receiving_sockets:
            if(allowBool):
                if int(recv[2]) >= 0:
                    if not procName in valid_ipc_rules.keys():
                        if (not recv[0] == '/') and (not recv[1] == '/'):
                            # no IPC with root
                            if(recv[0] == procName):
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName] = [recv[1]]
                            elif(recv[1] == procName):
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName] = [recv[0]]
                    else:
                        if (not recv[0] == '/') and (not recv[1] == '/'):
                            # no IPC with root
                            if(recv[0] == procName) and not recv[1] in valid_ipc_rules[procName]:
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName].append(recv[1])
                            elif(recv[1] == procName) and not recv[0] in valid_ipc_rules[procName]:
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName].append(recv[0])
            elif(not allowBool):
                if int(recv[2]) < 0:
                    if not procName in valid_ipc_rules.keys():
                        if (not recv[0] == '/') and (not recv[1] == '/'):
                            # no IPC with root
                            if(recv[0] == procName):
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName] = [recv[1]]
                            elif(recv[1] == procName):
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName] = [recv[0]]
                    else:
                        if (not recv[0] == '/') and (not recv[1] == '/'):
                            # no IPC with root
                            if(recv[0] == procName) and not recv[1] in valid_ipc_rules[procName]:
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName].append(recv[1])
                            elif(recv[1] == procName) and not recv[0] in valid_ipc_rules[procName]:
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName].append(recv[0])
        # Loop through send sockets
        for send in sending_sockets:
            if(allowBool):
                if int(send[2]) >= 0:
                    if not procName in valid_ipc_rules.keys():
                        if (not send[0] == '/') and (not send[1] == '/'):
                            # no IPC with root
                            if(send[0] == procName):
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName] = [send[1]]
                            elif(send[1] == procName):
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName] = [send[0]]
                    else:
                        if (not send[0] == '/') and (not send[1] == '/'):
                            # no IPC with root
                            if(send[0] == procName) and not send[1] in valid_ipc_rules[procName]:
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName].append(send[1])
                            elif(send[1] == procName) and not send[0] in valid_ipc_rules[procName]:
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName].append(send[0])
            elif(not allowBool):
                if int(send[2]) < 0:
                    if not procName in valid_ipc_rules.keys():
                        if (not send[0] == '/') and (not send[1] == '/'):
                            # no IPC with root
                            if(send[0] == procName):
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName] = [send[1]]
                            elif(send[1] == procName):
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName] = [send[0]]
                    else:
                        if (not send[0] == '/') and (not send[1] == '/'):
                            # no IPC with root
                            if(send[0] == procName) and not send[1] in valid_ipc_rules[procName]:
                                # traced process is sending socket data to another process
                                valid_ipc_rules[procName].append(send[1])
                            elif(send[1] == procName) and not send[0] in valid_ipc_rules[procName]:
                                # traced process is receiving socket data from another process
                                valid_ipc_rules[procName].append(send[0])
        # Find all IPC
        for k in valid_ipc_rules.keys():
            for v in valid_ipc_rules[k]:
                output_signal_str = v.split('/')[-1]
                output_string += f"  - ipc: {output_signal_str}\n"
        return output_string + "\n"

class GenerateResults():

    def __init__(self, traceFilePath, outputPolicyPath, procName, procPath) -> None:
        self.traceFileObject = TraceFile(traceFilePath, procName, procPath)
        self.policyStr = TraceToPolicy(self.traceFileObject).outputPolicyStr
        # Dont include restrictions section if no restrictions found
        splitPolicyNoNewlines = [f"{l}\n" for l in self.policyStr.splitlines() if l]
        splitPolicyNoNewlines = splitPolicyNoNewlines[0:-1] if splitPolicyNoNewlines[-1] == 'deny:\n' else splitPolicyNoNewlines
        # Add newline before 'deny:', if it is included
        if 'deny:\n' in splitPolicyNoNewlines:
            splitPolicyNoNewlines.insert(splitPolicyNoNewlines.index('deny:\n'), '\n') 
        # Add newline before 'allow:'
        splitPolicyNoNewlines.insert(splitPolicyNoNewlines.index('allow:\n'), '\n')
        self.policyStr = ''.join(splitPolicyNoNewlines)
        with open(outputPolicyPath, "w") as fout:
            fout.write(self.policyStr)

if __name__ == "__main__":
    # Relvant arrays - For report
    # with open(r"Output\reportCapSnip.txt", "w") as fx:
    #     fx.writelines([x for x in traceF.vfsTraces if 'Tid: 12449' in x])
    #     fx.writelines([x for x in traceF.pipeTraces if 'Return: 8' in x or 'Return: -' in x])
    #     fx.writelines(traceF.sigTraces)
    #     fx.writelines(traceF.capTraces)

    # Functions to ensure file types are correct
    def text_file(value):
        if not value.endswith('.txt'):
            raise argparse.ArgumentTypeError('capture-file must be of type *.txt')
        return value
    def yaml_file(value):
        if not value.endswith('.yml'):
            raise argparse.ArgumentTypeError('output-file must be of type *.yml')
        return value
    
    '''
    Example usage: python translateToPolicy.py -c Captures\moverenameCap.txt -o Output\mvRenameRemove2.yml -p mv -f /usr/bin/mv
    '''
    parser = argparse.ArgumentParser(description='Generates a BPFContain security policy')
    parser.add_argument('-c', '--capture-file', required=True, help='path to the bpftrace capture text file', type=text_file)
    parser.add_argument('-o', '--output-file', required=True, help='path to save the generated YAML security policy', type=yaml_file)
    parser.add_argument('-p', '--program', required=True, help='name of the program to generate security policy for')
    parser.add_argument('-f', '--full-path', required=True, help='full path of the program to generate security policy for')
    args = parser.parse_args()
    GenerateResults(args.capture_file, args.output_file, args.program, args.full_path)
