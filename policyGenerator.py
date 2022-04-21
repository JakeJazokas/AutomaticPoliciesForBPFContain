import subprocess
import time
import argparse
from translateToPolicy import GenerateResults

# Functions to ensure file types are correct
def text_file(value):
    if not value.endswith('.txt'):
        raise argparse.ArgumentTypeError('capture-file must be of type *.txt')
    return value
def yaml_file(value):
    if not value.endswith('.yml'):
        raise argparse.ArgumentTypeError('output-file must be of type *.yml')
    return value

parser = argparse.ArgumentParser(description='Traces a given program, then generates a BPFContain security policy')
parser.add_argument('-c', '--capture-file', required=True, help='path to the bpftrace capture text file', type=text_file)
parser.add_argument('-o', '--output-file', required=True, help='path to save the generated YAML security policy', type=yaml_file)
parser.add_argument('-p', '--program', required=True, help='name of the program to generate security policy for')
parser.add_argument('-f', '--full-path', required=True, help='full path of the program to generate security policy for')
parser.add_argument('-t', '--time', required=True, help='trace the given program for t seconds')
args = parser.parse_args()

bpftrace_process = subprocess.Popen(f'sudo bpftrace --unsafe traceSystemOperations.bt {args.program}', stdout=args.capture_file)

# Kill the tracing process after t seconds
time.sleep(args.time)
bpftrace_process.terminate() 
bpftrace_process.wait()

# Translate the traced operations to a BPFContain security policy
GenerateResults(args.capture_file, args.output_file, args.program, args.full_path)