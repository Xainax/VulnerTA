import os
import subprocess

# ---------------------------  
# 1. TAINTED SOURCE → SINK (should detect)
# ---------------------------

def tainted_exec():
    user_input = input("Enter command: ")  # SOURCE (tainted)
    eval(user_input)  # SINK (DANGEROUS)


def tainted_os_system():
    cmd = input("Command: ")
    os.system(cmd)  # TAINTED FLOW → SHELL EXECUTION


def tainted_subprocess():
    cmd = input("cmd: ")
    subprocess.call(cmd, shell=True)  # TAINTED + shell=True


# ---------------------------
# 2. SAFE USAGE (should NOT detect)
# ---------------------------

def safe_eval():
    expr = "2 + 2"
    result = eval(expr)  # SAFE CONSTANT INPUT
    return result


def safe_os_system():
    os.system("ls -la")  # CONSTANT STRING, SAFE


def safe_subprocess():
    subprocess.call(["ls", "-la"], shell=False)  # SAFE ARRAY FORM


# ---------------------------
# 3. PARTIAL TAINT (harder cases)
# ---------------------------

def partial_taint_concat():
    user_input = input("name: ")
    cmd = "echo " + user_input  # TAINT PROPAGATION
    os.system(cmd)  # SHOULD BE DETECTED


def sanitized_flow():
    user_input = input("name: ")
    safe_input = user_input.replace(";", "")  # simple sanitization
    os.system("echo " + safe_input)  # MAYBE SAFE depending on your rules


# ---------------------------
# 4. FILE WRITE VULNERABILITIES
# ---------------------------

def unsafe_file_write():
    filename = input("file: ")
    with open(filename, "w") as f:  # TAINTED FILE PATH
        f.write("hello")


def safe_file_write():
    filename = "output.txt"
    with open(filename, "w") as f:
        f.write("safe")


# ---------------------------
# 5. EDGE CASES (good for CFG testing)
# ---------------------------

def branch_taint(flag):
    user_input = input("data: ")

    if flag:
        cmd = user_input
    else:
        cmd = "echo safe"

    os.system(cmd)  # CFG-sensitive taint flow


def loop_taint():
    user_input = input("cmd: ")
    for i in range(3):
        os.system(user_input)  # repeated sink exposure