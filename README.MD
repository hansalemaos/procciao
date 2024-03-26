# A library for killing processes/subprocesses the most gracefully way possible

## pip install procciao

### Tested against Windows 10 / Python 3.11 / Anaconda


The attempts to kill processes go from the most gracefully to the most forcefully

1) https://github.com/ElyDotDev/windows-kill SIGINT/SIGBREAK (DLL/EXE)
2) powershell SIGINT/SIGBREAK/CLOSE
3) taskkill



```PY
from procciao import kill_proc
from procciao.procdict import get_procs
import re

d1 = get_procs(
    use_wmic=True,
    columns_to_parse=(
        # "CommandLine", -> if CommandLine is in columns_to_parse, all columns are parsed due to some strange output (header in more than one line)
        "CreationClassName",
        "CreationDate",
        "CSCreationClassName",
        "Description",
        "ExecutablePath",
        "ExecutionState",
        "Handle",
        "HandleCount",
        "Name",
        "ProcessId",
        "ReadOperationCount",
        "ReadTransferCount",
        "ThreadCount",
        "WriteOperationCount",
        "WriteTransferCount",
    ),
    searchdict={
        "ExecutablePath": re.compile(
            r".*chrome.exe.*"
        ),  # has to be a compiled regex, if regex is desired
        "HandleCount": lambda x: int(x) > 1,  # use functions for numbers and convert the data dtypes
        "Description": "chrome.exe",  # compares with ==
    },
)
d2 = get_procs(
    use_wmic=False,
    columns_to_parse=(
        "HandleCount",
        "Path",
        "Company",
        "CPU",
        "ProductVersion",
        "Description",
        "Product",
        "HasExited",
        "ExitTime",
        "Handle",
        "MainWindowHandle",
        "MainWindowTitle",
        "MainModule",
        "ProcessName",
        "Responding",
        "StartTime",
        "SynchronizingObject",
        "UserProcessorTime",
    ),
    searchdict={
        "Path": re.compile(
            r".*opera.exe.*", flags=re.I
        ),  # has to be a compiled regex, if regex is desired
        "Handle": lambda x: int(x) > 10,  # for numbers
    },
)

for k, v in d1.items():
    print(k, v)
    print(v["get_children_tree"]()) # print children tree
for k, v in d1.items():
    print(k, v)
    v["kill"]()

for k, v in d2.items():
    print(k, v)
    print(v["get_children_flat"]()) # print children (flat)
for k, v in d2.items():
    print(k, v)
    v["kill"](
        protect_myself=True,  # to overwrite the config
        winkill_sigint=False,
        winkill_sigbreak=False,
        winkill_sigint_dll=False,
        winkill_sigbreak_dll=False,
        powershell_sigint=False,
        powershell_sigbreak=False,
        powershell_close=False,
        multi_children_kill=False,
        multi_children_always_ignore_pids=(0, 4),
        print_output=True,
        taskkill_as_last_option=True,
    )

# get all data from all procs without any kill / get children functions
d3 = get_procs(use_wmic=True, columns_to_parse=(), searchdict=None, add_functions=False)
d4 = get_procs(
    use_wmic=False, columns_to_parse=(), searchdict=None, add_functions=False
)

# killing subprocesses
import subprocess
import time

p = subprocess.Popen("ping -n 30000 google.com", shell=False)
time.sleep(5)
kill_proc(p.pid)

p = subprocess.Popen(
    "ping -n 30000 google.com",
    shell=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
time.sleep(5)
kill_proc(p.pid)
print(p.stdout.read())
print(p.stderr.read())

# works even with shell=True
p = subprocess.Popen(
    "dir /b/s",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=True,
)
time.sleep(5)

# goes from the most gracefully to the most forcefully
# 1) https://github.com/ElyDotDev/windows-kill
# 2) powershell
# 3) taskkill
# Exact order:
kill_proc(
    pid=p.pid,
    kill_timeout=5,
    protect_myself=True,  # important, protect_myselfis False, you might kill the whole python process you are in.
    winkill_sigint_dll=True,  # dll first
    winkill_sigbreak_dll=True,
    winkill_sigint=True,  # exe from outside
    winkill_sigbreak=True,
    powershell_sigint=True,
    powershell_sigbreak=True,
    powershell_close=True,
    multi_children_kill=True,  # try to kill each child one by one
    multi_children_always_ignore_pids=(0, 4),  # ignore system processes
    print_output=True,
    taskkill_as_last_option=True,  # this always works, but it is not gracefully anymore
)

print(p.stdout.read())
print(p.stderr.read())
```