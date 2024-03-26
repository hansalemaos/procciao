from wmicprocsdict import get_dict_from_command
import re
from . import kill_proc
from pidconnectioninfos import (
    get_processes_and_children,
)
from typing import Literal
import os
import tempfile
from touchtouch import touch

keys_powershell = [
    "PriorityClass",
    "Id",
    "FileVersion",
    "HandleCount",
    "WorkingSet",
    "PagedMemorySize",
    "PrivateMemorySize",
    "VirtualMemorySize",
    "TotalProcessorTime",
    "SI",
    "Handles",
    "VM",
    "WS",
    "PM",
    "NPM",
    "Path",
    "Company",
    "CPU",
    "ProductVersion",
    "Description",
    "Product",
    "__NounName",
    "BasePriority",
    "ExitCode",
    "HasExited",
    "ExitTime",
    "Handle",
    "SafeHandle",
    "MachineName",
    "MainWindowHandle",
    "MainWindowTitle",
    "MainModule",
    "MaxWorkingSet",
    "MinWorkingSet",
    "Modules",
    "NonpagedSystemMemorySize",
    "NonpagedSystemMemorySize64",
    "PagedMemorySize64",
    "PagedSystemMemorySize",
    "PagedSystemMemorySize64",
    "PeakPagedMemorySize",
    "PeakPagedMemorySize64",
    "PeakWorkingSet",
    "PeakWorkingSet64",
    "PeakVirtualMemorySize",
    "PeakVirtualMemorySize64",
    "PriorityBoostEnabled",
    "PrivateMemorySize64",
    "PrivilegedProcessorTime",
    "ProcessName",
    "ProcessorAffinity",
    "Responding",
    "SessionId",
    "StartInfo",
    "StartTime",
    "SynchronizingObject",
    "Threads",
    "UserProcessorTime",
    "VirtualMemorySize64",
    "EnableRaisingEvents",
    "StandardInput",
    "StandardOutput",
    "StandardError",
    "WorkingSet64",
    "Site",
    "Container",
]

keys_wmic = [
    "CommandLine",
    "CreationClassName",
    "CreationDate",
    "CSCreationClassName",
    "CSName",
    "Description",
    "ExecutablePath",
    "ExecutionState",
    "Handle",
    "HandleCount",
    "InstallDate",
    "KernelModeTime",
    "MaximumWorkingSetSize",
    "MinimumWorkingSetSize",
    "Name",
    "OSCreationClassName",
    "OSName",
    "OtherOperationCount",
    "OtherTransferCount",
    "PageFaults",
    "PageFileUsage",
    "ParentProcessId",
    "PeakPageFileUsage",
    "PeakVirtualSize",
    "PeakWorkingSetSize",
    "Priority",
    "PrivatePageCount",
    "ProcessId",
    "QuotaNonPagedPoolUsage",
    "QuotaPagedPoolUsage",
    "QuotaPeakNonPagedPoolUsage",
    "QuotaPeakPagedPoolUsage",
    "ReadOperationCount",
    "ReadTransferCount",
    "SessionId",
    "Status",
    "TerminationDate",
    "ThreadCount",
    "UserModeTime",
    "VirtualSize",
    "WindowsVersion",
    "WorkingSetSize",
    "WriteOperationCount",
    "WriteTransferCount",
]

kill_timeout = 5
protect_myself = True
winkill_sigint = True
winkill_sigbreak = True
winkill_sigint_dll = True
winkill_sigbreak_dll = True
powershell_sigint = True
powershell_sigbreak = True
powershell_close = True
multi_children_kill = True
multi_children_always_ignore_pids = (0, 4)
print_output = True
taskkill_as_last_option = True


class GetChildren:
    def __init__(self, pid, flat: Literal["tree", "flat", "both"] = "flat"):
        self.pid = pid
        self.flat = flat

    def __call__(self):
        alloperaprocs = get_processes_and_children(pids_to_search=[self.pid])
        if self.flat == "flat":
            return alloperaprocs[1]
        if self.flat == "tree":
            return alloperaprocs[0]
        if self.flat == "both":
            return alloperaprocs

    def __repr__(self):
        if self.flat == "flat":
            return f"flat {self.pid}"
        if self.flat == "tree":
            return f"tree {self.pid}"
        if self.flat == "both":
            return f"tree/flat {self.pid}"

    def __str__(self):
        return self.__repr__()


class ProcKiller:
    def __init__(self, pid, **kwargs):
        self.pid = pid
        self.kill_timeout = kwargs.get("kill_timeout", 5)
        self.protect_myself = kwargs.get("protect_myself", True)
        self.winkill_sigint = kwargs.get("winkill_sigint", False)
        self.winkill_sigbreak = kwargs.get("winkill_sigbreak", False)
        self.winkill_sigint_dll = kwargs.get("winkill_sigint_dll", False)
        self.winkill_sigbreak_dll = kwargs.get("winkill_sigbreak_dll", False)
        self.powershell_sigint = kwargs.get("powershell_sigint", False)
        self.powershell_sigbreak = kwargs.get("powershell_sigbreak", False)
        self.powershell_close = kwargs.get("powershell_close", False)
        self.multi_children_kill = kwargs.get("multi_children_kill", False)
        self.multi_children_always_ignore_pids = kwargs.get(
            "multi_children_always_ignore_pids", (0, 4)
        )
        self.print_output = kwargs.get("print_output", False)
        self.taskkill_as_last_option = kwargs.get("taskkill_as_last_option", False)

    def __call__(self, **kwargs):
        self.kill_timeout = kwargs.get("kill_timeout", self.kill_timeout)
        self.protect_myself = kwargs.get("protect_myself", self.protect_myself)
        self.winkill_sigint = kwargs.get("winkill_sigint", self.winkill_sigint)
        self.winkill_sigbreak = kwargs.get("winkill_sigbreak", self.winkill_sigbreak)
        self.winkill_sigint_dll = kwargs.get(
            "winkill_sigint_dll", self.winkill_sigint_dll
        )
        self.winkill_sigbreak_dll = kwargs.get(
            "winkill_sigbreak_dll", self.winkill_sigbreak_dll
        )
        self.powershell_sigint = kwargs.get("powershell_sigint", self.powershell_sigint)
        self.powershell_sigbreak = kwargs.get(
            "powershell_sigbreak", self.powershell_sigbreak
        )
        self.powershell_close = kwargs.get("powershell_close", self.powershell_close)
        self.multi_children_kill = kwargs.get(
            "multi_children_kill", self.multi_children_kill
        )
        self.multi_children_always_ignore_pids = kwargs.get(
            "multi_children_always_ignore_pids", self.multi_children_always_ignore_pids
        )
        self.print_output = kwargs.get("print_output", self.print_output)
        self.taskkill_as_last_option = kwargs.get(
            "taskkill_as_last_option", self.taskkill_as_last_option
        )
        return kill_proc(
            pid=self.pid,
            kill_timeout=self.kill_timeout,
            protect_myself=self.protect_myself,
            winkill_sigint=self.winkill_sigint,
            winkill_sigbreak=self.winkill_sigbreak,
            winkill_sigint_dll=self.winkill_sigint_dll,
            winkill_sigbreak_dll=self.winkill_sigbreak_dll,
            powershell_sigint=self.powershell_sigint,
            powershell_sigbreak=self.powershell_sigbreak,
            powershell_close=self.powershell_close,
            multi_children_kill=self.multi_children_kill,
            multi_children_always_ignore_pids=self.multi_children_always_ignore_pids,
            print_output=self.print_output,
            taskkill_as_last_option=self.taskkill_as_last_option,
        )

    def __repr__(self):
        cfg = f"""
pid={self.pid}
kill_timeout={self.kill_timeout}
protect_myself={self.protect_myself}
winkill_sigint={self.winkill_sigint}
winkill_sigbreak={self.winkill_sigbreak}
winkill_sigint_dll={self.winkill_sigint_dll}
winkill_sigbreak_dll={self.winkill_sigbreak_dll}
powershell_sigint={self.powershell_sigint}
powershell_sigbreak={self.powershell_sigbreak}
powershell_close={self.powershell_close}
multi_children_kill={self.multi_children_kill}
multi_children_always_ignore_pids={self.multi_children_always_ignore_pids}
print_output={self.print_output}
taskkill_as_last_option={self.taskkill_as_last_option}"""

        return " | ".join(cfg.strip().splitlines())

    def __str__(self):
        return self.__repr__()



def parse_wmic(keys_normal, columns_to_parse=()):
    if "CommandLine" in columns_to_parse or not columns_to_parse:
        wmiccmd = "wmic process"
    else:
        wmiccmd = "wmic process get " + ",".join(columns_to_parse)
    return get_dict_from_command(
        cmd=wmiccmd,
        convert_dtypes_with_ast=False,
        format_powershell=False,
        cols=9999999,
        lines=1,
    )


def get_tmpfile(suffix=".ps1"):
    tfp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    filename = tfp.name
    filename = os.path.normpath(filename)
    tfp.close()
    touch(filename)
    return filename


def parse_powershell(keys_normal, columns_to_parse=()):
    if not columns_to_parse:
        columns_to_parse = keys_powershell
    columns_to_parse = list(columns_to_parse)
    if "Id" in columns_to_parse:
        columns_to_parse.pop(columns_to_parse.index("Id"))
    columns_to_parse.insert(1, "Id")  # insert("Id")
    columnsstr = ",".join(columns_to_parse)

    ps1file = get_tmpfile(suffix=".ps1")
    pscmd = r"""$processes = Get-Process | Select-Object columnsstr

$maxWidth = ($processes | ForEach-Object { $_.PSObject.Properties | ForEach-Object { $_.Name.Length } } | Measure-Object -Maximum).Maximum + 2

$processes | ForEach-Object {
    $_.PSObject.Properties | ForEach-Object {
        if ($_.Value -ne $null) {
            $_.Value = $_.Value.ToString().PadRight($maxWidth)
        } else {
            $_.Value = "".PadRight($maxWidth)
        }
    }
}

$processes  | Format-Table *
""".replace("columnsstr", columnsstr)

    # print(pscmd)
    with open(ps1file, "w", encoding="utf-8") as f:
        f.write(pscmd)

    pscmdfinal = f'powershell.exe -ExecutionPolicy RemoteSigned -File "{ps1file}"'
    d = get_dict_from_command(
        cmd=pscmdfinal,
        convert_dtypes_with_ast=False,
        format_powershell=False,
        cols=9999999,
        lines=1,
    )
    dn = {}

    for k, varsx in d.items():
        try:
            intid = int(varsx["Id"])
            dn[intid] = varsx.copy()
            dn[intid]["ProcessId"] = str(intid)
        except Exception:
            pass
    return dn


def parse_whole_dict(use_wmic=True, columns_to_parse=()):
    columns_to_parse = list(columns_to_parse)
    if use_wmic:
        d = parse_wmic(keys_normal=keys_wmic, columns_to_parse=columns_to_parse)

    else:
        d = parse_powershell(
            keys_normal=keys_powershell, columns_to_parse=columns_to_parse
        )
    return d


def get_procs(use_wmic=True, columns_to_parse=(), searchdict=None,add_functions=True):
    d = parse_whole_dict(use_wmic=use_wmic, columns_to_parse=columns_to_parse)


    if searchdict:
        resultsdict = {}
        for k2, v2 in d.items():
            for k, v in searchdict.items():
                try:
                    if isinstance(v, re.Pattern):
                        if v.search(v2[k]):
                            resultsdict.setdefault(k2, 0)
                            resultsdict[k2] += 1
                        continue
                except Exception:
                    pass
                try:
                    if callable(v):
                        if v.search(v2[k]):
                            resultsdict.setdefault(k2, 0)
                            resultsdict[k2] += 1
                        continue

                except Exception:
                    pass
                try:
                    dtype = None
                    if str(type(v)) != str(type(v2[k])):
                        dtype = type(v)
                    if dtype is not None:
                        v2k = dtype(v2[k])
                    else:
                        v2k = v2[k]
                    if v == v2k:
                        resultsdict.setdefault(k2, 0)
                        resultsdict[k2] += 1
                        continue

                except Exception:
                    pass

        dresults = {
            k: v
            for k, v in sorted(
                resultsdict.items(), key=lambda item: item[1], reverse=True
            )
            if v + 1 >= len(searchdict)
        }
        finaldict = {}
        for k, v in dresults.items():
            finaldict[k] = d[k]
    else:
        finaldict = d.copy()
    if not add_functions:
        return finaldict
    finaldict_with_kill = {}
    for k, v in finaldict.items():
        procpid = int(v["ProcessId"])
        finaldict_with_kill[procpid] = v
        finaldict_with_kill[procpid]["kill"] = ProcKiller(
            pid=procpid,
            kill_timeout=kill_timeout,
            protect_myself=protect_myself,
            winkill_sigint=winkill_sigint,
            winkill_sigbreak=winkill_sigbreak,
            winkill_sigint_dll=winkill_sigint_dll,
            winkill_sigbreak_dll=winkill_sigbreak_dll,
            powershell_sigint=powershell_sigint,
            powershell_sigbreak=powershell_sigbreak,
            powershell_close=powershell_close,
            multi_children_kill=multi_children_kill,
            multi_children_always_ignore_pids=multi_children_always_ignore_pids,
            print_output=print_output,
            taskkill_as_last_option=taskkill_as_last_option,
        )
        finaldict_with_kill[procpid]["get_children_flat"] = GetChildren(
            pid=procpid, flat="flat"
        )
        finaldict_with_kill[procpid]["get_children_tree"] = GetChildren(
            pid=procpid, flat="tree"
        )
        finaldict_with_kill[procpid]["get_children_flat_and_tree"] = GetChildren(
            pid=procpid, flat="both"
        )
    return finaldict_with_kill


