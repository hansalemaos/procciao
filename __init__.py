import subprocess
import os
import ctypes
import time

from pidconnectioninfos import (
    get_processes_and_children,

)
import tempfile
from touchtouch import touch

from flatten_any_dict_iterable_or_whatsoever import fla_tu
from flatten_everything import flatten_everything
from exceptdrucker import errwrite
from ctypes import wintypes
from . import savebase64

pathshort64, shortkiller = savebase64.pathshort64, savebase64.shortkiller

folder = os.sep.join(__file__.split(os.sep)[:-1])


startupinfo = subprocess.STARTUPINFO()
startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
startupinfo.wShowWindow = subprocess.SW_HIDE
creationflags = subprocess.CREATE_NO_WINDOW
invisibledict = {
    "startupinfo": startupinfo,
    "creationflags": creationflags,
    "start_new_session": True,
}

windll = ctypes.LibraryLoader(ctypes.WinDLL)
user32 = windll.user32
kernel32 = windll.kernel32
GetExitCodeProcess = windll.kernel32.GetExitCodeProcess
CloseHandle = windll.kernel32.CloseHandle
GetExitCodeProcess.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_ulong),
]
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
GetExitCodeProcess.restype = ctypes.c_int
CloseHandle.restype = ctypes.c_int

GetWindowRect = user32.GetWindowRect
GetClientRect = user32.GetClientRect
_GetShortPathNameW = kernel32.GetShortPathNameW
_GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_GetShortPathNameW.restype = wintypes.DWORD

def get_short_path_name(long_name):
    try:
        if os.path.exists(long_name):
            output_buf_size = 4096
            output_buf = ctypes.create_unicode_buffer(output_buf_size)
            _ = _GetShortPathNameW(long_name, output_buf, output_buf_size)
            return output_buf.value
    except Exception:
        pass
    return long_name


windows_kill_library64 = ctypes.CDLL(pathshort64)
sendSignal_address64 = getattr(
    windows_kill_library64, "?sendSignal@WindowsKillLibrary@@YAXKK@Z"
)
warmUp_address64 = getattr(
    windows_kill_library64,
    "?warmUp@WindowsKillLibrary@@YAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z",
)
sendSignal64 = ctypes.CFUNCTYPE(None, ctypes.c_ulong, ctypes.c_ulong)(
    sendSignal_address64
)
warmUp64 = ctypes.CFUNCTYPE(None, ctypes.c_char_p)(warmUp_address64)


def escapecmdlist(arguments):
    updatedarguments = []
    for a in arguments:
        a = str(a)
        if os.path.exists(a):
            a = "'" + get_short_path_name(a) + "'"
        else:
            if '"' not in a and "'" not in a and "`" not in a:
                a = "'" + str(a) + "'"
            elif '"' in a and ("'" not in a and "`" not in a):
                a = "'" + str(a) + "'"
            elif "'" in a and ('"' not in a and "`" not in a):
                a = '"' + str(a) + '"'
            elif "'" in a or '"' in a and "`" not in a:
                a = "`" + str(a) + "`"
        updatedarguments.append(a)
    updatedargumentsstr = ",".join(updatedarguments)
    return updatedargumentsstr


def check_if_dead(pid, print_output=True):
    try:
        p = subprocess.run(
            f"""wmic process where (ProcessId={pid}) get Caption,ProcessId,CommandLine""",
            shell=False,
            capture_output=True,
            **invisibledict,
        )

        if print_output:
            print(
                p.stdout.splitlines(),
                p.stderr.splitlines(),
                p.returncode,
            )
        if not p.stdout.strip() and not p.stderr.strip():
            return None, None
        return p.stdout, p.stderr
    except Exception:
        errwrite()
        return None, None


def get_tmpfile(suffix=".ps1"):
    tfp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    filename = tfp.name
    filename = os.path.normpath(filename)
    tfp.close()
    touch(filename)
    return filename


def kill_app(pid, cmd, protect_myself=True, kill_timeout=5):
    try:
        argsstring = " -ArgumentList " + escapecmdlist([str(cmd), str(pid)]) + " "
        WhatIf = ""
        Verb = " -Verb RunAs "
        UseNewEnvironment = ""
        Wait = ""
        stdinadd = ""
        WindowStyle = "Hidden"
        wholecommandline = f"""powershell.exe -ExecutionPolicy Unrestricted Start-Process -FilePath "{shortkiller}" {argsstring}{WhatIf}{Verb}{UseNewEnvironment}{Wait}{stdinadd} -WindowStyle {WindowStyle}"""
        p = subprocess.Popen(
            wholecommandline,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **invisibledict,
        )
        try:
            p.communicate(timeout=kill_timeout)
        except Exception:
            pass 
        return p
    except KeyboardInterrupt:
        if not protect_myself:
            raise KeyboardInterrupt
        else:
            try:
                time.sleep(1)
            except:
                pass


def send_ctrl_c_with_powershell(pid, protect_myself=True, kill_timeout=5, ctrl_cmd=0):

    try:
        cmd = r"""Set-ExecutionPolicy -ExecutionPolicy Unrestricted
        Get-ExecutionPolicy -List
        $ProcessID = PPPPP
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Add-Type -Names 'w' -Name 'k' -M '[DllImport(""kernel32.dll"")]public static extern bool FreeConsole();[DllImport(""kernel32.dll"")]public static extern bool AttachConsole(uint p);[DllImport(""kernel32.dll"")]public static extern bool SetConsoleCtrlHandler(uint h, bool a);[DllImport(""kernel32.dll"")]public static extern bool GenerateConsoleCtrlEvent(uint e, uint p);public static void SendCtrlC(uint p){FreeConsole();AttachConsole(p);GenerateConsoleCtrlEvent(KONSOLE_EVENT, 0);}';[w.k]::SendCtrlC($ProcessID)"))
        start-process powershell.exe -EncodedCommand $encodedCommand -WindowStyle Hidden""".replace(
            "KONSOLE_EVENT", str(int(ctrl_cmd))
        ).replace("PPPPP", str(int(pid)))
        p = subprocess.Popen(
            [
                "powershell.exe",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **invisibledict,
        )
        try:
            outs, errs = p.communicate(input=cmd.encode() + b"\n", timeout=kill_timeout)
        except Exception:
            pass
        return p

    except KeyboardInterrupt:
        if not protect_myself:
            raise KeyboardInterrupt
        else:
            try:
                time.sleep(1)
            except:
                pass


def protectfunction(fu, *args, **kwargs):
    protect_myself = kwargs.get("protect_myself", True)

    try:
        return fu(*args, **kwargs)
    except KeyboardInterrupt:
        if not protect_myself:
            raise KeyboardInterrupt
        try:
            time.sleep(1)
        except:
            try:
                time.sleep(1)
            except:
                pass
    except Exception:
        errwrite()



def protectfunctionmulti(fu, *args, **kwargs):
    protect_myself = kwargs.get("protect_myself", True)

    try:
        return fu(*args, **kwargs)
    except KeyboardInterrupt:
        if not protect_myself:
            raise KeyboardInterrupt
        try:
            time.sleep(1)
        except:
            try:
                time.sleep(1)
            except:
                pass
    except Exception:
        errwrite()


def get_children_pids(mypid, always_ignore=(0, 4)):
    procs_and_kids = get_processes_and_children(
        pids_to_search=[mypid], always_ignore=always_ignore
    )
    allprocs = [
        h
        for h in reversed(list(flatten_everything(fla_tu(procs_and_kids[0]))))
        if isinstance(h, int) and h > 0
    ]
    tempset = set()
    allkills2execute = []
    for i in allprocs:
        if i not in tempset:
            tempset.add(i)
            allkills2execute.append(i)
    return allkills2execute


def _taskkill(cmd: str) -> tuple:
    p = subprocess.run(
        cmd,
        capture_output=True,
        **invisibledict,
    )
    return (p.returncode, p.stdout.strip(), p.stderr.strip())


def kill_with_taskkill(pid, protect_myself=True, force=True):
    if not force:
        pidresults = f"taskkill /T /PID {pid}"
    else:
        pidresults = f"taskkill /F /T /PID {pid}"
    return _taskkill(pidresults)


def kill_app_dll(pid, cmd, protect_myself=True, kill_timeout=5):
    try:
        sendSignal64(int(pid), int(cmd))

    except KeyboardInterrupt:
        if not protect_myself:
            raise KeyboardInterrupt
        else:
            try:
                time.sleep(1)
            except:
                pass


# Example search for Notepad
def kill_proc(
    pid,
    kill_timeout=5,
    protect_myself=True,
    winkill_sigint_dll=True,
    winkill_sigbreak_dll=True,    
    winkill_sigint=True,
    winkill_sigbreak=True,

    powershell_sigint=True,
    powershell_sigbreak=True,
    powershell_close=True,
    multi_children_kill=True,
    multi_children_always_ignore_pids=(0, 4),
    print_output=True,
    taskkill_as_last_option=True,
):
    def checkstderrstdoutput(mypid):
        try:
            nonlocal are_we_done
            nonlocal counter
            are_we_done = False
            stdout_a, stderr_a = check_if_dead(mypid, print_output=print_output)
            if stdout_a is None:
                are_we_done=True
                resultsdict_stdout[counter] = 'None'
                resultsdict_stderr[counter] = 'None'                
            stdout_a = stdout_a.strip()
            stderr_a = stderr_a.strip()
            if not stdout_a and b"(s)" in stderr_a:
                are_we_done = True
            elif resultsdict_stdout[counter] != stdout_a:
                are_we_done = True
            counter = counter + 1

            resultsdict_stdout[counter] = stdout_a
            resultsdict_stderr[counter] = stderr_a
        except Exception:
            errwrite()
        except KeyboardInterrupt:
            if not protect_myself:
                raise KeyboardInterrupt
            try:
                time.sleep(1)
            except:
                try:
                    time.sleep(1)
                except:
                    pass

    counter = 0
    are_we_done = False
    resultsdict_stdout = {}
    resultsdict_stderr = {}
    mypid = int(pid)
    stdout_a, stderr_a = check_if_dead(mypid, print_output=print_output)
    stdout_a = stdout_a.strip()
    stderr_a = stderr_a.strip()

    resultsdict_stdout[counter] = stdout_a
    resultsdict_stderr[counter] = stderr_a
    if not stdout_a and b"(s)" in stderr_a:
        are_we_done = True
    if not are_we_done and winkill_sigint_dll:
        protectfunction(
            fu=kill_app_dll,
            pid=mypid,
            cmd=0,
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and winkill_sigbreak_dll:
        protectfunction(
            fu=kill_app_dll,
            pid=mypid,
            cmd=1,
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and winkill_sigint:
        protectfunction(
            fu=kill_app,
            pid=mypid,
            cmd="-SIGINT",
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and winkill_sigbreak:
        protectfunction(
            fu=kill_app,
            pid=mypid,
            cmd="-SIGBREAK",
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and powershell_sigint:
        protectfunction(
            fu=send_ctrl_c_with_powershell,
            pid=mypid,
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
            ctrl_cmd=0,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and powershell_sigbreak:
        protectfunction(
            fu=send_ctrl_c_with_powershell,
            pid=mypid,
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
            ctrl_cmd=1,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and powershell_close:
        protectfunction(
            fu=send_ctrl_c_with_powershell,
            pid=mypid,
            protect_myself=protect_myself,
            kill_timeout=kill_timeout,
            ctrl_cmd=2,
        )
        checkstderrstdoutput(mypid)
    if not are_we_done and multi_children_kill:
        allkills2execute = get_children_pids(mypid, always_ignore=multi_children_always_ignore_pids)
        for subprocesspid in allkills2execute:
            if not are_we_done and winkill_sigint_dll:
                protectfunction(
                    fu=kill_app_dll,
                    pid=mypid,
                    cmd=0,
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                )
                checkstderrstdoutput(mypid)
            if not are_we_done and winkill_sigbreak_dll:
                protectfunction(
                    fu=kill_app_dll,
                    pid=mypid,
                    cmd=1,
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                )
            if winkill_sigint:
                protectfunctionmulti(
                    fu=kill_app,
                    pid=subprocesspid,
                    cmd="-SIGINT",
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                )
            if winkill_sigbreak:
                protectfunctionmulti(
                    fu=kill_app,
                    pid=subprocesspid,
                    cmd="-SIGBREAK",
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                )
            if powershell_sigint:
                protectfunctionmulti(
                    fu=send_ctrl_c_with_powershell,
                    pid=subprocesspid,
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                    ctrl_cmd=0,
                )
            if powershell_sigbreak:
                protectfunctionmulti(
                    fu=send_ctrl_c_with_powershell,
                    pid=subprocesspid,
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                    ctrl_cmd=1,
                )
            if powershell_close:
                protectfunctionmulti(
                    fu=send_ctrl_c_with_powershell,
                    pid=subprocesspid,
                    protect_myself=protect_myself,
                    kill_timeout=kill_timeout,
                    ctrl_cmd=2,
                )
        checkstderrstdoutput(mypid)
    if not are_we_done and taskkill_as_last_option:
        allkills2execute = get_children_pids(
            mypid, always_ignore=multi_children_always_ignore_pids
        )
        lastresults = []
        for subprocesspid in allkills2execute:
            lastresult = kill_with_taskkill(pid=subprocesspid)
            lastresults.append(lastresult)
    else:
        lastresults = []
    return resultsdict_stdout, resultsdict_stderr, are_we_done, counter, lastresults


