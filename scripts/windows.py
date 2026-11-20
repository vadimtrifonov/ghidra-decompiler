"""Windows calls that the standard library does not offer: the run lock, the worker's job, version resources."""

import ctypes
from ctypes import wintypes

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_version = ctypes.WinDLL("version", use_last_error=True)

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_OPEN_EXISTING = 3
_OPEN_ALWAYS = 4
_FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
_HANDLE_FLAG_INHERIT = 1
_INVALID_HANDLE = wintypes.HANDLE(-1).value
_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32
_JOB_EXTENDED_LIMITS = 9
_JOB_KILL_ON_CLOSE = 0x2000

_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CreateFileW.argtypes = (
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
)
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
_kernel32.SetHandleInformation.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD)
_kernel32.CreateJobObjectW.restype = wintypes.HANDLE
_kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
_kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
_kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_version.GetFileVersionInfoSizeExW.argtypes = (wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPVOID)
_version.GetFileVersionInfoExW.argtypes = (
    wintypes.DWORD,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
)
_version.VerQueryValueW.argtypes = (wintypes.LPCVOID, wintypes.LPCWSTR, wintypes.LPVOID, wintypes.LPVOID)


class _BasicLimits(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class _ExtendedLimits(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", ctypes.c_uint64 * 6),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


def _error():
    return ctypes.WinError(ctypes.get_last_error())


def hold_lock(path):
    """Take the lock at path for as long as the returned handle is open; return None if it is taken.

    The file admits no second open, so the lock lasts until every process that inherited the handle has ended.
    Windows then deletes the file.
    """
    handle = _kernel32.CreateFileW(
        str(path), _GENERIC_WRITE | _DELETE, 0, None, _OPEN_ALWAYS, _FILE_FLAG_DELETE_ON_CLOSE, None
    )
    if handle == _INVALID_HANDLE:
        if ctypes.get_last_error() in (_ERROR_SHARING_VIOLATION, _ERROR_ACCESS_DENIED):
            return None
        raise _error()
    if not _kernel32.SetHandleInformation(handle, _HANDLE_FLAG_INHERIT, _HANDLE_FLAG_INHERIT):
        raise _error()
    return handle


def lock_is_held(path):
    handle = _kernel32.CreateFileW(str(path), _GENERIC_READ, 7, None, _OPEN_EXISTING, 0, None)
    if handle == _INVALID_HANDLE:
        return ctypes.get_last_error() in (_ERROR_SHARING_VIOLATION, _ERROR_ACCESS_DENIED)
    _kernel32.CloseHandle(handle)
    return False


def end_children_with_this_process():
    """Make Windows end every process this one starts when this one ends, however it ends.

    The caller must keep the returned handle.
    """
    job = _kernel32.CreateJobObjectW(None, None)
    if not job:
        raise _error()
    limits = _ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = _JOB_KILL_ON_CLOSE
    if not _kernel32.SetInformationJobObject(
        job, _JOB_EXTENDED_LIMITS, ctypes.byref(limits), ctypes.sizeof(limits)
    ) or not _kernel32.AssignProcessToJobObject(job, _kernel32.GetCurrentProcess()):
        raise _error()
    return job


def version_resource(path):
    """Return the FileVersion string and the numeric file version of a PE file; either can be None.

    Flags of 0 read the file's own resource.
    The plain calls prefer a language file beside it, which makes a system file's version depend on its folder.
    """
    size = _version.GetFileVersionInfoSizeExW(0, str(path), None)
    data = ctypes.create_string_buffer(size)
    if not size or not _version.GetFileVersionInfoExW(0, str(path), 0, size, data):
        return None, None
    value, length = ctypes.c_void_p(), wintypes.UINT()

    def query(block):
        found = _version.VerQueryValueW(data, block, ctypes.byref(value), ctypes.byref(length))
        return value.value if found and length.value else None

    numeric = None
    if fixed := query("\\"):
        _, _, high, low = (wintypes.DWORD * 4).from_address(fixed)
        numeric = f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"
    tables = []
    if translations := query("\\VarFileInfo\\Translation"):
        words = (wintypes.WORD * (length.value // 2)).from_address(translations)
        tables = [f"{words[i]:04x}{words[i + 1]:04x}" for i in range(0, len(words) - 1, 2)]
    for table in (*tables, "040904b0", "040904e4", "04090000"):
        if text := query(f"\\StringFileInfo\\{table}\\FileVersion"):
            return ctypes.wstring_at(text), numeric
    return None, numeric
