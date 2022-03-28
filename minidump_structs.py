import ctypes
from ctypes import Structure, Union
from abc import ABC, abstractmethod

ULONG32 = ctypes.c_uint32
ULONG = ULONG32
RVA = ULONG32
RVA64 = ctypes.c_uint64
ULONG64 = ctypes.c_uint64
USHORT = ctypes.c_ushort
UCHAR = ctypes.c_uint8
WCHAR = ctypes.c_wchar
DWORD = ctypes.c_uint32
ULONGLONG = ctypes.c_ulonglong
LONGLONG = ctypes.c_longlong
WORD = ctypes.c_uint16
BYTE = UCHAR
DWORD64 = ctypes.c_uint64

class generic_file_structure:
	_pack_ = 1
	def __init__(self, rva=0, writer=None, read=False):
		self._rva = rva
		self._writer = writer
		if read:
			self._writer.seek(self._rva)
			read_bytes = self._writer.read(self.size())
			fit = min(len(read_bytes), self.size())
			ctypes.memmove(ctypes.addressof(self), read_bytes, fit)

	def write(self):
		if self._writer is None:
			raise RuntimeError("_writer is None!")

		self._writer.seek(self._rva)
		self._writer.write(bytes(self))

	@classmethod
	def size(cls):
		return ctypes.sizeof(cls)

class MINIDUMP_LOCATION_DESCRIPTOR(generic_file_structure, Structure):	
	_fields_ = [
		("DataSize", ULONG32),
		("Rva", RVA)
	]

class MINIDUMP_LOCATION_DESCRIPTOR64(generic_file_structure, Structure):
	_fields_ = [
		("DataSize", ULONG64),
		("Rva", RVA64)
	]

class MINIDUMP_HEADER(generic_file_structure, Structure):
	_fields_ = [
		("Signature", ULONG32),
		("Version", ULONG32),
		("NumberOfStreams", ULONG32),
		("StreamDirectoryRva", RVA),
		("CheckSum", ULONG32),
		("TimeDateStamp", ULONG32),
		("Flags", RVA64)
	]

class MINIDUMP_DIRECTORY(generic_file_structure, Structure):
	_fields_ = [
		("StreamType", ULONG32),
		("Location", MINIDUMP_LOCATION_DESCRIPTOR)
	]

class CPU_INFORMATION(generic_file_structure, Structure):
	_fields_ = [
		("cpu_info_arr", 0x18 * UCHAR)
	]

class MINIDUMP_SYSTEM_INFO(generic_file_structure, Structure):
	_fields_ = [
		("ProcessorArchitecture", USHORT),
		("ProcessorLevel", USHORT),
		("ProcessorRevision", USHORT),
		("NumberOfProcessors", UCHAR),
		("ProductType", UCHAR),
		("MajorVersion", ULONG32),
		("MinorVersion", ULONG32),
		("BuildNumber", ULONG32),
		("PlatformId", ULONG32),
		("CSDVersionRva", RVA),
		("SuiteMask", USHORT),
		("Reserved2", USHORT),
		("Cpu", CPU_INFORMATION)
	]
class MINIDUMP_STRING(generic_file_structure, Structure):
	_fields_ = [
		("Length", ULONG32),
		# ("Buffer", WCHAR)
	]

class VS_FIXEDFILEINFO(generic_file_structure, Structure):
	_fields_ = [
		("dwSignature", DWORD),
		("dwStrucVersion", DWORD),
		("dwFileVersionMS", DWORD),
		("dwFileVersionLS", DWORD),
		("dwProductVersionMS", DWORD),
		("dwProductVersionLS", DWORD),
		("dwFileFlagsMask", DWORD),
		("dwFileFlags", DWORD),
		("dwFileOS", DWORD),
		("dwFileType", DWORD),
		("dwFileSubtype", DWORD),
		("dwFileDateMS", DWORD),
		("dwFileDateLS", DWORD)
	]

class MINIDUMP_MODULE(generic_file_structure, Structure):
	_fields_ = [
		("BaseOfImage", ULONG64),
		("SizeOfImage", ULONG32),
		("CheckSum", ULONG32),
		("TimeDateStamp", ULONG32),
		("ModuleNameRva", RVA),
		("VersionInfo", VS_FIXEDFILEINFO),
		("CvRecord", MINIDUMP_LOCATION_DESCRIPTOR),
		("MiscRecord", MINIDUMP_LOCATION_DESCRIPTOR),
		("Reserved0", ULONG64),
		("Reserved1", ULONG64),
	]

class MINIDUMP_MODULE_LIST(generic_file_structure, Structure):
	_fields_ = [
		("NumberOfModules", ULONG32),
		#   MINIDUMP_MODULE Modules[0];
	]

class MINIDUMP_MEMORY_DESCRIPTOR(generic_file_structure, Structure):
	_fields_ = [
		("StartOfMemoryRange", ULONG64),
		("Memory", MINIDUMP_LOCATION_DESCRIPTOR),
	]

class MINIDUMP_MEMORY_DESCRIPTOR64(generic_file_structure, Structure):
	_fields_ = [
		("StartOfMemoryRange", ULONG64),
		("DataSize", ULONG64),
	]


class MINIDUMP_THREAD(generic_file_structure, Structure):
	_fields_ = [
		("ThreadId", ULONG32),
		("SuspendCount", ULONG32),
		("PriorityClass", ULONG32),
		("Priority", ULONG32),
		("Teb", ULONG64),
		("Stack", MINIDUMP_MEMORY_DESCRIPTOR),
		("ThreadContext", MINIDUMP_LOCATION_DESCRIPTOR),
	]

class MINIDUMP_THREAD_LIST(generic_file_structure, Structure):
	_fields_ = [
		("NumberOfThreads", ULONG32),
		#   MINIDUMP_THREAD Threads[0];
	]

class MINIDUMP_MEMORY_INFO_LIST(generic_file_structure, Structure):
	_fields_ = [
		("SizeOfHeader", ULONG),
		("SizeOfEntry", ULONG),
		("NumberOfEntries", ULONG64),		
	]

class MINIDUMP_MEMORY_INFO(generic_file_structure, Structure):
	_fields_ = [
		("BaseAddress", ULONG64),
		("AllocationBase", ULONG64),
		("AllocationProtect", ULONG32),
		("__alignment1", ULONG32),
		("RegionSize", ULONG64),
		("State", ULONG32),
		("Protect", ULONG32),
		("Type", ULONG32),
		("__alignment2", ULONG32),
	]

string_protect_to_MemoryProtection = {
	"r--": 0x02,
	"-w-": 0x04, # Actually PAGE_READWRITE
	"--x": 0x10,
	"rw-": 0x04,
	"r-x": 0x20,
	"-wx": 0x40, # Actually PAGE_EXECUTE_READWRITE
	"rwx": 0x40,
	"---": 0x01,
}

string_type_to_MemoryType = {
	"Private": 0x20000,
	"Mapped": 0x40000,
	"Image": 0x1000000,
}

class MINIDUMP_MEMORY64_LIST(generic_file_structure, Structure):
	_fields_ = [
		("NumberOfMemoryRanges", ULONG64),
		("BaseRva", RVA64),
		# ("MemoryRanges", MINIDUMP_MEMORY_DESCRIPTOR64),
	]

class _M128A(generic_file_structure, Structure):
    _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG),
    ]
M128A = _M128A

class _XSAVE_FORMAT_64(generic_file_structure, Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * (8)),
        ("XmmRegisters", M128A * (16)),
        ("Reserved4", BYTE * (96)),
    ]
XSAVE_FORMAT_64 = _XSAVE_FORMAT_64

class _XSAVE_FORMAT_32(generic_file_structure, Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * (8)),
        ("XmmRegisters", M128A * (8)),
        ("Reserved4", BYTE * (192)),
        ("StackControl", DWORD * (7)),
        ("Cr0NpxState", DWORD),
    ]
XSAVE_FORMAT_32 = _XSAVE_FORMAT_32

class _TMP_DUMMYSTRUCTNAME(generic_file_structure, Structure):
    _fields_ = [
        ("Header", M128A * (2)),
        ("Legacy", M128A * (8)),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]
TMP_DUMMYSTRUCTNAME = _TMP_DUMMYSTRUCTNAME

class _TMP_CONTEXT64_SUBUNION(Union):
    _fields_ = [
        ("FltSave", XSAVE_FORMAT_64),
        ("DUMMYSTRUCTNAME", TMP_DUMMYSTRUCTNAME),
    ]
TMP_CONTEXT64_SUBUNION = _TMP_CONTEXT64_SUBUNION

class CONTEXT64(generic_file_structure, Structure):
    _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),
        ("DUMMYUNIONNAME", TMP_CONTEXT64_SUBUNION),
        ("VectorRegister", M128A * (26)),
        ("VectorControl", DWORD64),
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),
    ]

class _FLOATING_SAVE_AREA(generic_file_structure, Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * (80)),
        ("Cr0NpxState", DWORD),
    ]
FLOATING_SAVE_AREA = _FLOATING_SAVE_AREA

class CONTEXT32(generic_file_structure, Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * (512)),
    ]
    