import ctypes
from ctypes import Structure
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

class MINIDUMP_MEMORY64_LIST(generic_file_structure, Structure):
	_fields_ = [
		("NumberOfMemoryRanges", ULONG64),
		("BaseRva", RVA64),
		# ("MemoryRanges", MINIDUMP_MEMORY_DESCRIPTOR64),
	]
