from abc import ABC, abstractmethod
from collections import OrderedDict
import time
import pdb

from minidump_enums import *
from minidump_structs import *
import logging


class minidump_provider(ABC):
	"""
	after header is written self.bitness will contain system bitness and self.arch will contain ProcessorArchitecture

	"""
	@abstractmethod
	def get_system_info(self):
		"""
		get generic system information

		ProcessorArchitecture - one of (amd64, arm, ia64, intel)
		ProcessorLevel - Optional, default to INTEL_PRO_OR_PENTIUM_2 from ProcessorLevel enum
		ProcessorRevision - Optional, default to const 0x5E03
		MajorVersion
		MinorVersion
		BuildNumber
		NumberOfProcessors - Optional.  defaults to 1
		ProductType - Optional ProductType enum
		PlatformId - Optional PlatformId enum
		"""

	def get_modules(self):
		"""
		get module information as an array of

		BaseOfImage
		SizeOfImage
		ModuleName
		TimeDateStamp - Optional
		"""

		return []

	def get_memory_info(self):
		"""
		get memory info array of dict:

		BaseAddress - Optional, default to 0
		AllocationBase - Optional, default to 0, if AllocationBase is 0 then BaseAddress is used
		AllocationProtect
		Protect
		RegionSize - Optional, default to 0
		Type - Optional, "Mapped, Private or Image", defaults to Private
		"""

		return []

	def get_threads(self):
		"""
		get thread information as a dict of thread_id and members

		ThreadId :{ PriorityClass - Optional
					Priority - Optional
					Teb - Optional
					Context - Optional -> Dict of registers ({"Rip": 1})
		}
		"""

		return {}

	def get_memory_descriptors(self):
		"""
		get (range_start, range_start, info) array of valid memory in the dump
		"""
		return []

	@abstractmethod
	def get_bytes(self, address, size, info):
		"""
		reads addresses that were received from `get_memory_descriptors`
		info is used to pass information to the get_bytes function so you can calculate some logic once
		"""

def _context_from_provider_context(context, arch):
	if context is None:
		return None

	arch_to_context = {
		ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL.value: CONTEXT32,
		ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64.value: CONTEXT64
	}

	context_struct_class = arch_to_context.get(arch, None)
	if context_struct_class is None:
		logging.warning(f"Context object for {arch} is not defined")

		return None

	context_struct = context_struct_class()
	for field in context_struct._fields_:
		field_name = field[0]
		if field_name in context:
			setattr(context_struct, field_name, context[field_name])

	return context_struct

class minidump_writer:
	def __init__(self, file, chunk_size=0x10000):
		self._file = file

		self.bitness = 32
		self.whole_range_size = False

		self.chunk_size = chunk_size
		if self.chunk_size == -1:
			self.whole_range_size = True

		# translators translate results to the MINIDUMP format struct
		self.stream_to_handler = OrderedDict()
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.SystemInfoStream.value] = (self.get_system_info, self.get_system_info_translator, None)
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.ModuleListStream.value] = (self.get_modules, self.get_modules_translator, None)
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.ThreadListStream.value] = (self.get_threads, self.get_threads_translator, None)
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.MemoryInfoListStream.value] = (self.get_memory_info, self.get_memory_info_translator, None)

		# Put this last for clarity
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.Memory64ListStream.value] = (self.get_memory_descriptors, self.get_memory_descriptors_translator, self.memory_fetcher)
		

	def get_system_info_translator(self, system_info):
		allocated_system_info_rva = self._alloc(MINIDUMP_SYSTEM_INFO.size())
		system_info_struct = MINIDUMP_SYSTEM_INFO(allocated_system_info_rva, self._file)
		system_info_struct.ProcessorArchitecture = arch_to_ProcessorArchitecture.get(system_info["ProcessorArchitecture"], ProcessorArchitecture.PROCESSOR_ARCHITECTURE_UNKNOWN.value)

		self.arch = system_info_struct.ProcessorArchitecture
		if system_info_struct.ProcessorArchitecture in [ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64.value, ProcessorArchitecture.PROCESSOR_ARCHITECTURE_IA64.value]:
			self.bitness = 64

		system_info_struct.ProcessorLevel = system_info.get("ProcessorLevel", ProcessorLevel.INTEL_PRO_OR_PENTIUM_2.value)
		system_info_struct.ProcessorRevision = system_info.get("ProcessorRevision", 0x5E03)
		system_info_struct.MajorVersion = system_info["MajorVersion"]
		system_info_struct.MinorVersion = system_info["MinorVersion"]
		system_info_struct.BuildNumber = system_info["BuildNumber"]
		system_info_struct.NumberOfProcessors = system_info.get("NumberOfProcessors", 1)
		system_info_struct.ProductType = system_info.get("ProductType", ProductType.VER_NT_WORKSTATION.value)
		system_info_struct.PlatformId = system_info.get("PlatformId", PlatformId.VER_PLATFORM_WIN32_NT.value)
		system_info_struct.write()

		location = MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = system_info_struct.size()
		location.Rva = allocated_system_info_rva

		return location

	def get_memory_info_translator(self, memory_info):
		size_needed_for_info = MINIDUMP_MEMORY_INFO_LIST.size() + len(memory_info) * MINIDUMP_MEMORY_INFO.size()
		memory_info_list_location = self._alloc(size_needed_for_info)

		memory_info_list_struct = MINIDUMP_MEMORY_INFO_LIST(memory_info_list_location, self._file)
		memory_info_list_struct.SizeOfHeader = memory_info_list_struct.size()
		memory_info_list_struct.SizeOfEntry = MINIDUMP_MEMORY_INFO.size()
		memory_info_list_struct.NumberOfEntries = len(memory_info)
		memory_info_list_struct.write()

		for memory_info_index, current_memory_info in enumerate(memory_info):
			memory_info_location = memory_info_list_location + MINIDUMP_MEMORY_INFO_LIST.size() + (memory_info_index * MINIDUMP_MEMORY_INFO.size())
			memory_info_struct = MINIDUMP_MEMORY_INFO(memory_info_location, self._file)

			memory_info_struct.BaseAddress = current_memory_info.get("BaseAddress", 0)
			memory_info_struct.AllocationBase = current_memory_info.get("AllocationBase", 0)
			if memory_info_struct.AllocationBase == 0:
				memory_info_struct.AllocationBase = memory_info_struct.BaseAddress

			if type(current_memory_info["AllocationProtect"]) == int:
				memory_info_struct.AllocationProtect = current_memory_info["AllocationProtect"]
			else:
				memory_info_struct.AllocationProtect = string_protect_to_MemoryProtection[current_memory_info.get("AllocationProtect", "rwx")]
			
			if type(current_memory_info["Protect"]) == int:
				memory_info_struct.Protect = current_memory_info["Protect"]
			else:
				memory_info_struct.Protect = string_protect_to_MemoryProtection[current_memory_info.get("Protect", "rwx")]

			memory_info_struct.RegionSize = current_memory_info.get("RegionSize", 0)
			memory_info_struct.State = 0x1000 # MEM_COMMIT
			memory_info_struct.Type = string_type_to_MemoryType[current_memory_info.get("Type", "Private")]

			memory_info_struct.write()

		location = MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = memory_info_list_location

		return location


	def get_threads_translator(self, threads):
		size_needed_for_info = MINIDUMP_THREAD_LIST.size() + (MINIDUMP_THREAD.size() * len(threads.keys()))
		thread_info_location = self._alloc(size_needed_for_info)
		
		thread_list_struct = MINIDUMP_THREAD_LIST(thread_info_location, self._file)
		thread_list_struct.NumberOfThreads = len(threads.keys())
		thread_list_struct.write()

		for thread_index, thread_id in enumerate(threads):
			thread_struct_location = thread_info_location + MINIDUMP_THREAD_LIST.size() + (thread_index * MINIDUMP_THREAD.size())
			thread_struct = MINIDUMP_THREAD(thread_struct_location, self._file)
			thread_info = threads[thread_id]

			thread_struct.ThreadId = thread_id
			thread_struct.PriorityClass = thread_info.get("PriorityClass", 0)
			thread_struct.Priority = thread_info.get("Priority", 0)
			thread_struct.Teb = thread_info.get("Teb", 0)

			thread_context = thread_info.get("Context", {})
			thread_context_struct = _context_from_provider_context(thread_context, self.arch)
			if thread_context_struct is not None:
				context_bytes = bytes(thread_context_struct)
				context_location_rva = self._alloc_buffer(context_bytes)
				thread_struct.ThreadContext.Rva = context_location_rva
				thread_struct.ThreadContext.DataSize = len(context_bytes)

			thread_struct.write()

		location = MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = thread_info_location

		return location

	def get_modules_translator(self, modules):
		amount_of_modules = len(modules)
		size_needed_for_info = MINIDUMP_MODULE_LIST.size() + (MINIDUMP_MODULE.size() * amount_of_modules)
		minidump_module_list_location = self._alloc(size_needed_for_info)
		module_list_struct = MINIDUMP_MODULE_LIST(minidump_module_list_location, self._file)
		module_list_struct.NumberOfModules = amount_of_modules
		module_list_struct.write()

		for module_index, module in enumerate(modules):
			module_struct_location = minidump_module_list_location + MINIDUMP_MODULE_LIST.size() + (module_index * MINIDUMP_MODULE.size())
			module_struct = MINIDUMP_MODULE(module_struct_location, self._file)

			module_struct.BaseOfImage = module["BaseOfImage"]
			module_struct.SizeOfImage = module["SizeOfImage"]
			module_struct.TimeDateStamp = module.get("TimeDateStamp", 0)
			module_struct.ModuleNameRva = self._alloc_minidump_string(module["ModuleName"])

			module_struct.write()


		location = MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = minidump_module_list_location

		return location

	def get_memory_descriptors_translator(self, memory_descriptors):
		number_of_ranges = len(memory_descriptors)

		size_needed_for_info = MINIDUMP_MEMORY64_LIST.size() + (number_of_ranges * MINIDUMP_MEMORY_DESCRIPTOR64.size())
		memory_list_location = self._alloc(size_needed_for_info)
		memory64_list_struct = MINIDUMP_MEMORY64_LIST(memory_list_location, self._file)
		memory64_list_struct.NumberOfMemoryRanges = number_of_ranges

		total_size_for_memory = 0

		for range_index, descriptor in enumerate(memory_descriptors):
			descriptor_location = memory_list_location + MINIDUMP_MEMORY64_LIST.size() + (range_index * MINIDUMP_MEMORY_DESCRIPTOR64.size())
			descriptor_struct = MINIDUMP_MEMORY_DESCRIPTOR64(descriptor_location, self._file)

			range_start, range_size, _ = descriptor
			total_size_for_memory += range_size

			descriptor_struct.StartOfMemoryRange = range_start
			descriptor_struct.DataSize = range_size

			descriptor_struct.write()


		memory64_list_struct.BaseRva = self._alloc(total_size_for_memory)
		memory64_list_struct.write()

		location = MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = memory_list_location

		return location

	def memory_fetcher(self, memory_descriptors, directory):
		memory64_list_struct = MINIDUMP_MEMORY64_LIST(directory.Location.Rva, self._file, True)
		current_disk_rva = memory64_list_struct.BaseRva
		for range_start, range_size, info in memory_descriptors:
			self._get_bytes_wrapper(range_start, range_size, info, current_disk_rva)
			current_disk_rva += range_size
			
	def _get_bytes_wrapper(self, range_start, range_size, info, disk_rva):
		bytes_written = 0
		while bytes_written < range_size:
			chunk_size = self.chunk_size
			if self.whole_range_size:
				chunk_size = range_size

			amount_bytes_to_read = min(chunk_size, range_size - bytes_written)
			buffer = self.get_bytes(range_start + bytes_written, amount_bytes_to_read, info)

			self._file.seek(disk_rva)
			self._file.write(buffer)

			disk_rva += len(buffer)
			bytes_written += len(buffer)

		assert bytes_written == range_size

	def write(self):
		self.write_header()
		self.write_directories_header()
		self.write_directories()

	def write_header(self):
		self.header = MINIDUMP_HEADER(0, self._file)
		self.header.Signature = 0x504D444D # 'MDMP'
		self.header.Version = 0xA0BAA793
		self.header.NumberOfStreams = len(self.stream_to_handler)
		self.header.TimeDateStamp = int(time.time())
		self.header.StreamDirectoryRva = self.header.size()

		if MINIDUMP_STREAM_TYPE.Memory64ListStream.value in self.stream_to_handler:
			self.header.Flags |= MINIDUMP_TYPE.MiniDumpWithFullMemory
			self.header.Flags |= MINIDUMP_TYPE.MiniDumpIgnoreInaccessibleMemory

		if MINIDUMP_STREAM_TYPE.MemoryInfoListStream.value in self.stream_to_handler:
			self.header.Flags |= MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo

		self.header.write()

	def write_directories_header(self):
		current_file_offset = self.header.StreamDirectoryRva
		self._file.seek(current_file_offset)

		for stream_type in self.stream_to_handler:
			current_directory = MINIDUMP_DIRECTORY(current_file_offset, self._file)
			current_directory.StreamType = stream_type
			current_directory.write()
			current_file_offset += current_directory.size()

	def _alloc(self, amount):
		self._file.seek(0, 2)
		current_position = self._file.tell()
		self._file.seek(amount - 1, 1)
		self._file.write(b"\x00")

		return current_position

	def _alloc_buffer(self, buffer):
		allocated_location = self._alloc(len(buffer))
		self._file.seek(allocated_location)
		self._file.write(buffer)

		return allocated_location

	def _alloc_minidump_string(self, string_value):
		string_encoded = string_value.encode("utf-16-le") + b"\x00\x00"

		minidump_string = MINIDUMP_STRING()
		minidump_string.Length = len(string_encoded)

		return self._alloc_buffer(bytes(minidump_string) + string_encoded)

	def write_directories(self):
		for stream_index in range(self.header.NumberOfStreams):
			directory_offset = self.header.StreamDirectoryRva + (stream_index) * MINIDUMP_DIRECTORY.size()
			directory = MINIDUMP_DIRECTORY(directory_offset, self._file, True)
			info_getter, translator, post_translator = self.stream_to_handler[directory.StreamType]
			info = info_getter()
			location = translator(info)

			directory.Location = location
			directory.write()

			if post_translator:
				post_translator(info, directory)

