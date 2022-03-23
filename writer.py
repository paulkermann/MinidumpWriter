from abc import ABC, abstractmethod
from collections import OrderedDict
import time
import pdb

from minidump_enums import *
import minidump_strcuts
import logging


class minidump_provider(ABC):
	"""
	after header is written self.bitness will contain system bitness and self.arch will contain ProcessorArchitecture

	"""
	@abstractmethod
	def get_system_info(self):
		"""
		get generic system information
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

	def get_threads(self):
		"""
		TODO: add support for get thread context
		get thread information as a dict of thread_id and members

		ThreadId :{ PriorityClass - Optional
					Priority - Optional
					Teb - Optional
		}
		"""
		return {}

	def get_memory_descriptors(self):
		"""
		get (range_start, range_start) array of valid memory in the dump
		"""
		return []

	@abstractmethod
	def get_bytes(self, address, size):
		"""
		reads addresses that were received from `get_memory_descriptors`
		"""

def _context_from_provider_context(context, arch):
	if context is None:
		return None

	arch_to_context = {
		ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL.value: minidump_strcuts.CONTEXT32,
		ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64.value: minidump_strcuts.CONTEXT64
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
	def __init__(self, file):
		self._file = file

		self.bitness = 32
		# TODO: support more streams types: MemoryInfoListStream
		# translators translate results to the MINIDUMP format struct
		self.stream_to_handler = OrderedDict()
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.SystemInfoStream.value] = (self.get_system_info, self.get_system_info_translator, None)
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.ModuleListStream.value] = (self.get_modules, self.get_modules_translator, None)
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.ThreadListStream.value] = (self.get_threads, self.get_threads_translator, None)

		# Put this last for clarity
		self.stream_to_handler[MINIDUMP_STREAM_TYPE.Memory64ListStream.value] = (self.get_memory_descriptors, self.get_memory_descriptors_translator, self.memory_fetcher)
		

	def get_system_info_translator(self, system_info):
		allocated_system_info_rva = self._alloc(minidump_strcuts.MINIDUMP_SYSTEM_INFO.size())
		system_info_struct = minidump_strcuts.MINIDUMP_SYSTEM_INFO(allocated_system_info_rva, self._file)
		system_info_struct.ProcessorArchitecture = system_info["ProcessorArchitecture"]
		self.arch = system_info_struct.ProcessorArchitecture
		if system_info_struct.ProcessorArchitecture in [ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64, ProcessorArchitecture.PROCESSOR_ARCHITECTURE_IA64]:
			self.bitness = 64

		system_info_struct.ProcessorLevel = system_info["ProcessorLevel"]
		system_info_struct.ProcessorRevision = system_info["ProcessorRevision"]
		system_info_struct.MajorVersion = system_info["MajorVersion"]
		system_info_struct.MinorVersion = system_info["MinorVersion"]
		system_info_struct.BuildNumber = system_info["BuildNumber"]
		system_info_struct.NumberOfProcessors = system_info["NumberOfProcessors"]
		system_info_struct.ProductType = system_info["ProductType"]
		system_info_struct.PlatformId = system_info["PlatformId"]
		system_info_struct.write()

		location = minidump_strcuts.MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = system_info_struct.size()
		location.Rva = allocated_system_info_rva

		return location

	def get_threads_translator(self, threads):
		size_needed_for_info = minidump_strcuts.MINIDUMP_THREAD_LIST.size() + (minidump_strcuts.MINIDUMP_THREAD.size() * len(threads.keys()))
		thread_info_location = self._alloc(size_needed_for_info)
		
		thread_list_struct = minidump_strcuts.MINIDUMP_THREAD_LIST(thread_info_location, self._file)
		thread_list_struct.NumberOfThreads = len(threads.keys())
		thread_list_struct.write()

		for thread_index, thread_id in enumerate(threads):
			thread_struct_location = thread_info_location + minidump_strcuts.MINIDUMP_THREAD_LIST.size() + (thread_index * minidump_strcuts.MINIDUMP_THREAD.size())
			thread_struct = minidump_strcuts.MINIDUMP_THREAD(thread_struct_location, self._file)
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

		location = minidump_strcuts.MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = thread_info_location

		return location

	def get_modules_translator(self, modules):
		amount_of_modules = len(modules)
		size_needed_for_info = minidump_strcuts.MINIDUMP_MODULE_LIST.size() + (minidump_strcuts.MINIDUMP_MODULE.size() * amount_of_modules)
		minidump_module_list_location = self._alloc(size_needed_for_info)
		module_list_struct = minidump_strcuts.MINIDUMP_MODULE_LIST(minidump_module_list_location, self._file)
		module_list_struct.NumberOfModules = amount_of_modules
		module_list_struct.write()

		for module_index, module in enumerate(modules):
			module_struct_location = minidump_module_list_location + minidump_strcuts.MINIDUMP_MODULE_LIST.size() + (module_index * minidump_strcuts.MINIDUMP_MODULE.size())
			module_struct = minidump_strcuts.MINIDUMP_MODULE(module_struct_location, self._file)

			module_struct.BaseOfImage = module["BaseOfImage"]
			module_struct.SizeOfImage = module["SizeOfImage"]
			module_struct.TimeDateStamp = module.get("TimeDateStamp", 0)
			module_struct.ModuleNameRva = self._alloc_minidump_string(module["ModuleName"])

			module_struct.write()


		location = minidump_strcuts.MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = minidump_module_list_location

		return location

	def get_memory_descriptors_translator(self, memory_descriptors):
		number_of_ranges = len(memory_descriptors)

		size_needed_for_info = minidump_strcuts.MINIDUMP_MEMORY64_LIST.size() + (number_of_ranges * minidump_strcuts.MINIDUMP_MEMORY_DESCRIPTOR64.size())
		memory_list_location = self._alloc(size_needed_for_info)
		memory64_list_struct = minidump_strcuts.MINIDUMP_MEMORY64_LIST(memory_list_location, self._file)
		memory64_list_struct.NumberOfMemoryRanges = number_of_ranges

		total_size_for_memory = 0

		for range_index, descriptor in enumerate(memory_descriptors):
			descriptor_location = memory_list_location + minidump_strcuts.MINIDUMP_MEMORY64_LIST.size() + (range_index * minidump_strcuts.MINIDUMP_MEMORY_DESCRIPTOR64.size())
			descriptor_struct = minidump_strcuts.MINIDUMP_MEMORY_DESCRIPTOR64(descriptor_location, self._file)

			range_start, range_size = descriptor
			total_size_for_memory += range_size

			descriptor_struct.StartOfMemoryRange = range_start
			descriptor_struct.DataSize = range_size

			descriptor_struct.write()


		memory64_list_struct.BaseRva = self._alloc(total_size_for_memory)
		memory64_list_struct.write()

		location = minidump_strcuts.MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = size_needed_for_info
		location.Rva = memory_list_location

		return location

	def memory_fetcher(self, memory_descriptors, directory):
		memory64_list_struct = minidump_strcuts.MINIDUMP_MEMORY64_LIST(directory.Location.Rva, self._file, True)
		current_memory_rva = memory64_list_struct.BaseRva
		for range_start, range_size in memory_descriptors:
			buffer = self.get_bytes(range_start, range_size)
			assert len(buffer) == range_size

			self._file.seek(current_memory_rva)
			self._file.write(buffer)
			current_memory_rva += range_size

	def write(self):
		self.write_header()
		self.write_directories_header()
		self.write_directories()

	def write_header(self):
		self.header = minidump_strcuts.MINIDUMP_HEADER(0, self._file)
		self.header.Signature = 0x504D444D # 'MDMP'
		self.header.Version = 0xA0BAA793
		self.header.NumberOfStreams = len(self.stream_to_handler)
		self.header.TimeDateStamp = int(time.time())
		self.header.StreamDirectoryRva = self.header.size()

		if MINIDUMP_STREAM_TYPE.Memory64ListStream.value in self.stream_to_handler:
			self.header.Flags |= MINIDUMP_TYPE.MiniDumpWithFullMemory
			self.header.Flags |= MINIDUMP_TYPE.MiniDumpIgnoreInaccessibleMemory

		self.header.write()

	def write_directories_header(self):
		current_file_offset = self.header.StreamDirectoryRva
		self._file.seek(current_file_offset)

		for stream_type in self.stream_to_handler:
			current_directory = minidump_strcuts.MINIDUMP_DIRECTORY(current_file_offset, self._file)
			current_directory.StreamType = stream_type
			current_directory.write()
			current_file_offset += current_directory.size()

	def _alloc(self, amount):
		self._file.seek(0, 2)
		current_position = self._file.tell()
		self._file.write(b"\x00" * amount)

		return current_position

	def _alloc_buffer(self, buffer):
		allocated_location = self._alloc(len(buffer))
		self._file.seek(allocated_location)
		self._file.write(buffer)

		return allocated_location

	def _alloc_minidump_string(self, string_value):
		string_encoded = string_value.encode("utf-16-le") + b"\x00\x00"

		minidump_string = minidump_strcuts.MINIDUMP_STRING()
		minidump_string.Length = len(string_encoded)

		return self._alloc_buffer(bytes(minidump_string) + string_encoded)

	def write_directories(self):
		for stream_index in range(self.header.NumberOfStreams):
			directory_offset = self.header.StreamDirectoryRva + (stream_index) * minidump_strcuts.MINIDUMP_DIRECTORY.size()
			directory = minidump_strcuts.MINIDUMP_DIRECTORY(directory_offset, self._file, True)
			info_getter, translator, post_translator = self.stream_to_handler[directory.StreamType]
			info = info_getter()
			location = translator(info)

			directory.Location = location
			directory.write()

			if post_translator:
				post_translator(info, directory)

