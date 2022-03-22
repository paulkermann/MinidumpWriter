from minidump_enums import *
from writer import minidump_provider, minidump_writer

class dummy_writer(minidump_provider, minidump_writer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def get_system_info(self):
		to_return = {}
		to_return["ProcessorArchitecture"] = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL.value
		to_return["ProcessorLevel"] = ProcessorLevel.INTEL_PRO_OR_PENTIUM_2.value
		to_return["ProcessorRevision"] = 0x5E03
		to_return["MajorVersion"] = 0xa
		to_return["MinorVersion"] = 0
		to_return["BuildNumber"] = 0x295A
		to_return["NumberOfProcessors"] = 2
		to_return["ProductType"] = ProductType.VER_NT_WORKSTATION.value
		to_return["PlatformId"] = PlatformId.VER_PLATFORM_WIN32_NT.value

		return to_return

	def get_modules(self):
		list_of_modules = []
		for i in range(3):
			current_module = {}
			current_module["BaseOfImage"] = 0x10000 + (i) * 0x20000
			current_module["SizeOfImage"] = 0x10000
			current_module["ModuleName"] = "c:\\file_" + str(i)
			list_of_modules.append(current_module)

		return list_of_modules

	def get_threads(self):
		threads = {}
		for i in range(2):
			thread_info = {}
			thread_info["Teb"] = 0x400 + (0x400 * i)
			thread_info["Priority"] = 40
			thread_info["PriorityClass"] = 40
			threads[4 + (i * 4)] = thread_info

		return threads

	def get_memory_descriptors(self):
		memory_descriptors_arr = []
		memory_descriptors_arr.append((0x10000, 0x300))
		memory_descriptors_arr.append((0x500000, 0x5000))

		return memory_descriptors_arr

	def get_bytes(self, address, size):
		if address == 0x10000:
			return size * b"\x01"

		return size * b"\x55"

def main():
	with open("dummy_writer.dmp", "wb+") as f:
		test_writer = dummy_writer(f)
		test_writer.write()

if __name__ == "__main__":
	main()
