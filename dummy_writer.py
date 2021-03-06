from minidump_enums import *
from minidump_writer import minidump_provider, minidump_writer

class dummy_writer(minidump_provider, minidump_writer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def get_system_info(self):
		to_return = {}
		to_return["ProcessorArchitecture"] = "intel"
		to_return["ProcessorLevel"] = ProcessorLevel.INTEL_PRO_OR_PENTIUM_2.value
		to_return["ProcessorRevision"] = 0x5E03
		to_return["MajorVersion"] = 0xa
		to_return["MinorVersion"] = 0
		to_return["BuildNumber"] = 0x295A

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
			if i == 1:
				context = {}
				context["Eip"] = 0x100
				context["Eax"] = 0x1337
				thread_info["Context"] = context

			threads[4 + (i * 4)] = thread_info

		return threads

	def get_memory_info(self):
		memory_info = []
		info = {}
		info["BaseAddress"] = 0x10000
		info["RegionSize"] = 0x1000
		info["Protect"] = "r-x"
		info["AllocationProtect"] = "r-x"

		memory_info.append(info)

		info = {}
		info["BaseAddress"] = 0xff0000
		info["RegionSize"] = 0x1000000
		info["Protect"] = "rwx"
		info["AllocationProtect"] = "rwx"
		info["Type"] = "Mapped"
		memory_info.append(info)

		return memory_info

	def get_memory_descriptors(self):
		memory_descriptors_arr = []
		memory_descriptors_arr.append((0x10000, 0x300, None))
		memory_descriptors_arr.append((0x500000, 0x5000, None))

		return memory_descriptors_arr

	def get_bytes(self, address, size, info):
		if address == 0x10000:
			return size * b"\x01"

		return size * b"\x55"

def main():
	with open("dummy_writer.dmp", "wb+") as f:
		test_writer = dummy_writer(f)
		test_writer.write()

if __name__ == "__main__":
	main()
