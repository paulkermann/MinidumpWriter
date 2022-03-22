from minidump_enums import *
from writer import minidump_provider, minidump_writer
import windows
import sys
import pdb

class windows_writer(minidump_provider, minidump_writer):
	def __init__(self, file, pid=0, *args, **kwargs):
		self.process = windows.winobject.process.WinProcess(pid=pid)
		super().__init__(file, )

	def get_system_info(self):
		to_return = {}
		current_system_version = windows.system.get_version()
		if windows.system.bitness == 32:
			to_return["ProcessorArchitecture"] = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL.value
		else:
			to_return["ProcessorArchitecture"] = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64.value
		to_return["ProcessorLevel"] = ProcessorLevel.INTEL_PRO_OR_PENTIUM_2.value
		to_return["ProcessorRevision"] = 0x5E03
		to_return["MajorVersion"] = current_system_version.dwMajorVersion
		to_return["MinorVersion"] = current_system_version.dwMinorVersion
		to_return["BuildNumber"] = current_system_version.dwBuildNumber
		to_return["NumberOfProcessors"] = windows.current_process.peb.NumberOfProcessors
		to_return["ProductType"] = current_system_version.wProductType
		to_return["PlatformId"] = current_system_version.dwPlatformId

		return to_return

	def get_modules(self):
		list_of_modules = []
		for module in self.process.peb.modules:
			current_module = {}
			current_module["BaseOfImage"] = module.DllBase
			current_module["SizeOfImage"] = module.SizeOfImage
			current_module["ModuleName"] = module.FullDllName.str
			list_of_modules.append(current_module)

		return list_of_modules

	def get_threads(self):
		threads = {}
		for thread in self.process.threads:
			thread_info = {}
			thread_info["Teb"] = thread.teb_base
			thread_info["Priority"] = 0
			thread_info["PriorityClass"] = 0
			threads[thread.tid] = thread_info

		return threads

	def get_memory_descriptors(self):
		memory_descriptors_arr = []

		for basic_info in self.process.memory_state():
			if basic_info.State & 0x10000 == 0x10000:
				continue

			memory_descriptors_arr.append((basic_info.BaseAddress, basic_info.RegionSize))

		return memory_descriptors_arr

	def get_bytes(self, address, size):
		try:
			return self.process.read_memory(address, size)
		except:
			return b"\x00" * size

def main():
	import pdb; pdb.set_trace()
	pid = int(sys.argv[1])
	with open(f"windows_writer_{pid}.dmp", "wb+") as f:
		test_writer = windows_writer(f, pid=pid)
		test_writer.write()

if __name__ == "__main__":
	main()
