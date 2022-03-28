from minidump_enums import *
from minidump_writer import minidump_provider, minidump_writer
import windows
import sys

def windows_protect_to_string(protect):
	to_return = ""
	if "READ" in str(protect):
		to_return += "r"
	else:
		to_return += "-"

	if "WRITE" in str(protect):
		to_return += "w"
	else:
		to_return += "-"

	if "EXECUTE" in str(protect):
		to_return += "x"
	else:
		to_return += "-"

	return to_return	

class windows_writer(minidump_provider, minidump_writer):
	def __init__(self, file, pid=0, *args, **kwargs):
		self.process = windows.winobject.process.WinProcess(pid=pid)
		super().__init__(file, *args, **kwargs)

	def get_system_info(self):
		to_return = {}
		current_system_version = windows.system.get_version()
		if windows.system.bitness == 32:
			to_return["ProcessorArchitecture"] = "intel"
		else:
			to_return["ProcessorArchitecture"] = "amd64"
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

		if self.process.is_wow_64:
			for module in self.process.peb_syswow.modules:
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

			context = {}
			thread_context = thread.context
			if self.process.is_wow_64:
				thread_context = thread.context_syswow

			if hasattr(thread_context, "Rip"):
				context["Rip"] = thread_context.Rip
				context["Rsp"] = thread_context.Rsp
				context["Rbp"] = thread_context.Rbp
			else:
				context["Eip"] = thread_context.Eip
				context["Esp"] = thread_context.Esp
				context["Ebp"] = thread_context.Ebp

			thread_info["Context"] = context

			threads[thread.tid] = thread_info

		return threads

	def get_memory_info(self):
		memory_info = []
		for basic_info in self.process.memory_state():
			to_skip = False
			skip_states = [0x2000, 0x10000] # skip free and reserved
			for skip_state in skip_states:
				if basic_info.State & skip_state == skip_state:
					to_skip = True
					break

			if to_skip:
				continue

			info = {}
			info["BaseAddress"] = basic_info.BaseAddress
			info["RegionSize"] = basic_info.RegionSize
			info["AllocationBase"] = basic_info.AllocationBase
			info["Protect"] = windows_protect_to_string(basic_info.Protect)
			info["AllocationProtect"] = windows_protect_to_string(basic_info.AllocationProtect)
			
			if "PRIVATE" in str(basic_info.Type):
				info["Type"] = "Private"
			elif "MAPPED" in str(basic_info.Type):
				info["Type"] = "Mapped"
			else:
				info["Type"] = "Image"

			memory_info.append(info)

		return memory_info

	def get_memory_descriptors(self):
		memory_descriptors_arr = []

		for basic_info in self.process.memory_state():
			to_skip = False
			skip_states = [0x2000, 0x10000] # skip free and reserved
			for skip_state in skip_states:
				if basic_info.State & skip_state == skip_state:
					to_skip = True
					break

			if to_skip:
				continue
			
			memory_descriptors_arr.append((basic_info.BaseAddress, basic_info.RegionSize, basic_info))

		return memory_descriptors_arr

	def get_bytes(self, address, size, info):
		try:
			return self.process.read_memory(address, size)
		except:
			return b"\x00" * size

def main():
	pid = int(sys.argv[1])
	with open(f"windows_writer_{pid}.dmp", "wb+") as f:
		test_writer = windows_writer(f, pid=pid)
		test_writer.write()

if __name__ == "__main__":
	main()
