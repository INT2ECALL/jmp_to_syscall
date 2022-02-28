#include <vector>
#include "syscall.h"

using pNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

void* RuntimeDynamicLinking(const char* module_name, const char* fuction_name) {
	HMODULE module_handle = GetModuleHandleA(module_name);
	if (module_handle == NULL) {
		module_handle = LoadLibraryA(module_name);
		if (module_handle == NULL) return NULL;
	}
	return GetProcAddress(module_handle, fuction_name);
}

void* MemorySearch(unsigned char* address) {
	unsigned char egg[] = { 0x0f,0x05,0xc3 };
	unsigned char* max = address + 1024;
	while (true) {
		int n = 0;
		while (address < max) {
			address += 1;
			if (address == max) {
				return NULL;
			}
			else {
				if (*address == egg[n]) {
					n++;
					if (n == sizeof(egg)) {
						return (void*)(address - sizeof(egg) + 1);
					}
				}
				else {
					break;
				}
			}
		}
	}
}

std::vector<unsigned char> GetSyscallStub(DWORD hash) {
	std::vector<unsigned char> syscall{
	0x4c,0x8b,0xd1,                                         // mov r10, rcx
	0xb8,0x00,0x00,0x00,0x00,                               // mov eax, 0x0000 0000(syscall number)
	0x49,0xbb,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,     // mov r11, 0x0000 0000 0000 0000(syscall address)
	0x41,0xff,0xe3 };                                       // jmp r11
	DWORD oldprotect = 0;
	if (!VirtualProtect(syscall.data(), syscall.size(), PAGE_EXECUTE_READWRITE, &oldprotect)) {
		syscall.clear();
		return syscall;
	}
	auto number = SW2_GetSyscallNumber(hash);
	memcpy(&syscall[4], &number, 4);
	auto jmpaddr = MemorySearch((unsigned char*)RuntimeDynamicLinking("ntdll", "NtClose"));
	memcpy(&syscall[10], &jmpaddr, 8);
	return syscall;
}

int main(int argc, char* argv[]) {
    char test[] = "BOOM!BOOM!BOOM!";
	auto mem = VirtualAlloc(0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	auto sss = GetSyscallStub(0x08F19F9F7);

	size_t n;
	reinterpret_cast<pNtWriteVirtualMemory>(sss.data())(GetCurrentProcess(), mem, &test[0], sizeof(test), &n);

	return 0;
}