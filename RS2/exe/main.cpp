#include <stdio.h>
#include <Windows.h>
#include "DrvCtrl.h"
#include <iostream>
#include <stdlib.h>
#include <string>
#include <comdef.h>
#include <Wbemidl.h>
#include <psapi.h>
#include <unordered_map>
using namespace std;

#pragma comment(lib, "wbemuuid.lib")
typedef ULONG KPRIORITY;
enum HANDLE_TYPE {
	TYPE_FREE = 0,        // 'must be zero!
	TYPE_WINDOW = 1,      // 'in order of use for C code lookups
	TYPE_MENU = 2,         //
	TYPE_CURSOR = 3,       //
	TYPE_SETWINDOWPOS = 4, // HDWP
	TYPE_HOOK = 5,         //
	TYPE_CLIPDATA = 6,    // 'clipboard data
	TYPE_CALLPROC = 7,     //
	TYPE_ACCELTABLE = 8,   //
	TYPE_DDEACCESS = 9,    //  tagSVR_INSTANCE_INFO
	TYPE_DDECONV = 10,     //  
	TYPE_DDEXACT = 11,     // 'DDE transaction tracking info.
	TYPE_MONITOR = 12,     //
	TYPE_KBDLAYOUT = 13,   // 'Keyboard Layout handle (HKL) object.
	TYPE_KBDFILE = 14,     // 'Keyboard Layout file object.
	TYPE_WINEVENTHOOK = 15,// 'WinEvent hook (EVENTHOOK)
	TYPE_TIMER = 16,       //
	TYPE_INPUTCONTEXT = 17,// 'Input Context info structure
	TYPE_HIDDATA = 18,     //
	TYPE_DEVICEINFO = 19,  //
	TYPE_TOUCHINPUT = 20,  // 'Ustz' W7U sym tagTOUCHINPUTINFO
	TYPE_GESTUREINFO = 21, // 'Usgi'
	TYPE_CTYPES = 22,      // 'Count of TYPEs; Must be LAST + 1
	TYPE_GENERIC = 255     // 'used for generic handle validation
};

typedef struct _CLIENT_ID {
	ULONG_PTR   UniqueProcess;
	ULONG_PTR   UniqueThread;
} CLIENT_ID;
typedef   CLIENT_ID   *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

void WcharToChar(const wchar_t *wchar, char *chr, int length)
{
	WideCharToMultiByte(CP_ACP, 0, wchar, -1,
		chr, length, NULL, NULL);
}
int GetSystemVersion(char* pSystemVersion)
{
	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		return -1;
	}

	hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hres))
	{
		CoUninitialize();
		return -1;
	}

	IWbemLocator *pLoc = NULL;
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);
	if (FAILED(hres))
	{
		CoUninitialize();
		return -1;
	}

	IWbemServices *pSvc = NULL;
	hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
	if (FAILED(hres))
	{
		pLoc->Release();
		CoUninitialize();
		return -1;
	}

	hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return -1;
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_OperatingSystem"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return -1;
	}

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;
		hr = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
		WcharToChar(vtProp.bstrVal, pSystemVersion, 64);
		VariantClear(&vtProp);
		pclsObj->Release();
	}
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return 0;
}

void LoadDriver(int opr)
{
	if(opr!=0)
		hMyDrv=openDriver();
	else
		uninstallDriver();
}

void RKM(UINT64 Address, PVOID Buffer, SIZE_T Length)
{
	IoControl(hMyDrv ,CTL_CODE_GEN(0x809), &Address, 8, NULL, 0);		//address
	IoControl(hMyDrv ,CTL_CODE_GEN(0x80A), &Length, 8, NULL, 0);		//length
	IoControl(hMyDrv ,CTL_CODE_GEN(0x804), NULL, 0, Buffer, Length);	//get buffer
}

void getPETHREAD(UINT64 tid, PVOID Buffer, SIZE_T Length)
{
	IoControl(hMyDrv, CTL_CODE_GEN(0x801), &tid, 8, NULL, 0);		//address
	IoControl(hMyDrv, CTL_CODE_GEN(0x806), NULL, 0, Buffer, Length);	//get buffer
}

void getWin32THREAD(UINT64 tid, PVOID Buffer, SIZE_T Length)
{
	IoControl(hMyDrv, CTL_CODE_GEN(0x801), &tid, 8, NULL, 0);		//address
	IoControl(hMyDrv, CTL_CODE_GEN(0x807), NULL, 0, Buffer, Length);	//get buffer
}

void WKM(UINT64 Address, PVOID Buffer, SIZE_T Length)
{
	IoControl(hMyDrv ,CTL_CODE_GEN(0x809), &Address, 8, NULL, 0);		//address
	IoControl(hMyDrv ,CTL_CODE_GEN(0x80A), &Length, 8, NULL, 0);		//length
	IoControl(hMyDrv ,CTL_CODE_GEN(0x805), Buffer, Length, NULL, 0);	//set buffer
}

UINT64 GetQWORD(UINT64 address)
{
	UINT64 y=0;
	RKM(address,&y,8);
	return y;
}

UINT32 GetDWORD(UINT64 address)
{
	UINT32 y=0;
	RKM(address,&y,4);
	return y;
}

PUCHAR GetPNbyET(UINT64 ethread)
{
	PUCHAR y = (PUCHAR)malloc(64);
	IoControl(hMyDrv ,CTL_CODE_GEN(0x7FF), &ethread, 8, y, 64);
	return y;
}

/*
lkd> dt win32k!tagsharedinfo
   +0x000 psi              : Ptr64 tagSERVERINFO
   +0x008 aheList          : Ptr64 _HANDLEENTRY
   +0x010 HeEntrySize      : Uint4B
   +0x018 pDispInfo        : Ptr64 tagDISPLAYINFO
   +0x020 ulSharedDelta    : Uint8B
   +0x028 awmControl       : [31] _WNDMSG
   +0x218 DefWindowMsgs    : _WNDMSG
   +0x228 DefWindowSpecMsgs : _WNDMSG

lkd> dt win32k!tagSERVERINFO
   +0x000 dwSRVIFlags      : Uint4B
   +0x008 cHandleEntries   : Uint8B
   +0x010 mpFnidPfn        : [32] Ptr64     int64 
   +0x110 aStoCidPfn       : [7] Ptr64     int64 
   [省略......]
*/

/*win32k!_HANDLEENTRY
   +0x000 phead            : Ptr64 _HEAD
   +0x008 pOwner           : Ptr64 Void
   +0x010 bType            : UChar
   +0x011 bFlags           : UChar
   +0x012 wUniq            : Uint2B*/

typedef struct _HANDLEENTRY
{
	UINT64	phead;
	UINT64	pOwner;
	UCHAR	bType;
	UCHAR	bFlags;
	USHORT	wUniq;
}HANDLEENTRY,*PHANDLEENTRY;

/*
lkd> dt win32k!taghook
   +0x000 head             : _THRDESKHEAD
   +0x028 phkNext          : Ptr64 tagHOOK
   +0x030 iHook            : Int4B
   +0x038 offPfn           : Uint8B
   +0x040 flags            : Uint4B
   +0x044 ihmod            : Int4B
   +0x048 ptiHooked        : Ptr64 tagTHREADINFO
   +0x050 rpdesk           : Ptr64 tagDESKTOP
   +0x058 nTimeout         : Pos 0, 7 Bits
   +0x058 fLastHookHung    : Pos 7, 1 Bit
lkd> dt_THRDESKHEAD
win32k!_THRDESKHEAD
   +0x000 h                : Ptr64 Void
   +0x008 cLockObj         : Uint4B
   +0x010 pti              : Ptr64 tagTHREADINFO
   +0x018 rpdesk           : Ptr64 tagDESKTOP
   +0x020 pSelf            : Ptr64 UChar
*/
typedef struct _HANDLEENTRY15063
{
	PVOID        phead;
	PVOID        tid;
	PVOID        pOwner;
	UCHAR        bType;
	UCHAR        bFlags;
	USHORT        wUniq;
}HANDLEENTRY15063, *PHANDLEENTRY15063;



typedef struct _HOOK_INFO
{
	HANDLE       hHandle;                    //钩子的句柄   句柄是全局的 可以UnhookWindowsHookEx  把钩子卸掉
	PVOID           Unknown1;
	PVOID        Win32Thread;                 //一个指向 win32k!_W32THREAD 结构体的指针
	PVOID         Unknown2;
	PVOID        SelfHook;                   //指向结构体的首地址
	PVOID        NextHook;                   //指向下一个钩子结构体
	int          iHookType;                 //钩子的类型， winuser.h 中有定义
	int            Patch2;
	PVOID        OffPfn;                    //钩子函数的地址偏移，相对于所在模块的偏移
	int          iHookFlags;
	int          iMod;                      //钩子函数做在模块的索引号码，通过查询 WowProcess 结构可以得到模块的基地址。
	PVOID        Win32ThreadHooked;         // ？？？被钩的线程的结构指针，不知道
	//下面还有，省略。。。
} HOOK_INFO, *PHOOK_INFO;

char *GetHookType(int Id)
{
	char *string;
	string=(char*)malloc(32);
	switch(Id)
	{
		case -1:
		{
			strcpy(string,"WH_MSGFILTER");
			break;
		}
		case 0:
		{
			strcpy(string,"WH_JOURNALRECORD");
			break;
		}
		case 1:
		{
			strcpy(string,"WH_JOURNALPLAYBACK");
			break;
		}
		case 2:
		{
			strcpy(string,"WH_KEYBOARD");
			break;
		}
		case 3:
		{
			strcpy(string,"WH_GETMESSAGE");
			break;
		}
		case 4:
		{
			strcpy(string,"WH_CALLWNDPROC");
			break;
		}
		case 5:
		{
			strcpy(string,"WH_CBT");
			break;
		}
		case 6:
		{
			strcpy(string,"WH_SYSMSGFILTER");
			break;
		}
		case 7:
		{
			strcpy(string,"WH_MOUSE");
			break;
		}
		case 8:
		{
			strcpy(string,"WH_HARDWARE");
			break;
		}
		case 9:
		{
			strcpy(string,"WH_DEBUG");
			break;
		}
		case 10:
		{
			strcpy(string,"WH_SHELL");
			break;
		}
		case 11:
		{
			strcpy(string,"WH_FOREGROUNDIDLE");
			break;
		}
		case 12:
		{
			strcpy(string,"WH_CALLWNDPROCRET");
			break;
		}
		case 13:
		{
			strcpy(string,"WH_KEYBOARD_LL");
			break;
		}
		case 14:
		{
			strcpy(string,"WH_MOUSE_LL");
			break;
		}
		default:
		{
			strcpy(string,"????");
			break;
		}
	}
	return string;
}

char *GetHookFlagString(int Flag)
{
	char *string;
	string=(char*)malloc(8);
	if(Flag==1 || Flag==3)
		strcpy(string,"Global");
	else
		strcpy(string,"Local");
	return string;
}

void EnumMsgHook()
{
	int i=0;
	UINT64 pgSharedInfo = (UINT64)GetProcAddress(GetModuleHandleA("user32.dll"), "gSharedInfo");
	printf("%I64d\n", pgSharedInfo);

	UINT64 phe = GetQWORD(pgSharedInfo+8);	//+0x008 aheList          : Ptr64 _HANDLEENTRY
	UINT64 count = GetQWORD(GetQWORD(pgSharedInfo)+8);
	HANDLEENTRY heStruct={0};
	HOOK_INFO Hook={0};
	for(i=0;i<count;i++)
	{
		memcpy(&heStruct,(PVOID)(phe + i*sizeof(HANDLEENTRY)),sizeof(HANDLEENTRY));
		if(heStruct.bType==5)
		{
			RKM(heStruct.phead,&Hook,sizeof(HOOK_INFO));
			printf("hHandle:     0x%llx\n",Hook.hHandle);
			printf("iHookFlags:  %s\n",GetHookFlagString(Hook.iHookFlags));
			printf("iHookType:   %s\n",GetHookType(Hook.iHookType));
			printf("OffPfn:      0x%llx\n",Hook.OffPfn);
			printf("ETHREAD:     0x%llx\n",GetQWORD((UINT64)(Hook.Win32Thread)));
			printf("ProcessName: %s\n\n",GetPNbyET(GetQWORD((UINT64)(Hook.Win32Thread))));
		}
	}
}
void MsgHook15063(int version)
{
	typedef NTSTATUS(NTAPI* pNtQIT)(HANDLE ProcessHandle, LONG ThreadInformationClass, PVOID ThreadInformation,
		ULONG ThreadInformationLength, PULONG ReturnLength OPTIONAL);
	static pNtQIT NtQueryInformationThread = NULL;
	UINT64 WIN32THREADINFO_APHKSTART_OFFSET;
	if (version > 15063) {
		WIN32THREADINFO_APHKSTART_OFFSET = 0x370;//可能因为版本号不同而改变的硬编码
	}
	else {
		WIN32THREADINFO_APHKSTART_OFFSET = 0x310;//可能因为版本号不同而改变的硬编码
	}
	UINT64 pgSharedInfo = (UINT64)GetProcAddress(LoadLibraryW(L"user32.dll"), "gSharedInfo");
	UINT64 pHE = GetQWORD(pgSharedInfo + 8);//信息结构体基址
	UINT64 sHE = GetQWORD(pgSharedInfo + 16);//信息结构体长度
	UINT64 i, count = GetQWORD(GetQWORD(pgSharedInfo) + 8);//信息结构体数量
	NTSTATUS ntStatus;
	if (NtQueryInformationThread == NULL) {
		NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
			"NtQueryInformationThread");
	}
	if (NtQueryInformationThread == NULL) {
		printf("%s(): cannot found NtQueryInformationThread()\n", __FUNCTION__);
		return;
	}
	//typedef PVOID(NTAPI *HMValidateHandleFn)(HANDLE Handle, int hType);
	//HMValidateHandleFn HMValidateHandle = 0;
	//HMODULE hUser32 = LoadLibraryA("user32.dll");
	//PBYTE pMenuFunc = (PBYTE)GetProcAddress(hUser32, "IsMenu");
	//if (pMenuFunc) {
	//	unsigned int uiHMValidateHandleOffset = 0;
	//	for (unsigned int i = 0; i < 0x1000; i++) {
	//		BYTE* test = pMenuFunc + i;
	//		if (*test == 0xE8) {
	//			uiHMValidateHandleOffset = i + 1;
	//			break;
	//		}
	//	}
	//	if (uiHMValidateHandleOffset == 0) {
	//		printf("%s():Failed to find offset of HMValidateHandle from location of 'IsMenu'\n", __FUNCTION__);
	//	}
	//	else {
	//		unsigned int addr = *(unsigned int *)(pMenuFunc + uiHMValidateHandleOffset);
	//		unsigned int offset = ((unsigned int)pMenuFunc - (unsigned int)hUser32) + addr;
	//		//The +11 is to skip the padding bytes as on Windows 10 these aren't nops
	//		HMValidateHandle = (HMValidateHandleFn)((ULONG_PTR)hUser32 + offset + 11);
	//	}
	//}
	//else {
	//	printf("%s(): GetProcAddress(GetModuleHandle) fail\n", __FUNCTION__);
	//}
	//printf("HMValidateHandle=%lld\n", HMValidateHandle);
	unordered_map<DWORD, DWORD> tids;
	printf("count=%ld\n", count);
	for (i = 0; i < count; i++)
	{
		LOOP:PHANDLEENTRY15063 pInfo = (PHANDLEENTRY15063)(pHE + i * sHE);
		if (!IsBadReadPtr((const void*)pInfo, sHE))
		{
			if (pInfo->bType == TYPE_HOOK)
			{
				DWORD tid = (DWORD)(pInfo->tid);
				if (tids.find(tid) != tids.end()) {
					i += 1;
					goto LOOP;
				}
				else {
					tids.insert({tid,tid});
				}
				PVOID Win32Thread;

				//PVOID ethread;
				//getPETHREAD((UINT64)tid, &ethread, sizeof(ethread));
				//printf("ethread=0x%llx\n", ethread);
				//RKM((UINT64)ethread + 0x1c8, &Win32Thread, sizeof(Win32Thread));
				//printf("Win32Thread=0x%llx\n", Win32Thread);

				getWin32THREAD((UINT64)tid, &Win32Thread, sizeof(Win32Thread));
				HANDLE ht = OpenThread(THREAD_ALL_ACCESS, 0, tid);
				if (ht)
				{
					HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
					UINT32 ThreadBasicInformation = 0;
					THREAD_BASIC_INFORMATION bi;
					ntStatus = NtQueryInformationThread(hThread, ThreadBasicInformation, &bi, sizeof(bi), NULL);
					if (ntStatus != 0) {
						printf("%s(): NtQueryInformationThread() fail\n", __FUNCTION__);
						return;
					}

					UINT64 teb = (UINT64)bi.TebBaseAddress;
					DWORD pid = bi.ClientId.UniqueProcess;
					LONG k;
					struct _HOOK_INFO* thkp[16] = { 0 };
					SIZE_T pW32Thread = 0;
					RKM((UINT64)Win32Thread, &pW32Thread, sizeof(thkp));
					RKM((UINT64)pW32Thread + WIN32THREADINFO_APHKSTART_OFFSET, thkp, sizeof(thkp));

					for (k = WH_MIN; k < WH_MAX; k++)
					{
						if (thkp[k + 1])
						{
							struct _HOOK_INFO thk = { 0 };
							RKM((UINT64)(thkp[k + 1]), &thk, sizeof(thk));
							if (thk.hHandle != 0) {
								printf("tid:         %ld\n", tid);
								printf("pid          %ld\n", pid);
								printf("hHandle:     0x%llx\n", thk.hHandle);
								printf("SelfHook:    0x%llx\n", thk.SelfHook);
								printf("NextHook:    0x%llx\n", thk.NextHook);
								printf("iHookFlags:  0x%llx\n", thk.iHookFlags);
								printf("iHookFlags:  %s\n", GetHookFlagString(thk.iHookFlags));
								printf("iHookType:   0x%llx\n", thk.iHookType);
								printf("iHookType:   %s\n", GetHookType(thk.iHookType));
								printf("OffPfn:      0x%llx\n", thk.OffPfn);
								printf("ETHREAD:     0x%llx\n", GetQWORD((UINT64)(thk.Win32Thread)));
								HANDLE pHandle = OpenProcess(
									PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
									FALSE,
									pid /* This is the PID, you can find one from windows task manager */
								);
								if (pHandle)
								{
									CHAR Buffer[MAX_PATH] = {0};
									DWORD size = MAX_PATH;
									if (QueryFullProcessImageNameA(pHandle, 0, Buffer, &size))
									{
										printf("ProcessName: %s\n\n", Buffer);
									}
									else {
										printf("ProcessName: %s\n\n", GetPNbyET(GetQWORD((UINT64)(thk.Win32Thread))));
									}
									CloseHandle(pHandle);
								}
								else {
									printf("ProcessName: %s\n\n", GetPNbyET(GetQWORD((UINT64)(thk.Win32Thread))));
								}

							}
							while (thk.NextHook != 0) {
								PVOID next = thk.NextHook;
								memset(&thk, 0, sizeof(thk));
								RKM((UINT64)(next), &thk, sizeof(thk));
								if (thk.hHandle != 0) {
									printf("tid:         %ld\n", tid);
									printf("pid          %ld\n", pid);
									printf("hHandle:     0x%llx\n", thk.hHandle);
									printf("SelfHook:    0x%llx\n", thk.SelfHook);
									printf("NextHook:    0x%llx\n", thk.NextHook);
									printf("iHookFlags:  0x%llx\n", thk.iHookFlags);
									printf("iHookFlags:  %s\n", GetHookFlagString(thk.iHookFlags));
									printf("iHookType:   0x%llx\n", thk.iHookType);
									printf("iHookType:   %s\n", GetHookType(thk.iHookType));
									printf("OffPfn:      0x%llx\n", thk.OffPfn);
									printf("ETHREAD:     0x%llx\n", GetQWORD((UINT64)(thk.Win32Thread)));
									HANDLE pHandle = OpenProcess(
										PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
										FALSE,
										pid /* This is the PID, you can find one from windows task manager */
									);
									if (pHandle)
									{
										CHAR Buffer[MAX_PATH] = { 0 };
										DWORD size = MAX_PATH;
										if (QueryFullProcessImageNameA(pHandle, 0, Buffer, &size))
										{
											printf("ProcessName: %s\n\n", Buffer);
										}
										else {
											printf("ProcessName: %s\n\n", GetPNbyET(GetQWORD((UINT64)(thk.Win32Thread))));
										}
										CloseHandle(pHandle);
									}
									else {
										printf("ProcessName: %s\n\n", GetPNbyET(GetQWORD((UINT64)(thk.Win32Thread))));
									}
								}
							}
						}
					}
					CloseHandle(ht);
				}
				else {
					printf("%s(): OpenThread() fail\n", __FUNCTION__);
				}
			}
		}
	}
}
int getversion() {
	int version = 0;
	char pVersion[20];
	int retcode = 0;
	const char* s = "10.0.";
	char *p;
	retcode = GetSystemVersion(pVersion);
	if (retcode == 0)
	{
		p = strstr(pVersion, s);
		if (p != NULL)
		{
			version = atoi(pVersion + 5);
			return version;
		}
		else {
			return 0;
		}
	}
	else {
		printf("%s(): cannot GetSystemVersion\n", __FUNCTION__);
		return -1;
	}
}
int main()
{
	LoadDriver(1);
	int version = getversion();
	if(version != -1){
		//EnumMsgHook();
		MsgHook15063(version);
	}
	LoadDriver(0);
}