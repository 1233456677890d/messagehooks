#include <ntddk.h>

#define dprintf				DbgPrint

#define	DEVICE_NAME			L"\\Device\\EnumMsgHook64"
#define LINK_NAME			L"\\DosDevices\\EnumMsgHook64"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\EnumMsgHook64"

#define IOCTL_READ_KRNL_MM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)	//read kernel
#define IOCTL_MODIFY_KN_MM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)	//write kernel
#define IOCTL_SET_RWKM_ADR	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)	//set address
#define IOCTL_SET_RWKM_LEN	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)	//set length

#define IOCTL_GET_PN_BY_ET	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7FF, METHOD_BUFFERED, FILE_ANY_ACCESS)	//set length

#define IOCTL_SET_RWKM_TID	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)	//set length

#define IOCTL_GET_ETHREAD_BY_TID	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)	//set length
#define IOCTL_GET_WIN32THREAD_BY_TID	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)	//set length
