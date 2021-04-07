/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_messageHookDriver,
    0xe1206eaf,0xafd0,0x4a81,0xbf,0x50,0xfa,0xf9,0x5b,0xee,0x03,0x65);
// {e1206eaf-afd0-4a81-bf50-faf95bee0365}
