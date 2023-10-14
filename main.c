// Stripped down version just to get the DVD Structure response from an OG Xbox game disk on an original xboe console.
// Used an input to emulate DVD authentication in xemu

// All credits to Xbox7887 who pretty much work all this out

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>

#include <hal/debug.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <hal/fileio.h>

#include <nxdk/mount.h>

#include <xboxkrnl/xboxkrnl.h>

#include <SDL.h>

#define GET_CAP 1
// http://www.ioctls.net/
#define IOCTL_SCSI_PASS_THROUGH_DIRECT 0x4D014
#define SCSI_IOCTL_DATA_IN 1  // read data
#define SCSIOP_READ_DVD_STRUCTURE 0xAD // layout + challenge response


SDL_GameController *controller = NULL;

typedef struct _SCSI_PASS_THROUGH_DIRECT
{
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;
_Static_assert(sizeof(SCSI_PASS_THROUGH_DIRECT) == 44, "sizeof(SCSI_PASS_THROUGH_DIRECT) != 44");

#pragma pack(push, scsi, 1)

// scsi command descriptor blocks
typedef union _CDB
{
    // used for reading the dvd structure and other general security-related data
    struct _READ_DVD_STRUCTURE
    {
        UCHAR OperationCode; // 0xAD - SCSIOP_READ_DVD_STRUCTURE
        UCHAR Reserved1 : 5; // offset 0x1
        UCHAR Lun : 3;
        UCHAR RMDBlockNumber[4];   // offset 0x2
        UCHAR LayerNumber;         // offset 0x6
        UCHAR Format;              // offset 0x7
        UCHAR AllocationLength[2]; // offset 0x8
        UCHAR Reserved3 : 6;       // offset 0x10
        UCHAR AGID : 2;
        UCHAR Control; // offset 0x11
    } READ_DVD_STRUCTURE;
} CDB, *PCDB;

// contains regular dvd structure info as well as additional xbox-specific stuff like sigs and challenges
typedef struct _XBOX_DVD_LAYOUT
{
    UCHAR data[1636];
} XBOX_DVD_LAYOUT, *PXBOX_DVD_LAYOUT;
_Static_assert(sizeof(XBOX_DVD_LAYOUT) == 1636, "sizeof(XBOX_DVD_LAYOUT) != 1636");

#pragma pack(pop, scsi)

uint16_t bswap16(uint16_t val)
{
    return (val >> 8) | (val << 8);
}

void reboot()
{
    HalWriteSMBusValue(0x20, 2, 0, 1);
}

void assertOrExit(bool isExpected, const char *format, ...);

int getDvdTrayState()
{
    DWORD state;
    HalReadSMBusValue(0x20, 0x3, 0, &state);
    return state;
}

void ejectDvdTray(bool confirm)
{

    HalWriteSMBusValue(0x20, 0xC, 0, 0);
    Sleep(250);

    if (confirm)
    {
        // wait 5 seconds or until tray state is marked open
        for (int i = 0; i < 50; i++)
        {
            if (getDvdTrayState() == 0x10)
                return;

            Sleep(100);
        }

        assertOrExit(false, "Failed to eject DVD tray! (State 0x%X)\n", getDvdTrayState());
    }
}

void injectDvdTray(bool confirm)
{

    HalWriteSMBusValue(0x20, 0xC, 0, 1);
    Sleep(250);

    if (confirm)
    {
        // wait 30 seconds or until tray state is marked closed with media detected
        for (int i = 0; i < 300; i++)
        {
            if (getDvdTrayState() == 0x60)
                return;

            Sleep(100);
        }

        assertOrExit(false, "Failed to detect DVD media! (State 0x%X)\n", getDvdTrayState());
    }
}

void waitAndExit()
{

    ejectDvdTray(false);

    debugPrint("\nRemove media and press START to restart...");
    do
    {
        SDL_GameControllerUpdate();
    } while (!SDL_GameControllerGetButton(controller, SDL_CONTROLLER_BUTTON_START));

    injectDvdTray(false);

    reboot();
    while (1)
        ;
}

void assertOrExit(bool isExpected, const char *format, ...)
{
    char buffer[512];
    unsigned short len;
    va_list argList;
    va_start(argList, format);
    vsprintf(buffer, format, argList);
    va_end(argList);

    if (!isExpected)
    {
        debugPrint("%s", buffer);
        return waitAndExit();
    }
}

void writeFileBytes(const char *name, const uint8_t *data, uint32_t dataOffset, uint32_t dataLength)
{
    debugPrint("Writing %d bytes to \"%s\"\n", dataLength, name);

    // create the file
    HANDLE handle = CreateFile(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    assertOrExit(handle != INVALID_HANDLE_VALUE, "File creation failure (0x%08X)\n", GetLastError());

    // write to the file
    DWORD bytesWritten;
    NTSTATUS status = WriteFile(handle, data + dataOffset, dataLength, &bytesWritten, NULL);
    NtClose(handle);
    assertOrExit(bytesWritten == dataLength, "File write failure (0x%08X)\n", status);
}

// preps the scsi command passthrough and data structs and returns a pointer to the cdb to be filled out by the caller
PCDB prepScsiCmd(PSCSI_PASS_THROUGH_DIRECT scsi, int transferType, PVOID *data, size_t dataLen)
{
    ZeroMemory(scsi, sizeof(SCSI_PASS_THROUGH_DIRECT));
    ZeroMemory(data, dataLen);
    scsi->Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    scsi->DataIn = transferType;
    scsi->DataBuffer = data;
    scsi->DataTransferLength = dataLen;
    return (PCDB)&scsi->Cdb;
}

// xemu atapi.c cmd_read_dvd_structure 0xAD
NTSTATUS getDvdLayout(PDEVICE_OBJECT cdrom, OUT PXBOX_DVD_LAYOUT layout)
{
    SCSI_PASS_THROUGH_DIRECT scsi_cmd;

    // prep the scsi command
    PCDB read_layout_cdb = prepScsiCmd(&scsi_cmd, SCSI_IOCTL_DATA_IN, (PVOID *)layout, sizeof(XBOX_DVD_LAYOUT));
    read_layout_cdb->READ_DVD_STRUCTURE.OperationCode = SCSIOP_READ_DVD_STRUCTURE;
    *(uint32_t *)&read_layout_cdb->READ_DVD_STRUCTURE.RMDBlockNumber = 0xFFFD02FF;
    read_layout_cdb->READ_DVD_STRUCTURE.LayerNumber = 0xFE;
    read_layout_cdb->READ_DVD_STRUCTURE.Format = 0;
    *(uint16_t *)&read_layout_cdb->READ_DVD_STRUCTURE.AllocationLength = bswap16(sizeof(XBOX_DVD_LAYOUT)); // big endian (assuming this is ran on x86)
    read_layout_cdb->READ_DVD_STRUCTURE.Control = 0xC0;

    // request dvd layout info
    return IoSynchronousDeviceIoControlRequest(IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                               cdrom, &scsi_cmd, sizeof(SCSI_PASS_THROUGH_DIRECT), NULL, 0, NULL, FALSE);
}

void init_sdl()
{
    int status;

    XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

    assertOrExit(SDL_Init(SDL_INIT_GAMECONTROLLER) == STATUS_SUCCESS,
                 "Failed to initialize SDL input\n");

    SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "1");

    for (int i = 0; i < SDL_NumJoysticks(); ++i)
    {
        if (SDL_IsGameController(i))
        {
            controller = SDL_GameControllerOpen(i);
            debugPrint("Using first detected controller for input\n");
            break;
        }
    }

    assertOrExit(controller != NULL, "Couldn't find any joysticks\n");
}

// https://xboxdevwiki.net/DVD_Drive
int main(void)
{

    ANSI_STRING cdrom_name;
    PDEVICE_OBJECT cdrom_device;
    NTSTATUS status;
    bool success;
    SCSI_PASS_THROUGH_DIRECT scsi_cmd;
    XBOX_DVD_LAYOUT dvd_layout;
    init_sdl();

    // dvd eject/inject logic for real hardware
    if (HalDiskModelNumber.Buffer[0] != 'Q')
    { // starts with "QEMU" for now

        // disable reset on eject
        HalWriteSMBusValue(0x20, 0x19, 0, 1);
        Sleep(250);

        debugPrint("Ejecting DVD tray...");
        ejectDvdTray(true);
        debugPrint("done!\n");

        debugPrint("Press A when media is inserted...");
        do
        {
            SDL_GameControllerUpdate();
        } while (!SDL_GameControllerGetButton(controller, SDL_CONTROLLER_BUTTON_A));
        debugPrint("done!\n");

        debugPrint("Injecting DVD tray...");
        injectDvdTray(true);
        debugPrint("done!\n");
    }

    // prep filesystem for dumps
    success = nxMountDrive('C', "\\Device\\Harddisk0\\Partition2");
    assertOrExit(success, "Failed to mount C drive! (0x%08X)\n", GetLastError());
    CreateDirectory("C:\\backup", NULL);

    // get the cdrom device object
    RtlInitAnsiString(&cdrom_name, "\\Device\\CdRom0");
    status = ObReferenceObjectByName(&cdrom_name, 0, &IoDeviceObjectType, 0, (PVOID *)&cdrom_device);
    assertOrExit(status == STATUS_SUCCESS, "Failed to obtain CDROM device object! (0x%08X)\n", status);

    // get the dvd layout
    status = getDvdLayout(cdrom_device, &dvd_layout);
    assertOrExit(status == STATUS_SUCCESS, "Failed to read DVD layout! (0x%08X)\n", status);
    writeFileBytes("C:\\backup\\dvd_layout.bin", (uint8_t *)&dvd_layout, 0, sizeof(XBOX_DVD_LAYOUT));

    waitAndExit();

    return 0;
}
