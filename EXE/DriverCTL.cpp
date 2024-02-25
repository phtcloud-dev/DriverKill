#include <iostream>
#include <Windows.h>
#include <winioctl.h>
#include <windows.h> 
#include <winsvc.h> 
#include <conio.h> 
#include <stdio.h>

#define DRIVER_NAME L"DriverKill"  
#define DRIVER_PATH L".\\DriverKill.sys"

BOOL DriverLoad(PCWSTR DriverName, PCWSTR DriverPath)
{
    WCHAR szDriverFullPath[MAX_PATH] = { 0 };
    GetFullPathNameW(DriverPath, MAX_PATH, szDriverFullPath, NULL);
    std::wcout << szDriverFullPath << std::endl;
    SC_HANDLE hServiceMgr = NULL; 
    hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == hServiceMgr)
    {
        return FALSE;
    }




    //3 获取NT驱动程序服务句柄
    SC_HANDLE hServiceDDK = NULL; // NT驱动程序服务句柄
    hServiceDDK = CreateServiceW(
        hServiceMgr,
        DriverName,
        DriverName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        szDriverFullPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (NULL == hServiceDDK)
    {
        DWORD dwErr = GetLastError();
        if (dwErr != ERROR_IO_PENDING && dwErr != ERROR_SERVICE_EXISTS)
        {
            return FALSE;
        }
    }



    hServiceDDK = OpenServiceW(hServiceMgr, DriverName, SERVICE_ALL_ACCESS);

    // go 开始运行驱动
    bool btmp = StartService(hServiceDDK, NULL, NULL);
    if (!btmp)
    {
        DWORD dwErr = GetLastError();
        if (dwErr != ERROR_SERVICE_ALREADY_RUNNING)
        {


            return FALSE;
        }
    }

    if (hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return TRUE;
}
void UnLoadDriver(PCWSTR lpszDriverName)
{
    SC_HANDLE hServiceMgr = OpenSCManagerW(0, 0, SC_MANAGER_ALL_ACCESS);
    SC_HANDLE hServiceDDK = OpenServiceW(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
    SERVICE_STATUS SvrStatus;
    ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrStatus);
    DeleteService(hServiceDDK);
    if (hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
}
#define IOCTL_IO_Killer CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)



void Start(DWORD processId) {
    HANDLE hDevice = CreateFileA("\\\\.\\FKDriverKill", GENERIC_READ | GENERIC_WRITE, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[!]Error!\n");
        printf("[!]Code: %d\n", GetLastError());
        CloseHandle(hDevice);
    }
    else
    {

        DWORD input = processId, output = 0, ref_len = 0;
        DeviceIoControl(hDevice, IOCTL_IO_Killer, &input, sizeof(input), &output, sizeof(output), &ref_len, 0);

        if (output == 1) {
            printf("[*]Successful\n");
        }
        else {
            printf("[!]Error PID Not Found\n");
        }
        CloseHandle(hDevice);
    }
}

void Test(DWORD processId) {
    HANDLE hDevice = CreateFileA("\\\\.\\FKDriverKill", GENERIC_READ | GENERIC_WRITE, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[!]Driver Load Error!\n");
        printf("[!]Make sure that the driver file is in the running directory!\n");
        printf("[!]You can use \"cd\" to change running directory!\n");
        printf("[!]You can Try Turn Off AV!\n");
        CloseHandle(hDevice);
        UnLoadDriver(DRIVER_NAME);
    }
    else {
        printf("[*]Driver Loaded!\n");
    }
    CloseHandle(hDevice);
}

void help(){
    printf("[*]Made By Phtcloud 2024\n");
    printf("[*]DriverKill R3 Demo Beta V1.0\n");
    printf("[-]Usage: DriverKill.exe [load/unload/pid] [ProcessID]\n");
    printf("[-]Use: \"DriverKill.exe load\" to load Driver\n");
    printf("[-]Use: \"DriverKill.exe unload\" to unload Driver\n");
    printf("[-]Use: \"DriverKill.exe pid [pid]\" to kill process\n");
    printf("[-]Error Code:2 --- Driver is not loading use \"DriverKill.exe load\" to fix (need Administrator)\n");
    system("pause");
}

int main(int argc, char* argv[])
{

    if (argc > 1) {
        if (strcmp(argv[1], "load") == 0) {
            BOOL isAdmin = FALSE;
            SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
            PSID administratorsGroup;
            if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
                if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
                    isAdmin = FALSE;
                }
                FreeSid(administratorsGroup);
            }

            if (isAdmin) {
                DriverLoad(DRIVER_NAME, DRIVER_PATH);
                Test(1);
            }
            else {
                printf("[!]This Command need Administrator mode\n");
            }
        }
        else if (strcmp(argv[1], "pid") == 0 && argc > 2) {
            DWORD processId = atoi(argv[2]); 
            Start(processId);
        }
        else if (strcmp(argv[1], "unload") == 0) {
            BOOL isAdmin = FALSE;
            SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
            PSID administratorsGroup;
            if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
                if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
                    isAdmin = FALSE;
                }
                FreeSid(administratorsGroup);
            }

            if (isAdmin) {
                UnLoadDriver(DRIVER_NAME);
            }
            else {
                printf("[!]This Command need Administrator mode\n");
            }
        }
        else {
            help();
        }
    }
    else {
        help();
    }

    return 0;
}
