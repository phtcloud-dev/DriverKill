#include <ntifs.h>
#include <windef.h>

// 控制器
#define IOCTL_IO_Killer CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Proc);
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS proc);

DWORD dw = 0;
DWORD backb = 0;
// 卸载驱动执行
VOID UnDriver(PDRIVER_OBJECT pDriver)
{
	PDEVICE_OBJECT pDev;                                        // 用来取得要删除设备对象
	UNICODE_STRING SymLinkName;                                 // 局部变量symLinkName
	pDev = pDriver->DeviceObject;
	IoDeleteDevice(pDev);                                       // 调用IoDeleteDevice用于删除设备
	RtlInitUnicodeString(&SymLinkName, L"\\??\\FKDriverKill");     // 初始化字符串将symLinkName定义成需要删除的符号链接名称
	IoDeleteSymbolicLink(&SymLinkName);                         // 调用IoDeleteSymbolicLink删除符号链接
}

// 创建设备连接
NTSTATUS CreateDriverObject(IN PDRIVER_OBJECT pDriver)
{
	NTSTATUS Status;
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING DriverName;
	UNICODE_STRING SymLinkName;

	// 创建设备名称字符串
	RtlInitUnicodeString(&DriverName, L"\\Device\\FKDriverKill");
	Status = IoCreateDevice(pDriver, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);

	// 指定通信方式为缓冲区
	pDevObj->Flags |= DO_BUFFERED_IO;

	// 创建符号链接
	RtlInitUnicodeString(&SymLinkName, L"\\??\\FKDriverKill");
	Status = IoCreateSymbolicLink(&SymLinkName, &DriverName);
	return STATUS_SUCCESS;
}

// 创建回调函数
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;          // 返回成功
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);        // 指示完成此IRP
	return STATUS_SUCCESS;                           // 返回成功
}

// 关闭回调函数
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;          // 返回成功
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);        // 指示完成此IRP
	return STATUS_SUCCESS;                           // 返回成功
}

void ZwKillProcess(ULONG pid)
{
	HANDLE ProcessHandle = NULL;
	OBJECT_ATTRIBUTES obj;
	CLIENT_ID cid = { 0 };
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;
	ntStatus = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &obj, &cid);
	if (NT_SUCCESS(ntStatus))
	{
		ZwTerminateProcess(ProcessHandle, 0);
		ZwClose(ProcessHandle);
		backb = 1;
	}
	ZwClose(ProcessHandle);
}

void MemKillProcess(HANDLE pid)
{
	PEPROCESS proc = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PKAPC_STATE pApcState = NULL;


	PsLookupProcessByProcessId((HANDLE)pid, &proc);
	if (proc == 0)
	{

		return;
	}

	//KeAttachProcess(proc);
	//KeDetachProcess()  等都已经过时.所以使用新的
	pApcState = (PKAPC_STATE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PKAPC_STATE), '1111');
	if (NULL == pApcState)
	{
		ObDereferenceObject(proc);
		return;
	}
	__try {
		KeStackAttachProcess(proc, pApcState);
		//KeAttachProcess(proc);
		for (int i = 0x10000; i < 0x20000000; i += PAGE_SIZE)
		{
			__try
			{
				memset((PVOID)i, 0, PAGE_SIZE);
			}
			__except (1)
			{
				;        //内部处理异常
			}
		}
		KeUnstackDetachProcess(pApcState);
		//KeDetachProcess();
		ObDereferenceObject(proc);
		return;
	}
	__except (1)
	{
		KeUnstackDetachProcess(pApcState);
		ObDereferenceObject(proc);
	}


	return;
}

PEPROCESS GetEprocessByPid(HANDLE pid)
{
	//根据PID 返回PEPROCESS
	PEPROCESS pEpro = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	ntStatus = PsLookupProcessByProcessId(pid, &pEpro);
	if (NT_SUCCESS(ntStatus))
	{
		return pEpro;
	}
	return NULL;
}

void TestSusPendProcess(ULONG pid)
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = GetEprocessByPid((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsSuspendProcess(pCurrentEprocess);
		ObDereferenceObject(pCurrentEprocess);
	}

}

// 主控制器,用于判断R3发送的控制信号
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;

	// 获得IRP里的关键数据
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	// 获取控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	// 输入和输出的缓冲区（DeviceIoControl的InBuffer和OutBuffer都是它）
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;

	// EXE发送传入数据的BUFFER长度（DeviceIoControl的nInBufferSize）
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;

	// EXE接收传出数据的BUFFER长度（DeviceIoControl的nOutBufferSize）
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	// 对不同控制信号的处理流程
	switch (uIoControlCode)
	{
		
	case IOCTL_IO_Killer:
	{

		
		memcpy(&dw, pIoBuffer, sizeof(DWORD));


		


		TestSusPendProcess(dw);
		ZwKillProcess(dw);
		MemKillProcess(dw);

		
		memcpy(pIoBuffer, &backb, sizeof(DWORD));
		backb = 0;
		
		status = STATUS_SUCCESS;
		break;
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = uOutSize;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
	}

	
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;

	
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}




// 入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegistryPath)
{
	
	CreateDriverObject(pDriver);

	pDriver->DriverUnload = UnDriver;                               
	pDriver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;         
	pDriver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;           
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;  

	return STATUS_SUCCESS;
}