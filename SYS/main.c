#include <ntifs.h>
#include <windef.h>

// ������
#define IOCTL_IO_Killer CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Proc);
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS proc);

DWORD dw = 0;
DWORD backb = 0;
// ж������ִ��
VOID UnDriver(PDRIVER_OBJECT pDriver)
{
	PDEVICE_OBJECT pDev;                                        // ����ȡ��Ҫɾ���豸����
	UNICODE_STRING SymLinkName;                                 // �ֲ�����symLinkName
	pDev = pDriver->DeviceObject;
	IoDeleteDevice(pDev);                                       // ����IoDeleteDevice����ɾ���豸
	RtlInitUnicodeString(&SymLinkName, L"\\??\\FKDriverKill");     // ��ʼ���ַ�����symLinkName�������Ҫɾ���ķ�����������
	IoDeleteSymbolicLink(&SymLinkName);                         // ����IoDeleteSymbolicLinkɾ����������
}

// �����豸����
NTSTATUS CreateDriverObject(IN PDRIVER_OBJECT pDriver)
{
	NTSTATUS Status;
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING DriverName;
	UNICODE_STRING SymLinkName;

	// �����豸�����ַ���
	RtlInitUnicodeString(&DriverName, L"\\Device\\FKDriverKill");
	Status = IoCreateDevice(pDriver, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);

	// ָ��ͨ�ŷ�ʽΪ������
	pDevObj->Flags |= DO_BUFFERED_IO;

	// ������������
	RtlInitUnicodeString(&SymLinkName, L"\\??\\FKDriverKill");
	Status = IoCreateSymbolicLink(&SymLinkName, &DriverName);
	return STATUS_SUCCESS;
}

// �����ص�����
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;          // ���سɹ�
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);        // ָʾ��ɴ�IRP
	return STATUS_SUCCESS;                           // ���سɹ�
}

// �رջص�����
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;          // ���سɹ�
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);        // ָʾ��ɴ�IRP
	return STATUS_SUCCESS;                           // ���سɹ�
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
	//KeDetachProcess()  �ȶ��Ѿ���ʱ.����ʹ���µ�
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
				;        //�ڲ������쳣
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
	//����PID ����PEPROCESS
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

// ��������,�����ж�R3���͵Ŀ����ź�
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;

	// ���IRP��Ĺؼ�����
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	// ��ȡ������
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	// ���������Ļ�������DeviceIoControl��InBuffer��OutBuffer��������
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;

	// EXE���ʹ������ݵ�BUFFER���ȣ�DeviceIoControl��nInBufferSize��
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;

	// EXE���մ������ݵ�BUFFER���ȣ�DeviceIoControl��nOutBufferSize��
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	// �Բ�ͬ�����źŵĴ�������
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




// ��ں���
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegistryPath)
{
	
	CreateDriverObject(pDriver);

	pDriver->DriverUnload = UnDriver;                               
	pDriver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;         
	pDriver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;           
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;  

	return STATUS_SUCCESS;
}