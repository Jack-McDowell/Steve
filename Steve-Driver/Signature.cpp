#include "Signature.h"

#include "ntifs.h"

#include "Generic.h"

typedef NTSTATUS(*PFN_PROCESS_STACK_LOCATION)(
	PEPROCESS Process,
	ULONG_PTR StackAddress,
	ULONG_PTR ReturnAddress,
	PVOID Context);

EXTERN_C PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

_Success_(NT_SUCCESS(return))
NTSTATUS ComputeJA3(
	_In_reads_(ClientHelloSize) PVOID ClientHello,
	ULONG ClientHelloSize,
	_Out_writes_(sizeof(MD5)) PMD5 OutJA3)
{
	RtlZeroMemory(OutJA3, sizeof(MD5));

	return STATUS_SUCCESS;
}

_Success_(NT_SUCCESS(return))
NTSTATUS ComputeJA3s(
	_In_reads_(ServerHelloSize) PVOID ServerHello,
	ULONG ServerHelloSize,
	_Out_writes_(sizeof(MD5)) PMD5 OutJA3s)
{
	RtlZeroMemory(OutJA3s, sizeof(MD5));

	return STATUS_SUCCESS;
}

_Success_(NT_SUCCESS(return))
NTSTATUS SignatureUpdateServer(
	_In_reads_(StreamDataSize) PVOID StreamData,
	ULONG StreamDataSize,
	_Out_ PSIGNATURE Signature)
{
	return ComputeJA3s(StreamData, StreamDataSize, &Signature->JA3s);
}

_Success_(NT_SUCCESS(return))
static NTSTATUS TraceUserStack(
	_In_ HANDLE ThreadId,
	PFN_PROCESS_STACK_LOCATION StackLocationCallback,
	_Inout_ PVOID CallbackContext)
{

}

_Success_(NT_SUCCESS(return))
static NTSTATUS ProcessStackLocation(
	PEPROCESS Process,
	ULONG_PTR StackAddress,
	ULONG_PTR ReturnAddress,
	_Out_ PVOID Context)
{

}

_Success_(NT_SUCCESS(return))
static NTSTATUS GetClientIdFromMeta(
	_In_ PVOID MetaContext,
	_Out_ PCLIENT_ID Client)
{

}

_Success_(NT_SUCCESS(return))
static NTSTATUS SignatureFillSendingContext(
	_In_ PVOID MetaContext,
	_Out_ PSIGNATURE Signature)
{
	NTSTATUS Status;
	CLIENT_ID CallerClient;
	PEPROCESS CallerProcess;

	CallerProcess = NULL;

	Status = GetClientIdFromMeta(MetaContext, &CallerClient);
	ExitAndLogOnFailure(Status, TraceUserStack(), Exit);

	Signature->Pid = HandleToUlong(CallerClient.UniqueProcess);
	Signature->Tid = HandleToUlong(CallerClient.UniqueThread);

	/* Get the process's image name by lookup up the EPROCESS and querying that */
	Status = PsLookupProcessByProcessId(CallerClient.UniqueProcess, &CallerProcess);
	ExitAndLogOnFailure(Status, PsLookupProcessByProcessId(), Exit);
	
	strncpy(
		Signature->ProcessName, 
		PsGetProcessImageFileName(CallerProcess), 
		sizeof(Signature->ProcessName));
	
	/* Walk the thread's stack and look for the responsible module */
	Status = TraceUserStack(
		CallerClient.UniqueThread,
		ProcessStackLocation,
		Signature);
	ExitAndLogOnFailure(Status, TraceUserStack(), Exit);

Exit:
	if(CallerProcess) {
		ObDereferenceObject(CallerProcess);
	}

	return Status;
}

_Success_(NT_SUCCESS(return))
static NTSTATUS SignatureFillNetworkContext(
	_In_ PVOID MetaContext,
	_Out_ PSIGNATURE Signature)
{

}

_Success_(NT_SUCCESS(return))
NTSTATUS SignatureCreate(
	_In_reads_(StreamDataSize) PVOID StreamData,
	ULONG StreamDataSize,
	_In_ PVOID MetaContext,
	_Out_ PSIGNATURE Signature)
{
	NTSTATUS Status;

	Status = SignatureFillSendingContext(MetaContext, Signature);
	ExitAndLogOnFailure(Status, SignatureFillSendingContext(), Exit);
	
	Status = SignatureFillNetworkContext(MetaContext, Signature);
	ExitAndLogOnFailure(Status, SignatureFillNetworkContext(), Exit);

	Status = ComputeJA3(StreamData, StreamDataSize, &Signature->JA3);
	ExitAndLogOnFailure(Status, ComputeJA3(), Exit);

Exit:
	return Status;
}