

#define STRIP(...) __VA_ARGS__
#define DPX(Format) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, STRIP Format);
#define DPF(x) DbgPrint x

#define ExitAndLogOnFailure(NtStatus, FailedAction, ExitLabel) \
    if (!NT_SUCCESS(NtStatus)) {                               \
        DPF((__FUNCTION__ ": %d " #FailedAction " FAIL=%08x\n", __LINE__, NtStatus)); \
        goto ExitLabel;                                        \
    }