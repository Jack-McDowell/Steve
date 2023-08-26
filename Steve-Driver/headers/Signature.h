#pragma once

#include <ntifs.h>

enum class IP_VERSION : bool {
    V4,
    V6
};

struct IP {
    IP_VERSION Version;
    
    union {
        ULONG AddrV4;
        USHORT AddrV6[8];
    };
};

typedef struct _MD5 {
    UCHAR Hash[16];
} MD5, *PMD5;

typedef struct _SIGNATURE {
    BOOLEAN Valid;

    IP SourceIP;
    USHORT SourcePort;
    
    IP DestinationIP;
    USHORT DestinationPort;

    MD5 JA3;
    MD5 JA3s;

    ULONG Pid;
    ULONG Tid;

    CHAR ProcessName[32];
    CHAR ModuleName[32];
} SIGNATURE, *PSIGNATURE;

bool SignatureInBlacklist(_In_ PSIGNATURE Signature);

_Success_(NT_SUCCESS(return))
NTSTATUS SignatureCreate(
    _In_reads_(StreamDataSize) PVOID StreamData,
    ULONG StreamDataSize,
    _In_ PVOID MetaContext,
    _Out_ PSIGNATURE Signature);

_Success_(NT_SUCCESS(return))
NTSTATUS SignatureUpdateServer(
    _In_reads_(StreamDataSize) PVOID StreamData,
    ULONG StreamDataSize,
    _Out_ PSIGNATURE Signature);