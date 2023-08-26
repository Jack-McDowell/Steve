#pragma once

#include "ntifs.h"

#pragma pack(push, 1)
typedef struct _TLS_HEADER {
    UCHAR MessageType;
    USHORT Signature;
    USHORT ContentLength;
} TLS_HEADER, * PTLS_HEADER;
#pragma pack(pop)

#define TLS_MESSAGE_TYPE_HANDSHAKE 0x16
#define TLS_SIGNATURE RtlUshortByteSwap(0x0301)