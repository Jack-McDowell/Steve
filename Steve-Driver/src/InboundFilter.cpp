#include "fwpmk.h"
#include "fwpsk.h"

#include "FlowData.h"
#include "Generic.h"
#include "Signature.h"
#include "Tls.h"

static NTSTATUS CheckTlsServerHello(
    _In_reads_(StreamDataSize) PVOID StreamData,
    ULONG StreamDataSize,
    _Out_ PFILTER_RESULT_DATA Action)
{
    NTSTATUS Status;
    PTLS_HEADER TlsHeader;
    USHORT TlsHeaderLen;

    Status = STATUS_SUCCESS;

    if(StreamDataSize < sizeof(TLS_HEADER)) {
        Action->Result = FILTER_RESULT::NeedMoreData;
        Action->BytesNeeded = sizeof(TLS_HEADER) - StreamDataSize;
        Status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    TlsHeader = (PTLS_HEADER) StreamData;

    if(TlsHeader->Signature != TLS_SIGNATURE) {
        Status = STATUS_INVALID_CONNECTION;
        goto Exit;
    }

    if(TlsHeader->MessageType != TLS_MESSAGE_TYPE_HANDSHAKE) {
        Status = STATUS_INVALID_CONNECTION;
        goto Exit;
    }

    TlsHeaderLen = RtlUshortByteSwap(TlsHeader->ContentLength);
    if(TlsHeaderLen > StreamDataSize) {
        Action->Result = FILTER_RESULT::NeedMoreData;
        Action->BytesNeeded = TlsHeaderLen - StreamDataSize;
        Status = STATUS_BUFFER_TOO_SMALL;
    }

Exit:
    return Status;
}

_Success_(NT_SUCCESS(return) || return == STATUS_MORE_PROCESSING_REQUIRED)
static NTSTATUS HandleInboundPreprocessDecision(
    FLOW_STATE FlowState,
    _Out_ PFILTER_RESULT_DATA Action)
{
    NTSTATUS Status;

    if(ShouldBlockPacket(FlowState)) {
        /* If we have already determined the connection should be blocked,
         * block it. */
        Action->Result = FILTER_RESULT::Block;
        Status = STATUS_SUCCESS;
    }

    else if(InboundStateNeedsProcessing(FlowState)) {
        /* If we have already determined the connection shouldn't be blocked, no
         * further processing is required. */
        Status = STATUS_SUCCESS;
    }

    else if(InboundStateInvalid(FlowState)) {
        Status = STATUS_INVALID_CONNECTION;
    }

    else {
        Status = STATUS_MORE_PROCESSING_REQUIRED;
    }

    return Status;
}

_Success_(NT_SUCCESS(return))
NTSTATUS FilterInboundPacket(
    _In_reads_(StreamDataSize) PVOID StreamData,
    ULONG StreamDataSize,
    _In_opt_ PVOID StreamContext,
    _Out_ PFILTER_RESULT_DATA Action)
{
    NTSTATUS Status;
    PFLOW_CONTEXT Context;

    Status = STATUS_SUCCESS;
    Context = NULL;

    Action->Result = FILTER_RESULT::Allow;

    if(!StreamContext) {
        goto Exit;
    }

    Context = (PFLOW_CONTEXT) StreamContext;
    if(NT_SUCCESS(HandleInboundPreprocessDecision(Context->State, Action))) {
        goto Exit;
    }

    else if(Status != STATUS_MORE_PROCESSING_REQUIRED) {
        ExitAndLogOnFailure(Status, HandleInboundPreprocessDecision(), Exit);
    }

    if(!Context->Signature.Valid) {
        /* We missed the client hello */
        Status = STATUS_FWP_NOT_FOUND;
        goto Exit;
    }

    Status = CheckTlsServerHello(StreamData, StreamDataSize, Action);
    if(Status == STATUS_BUFFER_TOO_SMALL) {
        /* In this case, CheckTlsServerHello has already updated `Action`.
         * Reset status so our state doesn't get set to error */
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    else if(Status == STATUS_INVALID_CONNECTION) {
        /* This means that the packet isn't a server hello. Reset status so
         * our state doesn't get overwritten in the exit handler */
        Status = STATUS_SUCCESS;
        Context->State = FLOW_STATE::NotTLS;
        goto Exit;
    }

    else {
        /* Either we succeeded or experienced an unexpected failure */
        ExitAndLogOnFailure(Status, CheckTlsServerHello(), Exit);
    }

    /* Update JA3s */
    Status = SignatureUpdateServer(StreamData, StreamDataSize, &Context->Signature);
    ExitAndLogOnFailure(Status, SignatureUpdateServer(), Exit);

    if(SignatureInBlacklist(&Context->Signature)) {
        Action->Result = FILTER_RESULT::Block;
        Context->State = FLOW_STATE::Blocked;
        goto Exit;
    } else {
        Context->State = FLOW_STATE::ClientHandshake;
    }

Exit:
    if(!NT_SUCCESS(Status) && Context) {
        Context->State = FLOW_STATE::Error;
    }

    return Status;
}