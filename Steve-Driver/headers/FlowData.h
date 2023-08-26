#pragma once

#include "Signature.h"

enum class FLOW_STATE {

    /*
     * State Transitions (on outbound data): 
     *
     * Stream data is not TLS handshake:          Uninit -> NotTLS
     * Stream data matches blacklist condition:   Uninit -> Blocked
     * Stream data contains client TLS handshake: Uninit -> ClientHandshake
     * Something goes wrong:                      Uninit -> Error
     */
    Uninit,
    /*
     * State Transitions (on inbound data): 
     *
     * Stream data is not TLS handshake:          ClientHandshake -> NotTLS
     * Stream data matches blacklist condition:   ClientHandshake -> Blocked
     * Stream data contains server TLS handshake: ClientHandshake -> Initialized
     * Something goes wrong:                      ClientHandshake -> Error
     */
    ClientHandshake,
    /*
     * This is a terminal state
     */
    Initialized,
    /*
     * State Transitions: 
     *
     * Stream data matches blacklist condition: NotTLS -> Blocked
     * 
     * Generally, neither should happen; this should be a terminal state
     */
    NotTLS,
    /*
     * This is a terminal state
     */
    Blocked,
    /*
     * This is a terminal state
     */
    Error,
};

inline bool OutboundStateNeedsProcessing(FLOW_STATE state) { return state == FLOW_STATE::Uninit; }
inline bool OutboundStateInvalid(FLOW_STATE state) { return state == FLOW_STATE::ClientHandshake; }

inline bool InboundStateNeedsProcessing(FLOW_STATE state) { return state == FLOW_STATE::ClientHandshake; }
inline bool InboundStateInvalid(FLOW_STATE state) { return state == FLOW_STATE::Uninit; }

inline bool ShouldBlockPacket(FLOW_STATE state) { return state == FLOW_STATE::Blocked; }

typedef struct _FLOW_CONTEXT {
    FLOW_STATE State;
    SIGNATURE Signature;
} FLOW_CONTEXT, * PFLOW_CONTEXT;

enum class FILTER_RESULT {
    Allow,
    Block,
    NeedMoreData,
};

typedef struct _FILTER_RESULT_DATA {
    FILTER_RESULT Result;
    ULONG BytesNeeded;
} FILTER_RESULT_DATA, * PFILTER_RESULT_DATA;