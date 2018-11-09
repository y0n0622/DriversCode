NtAlpcSendWaitReceivePort(IN  HANDLE PortHandle,
                                        IN    DWORD SendFlags,
                                        IN    PLPC_MESSAGE SendMessage OPTIONAL,
                                        IN    PVOID InMessageBuffer OPTIONAL,
                                        OUT    PLPC_MESSAGE ReceiveBuffer OPTIONAL,
                                        OUT    PULONG ReceiveBufferSize OPTIONAL,
                                        OUT    PVOID OutMessageBuffer OPTIONAL,
                                            PLARGE_INTEGER Timeout OPTIONAL )
//其中第三个参数PLPC_MESSAGE SendMessage 保存很多有用信息。
typedef struct _LPC_MESSAGE {
    USHORT                  DataLength;
    USHORT                  Length;
    USHORT                  MessageType;
    USHORT                  DataInfoOffset;
    CLIENT_ID               ClientId;
    ULONG                   MessageId;
    ULONG                   CallbackId;
} LPC_MESSAGE, *PLPC_MESSAGE;
//这个结构大体是这个原型，在wrk中是
typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        LPC_CLIENT_ID ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    };
    ULONG MessageId;
    union {
        LPC_SIZE_T ClientViewSize;          // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    };
//  UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;