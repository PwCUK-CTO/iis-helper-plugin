"""
Description: IDA Python plugin to help analyse native IIS modules
Author: @BitsOfBinary
License:
Copyright 2023 PwC International Limited
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

IIS_CLASSES = """class  IWpfSettings;

typedef enum GLOBAL_NOTIFICATION_STATUS
{
    GL_NOTIFICATION_CONTINUE,                  // continue processing
                                               // for notification
    GL_NOTIFICATION_HANDLED                    // finish processing for
                                               // notification
};

typedef enum CACHE_OPERATION
{
    CACHE_OPERATION_RETRIEVE,
    CACHE_OPERATION_ADD,
    CACHE_OPERATION_DELETE,
    CACHE_OPERATION_FLUSH_PREFIX,
    CACHE_OPERATION_ENUM
};

class IHttpEventProvider
{
 public:
    virtual
    void
    SetErrorStatus(
        HRESULT             hrError
    );
};

class ICustomNotificationProvider : public IHttpEventProvider
{
 public:
    virtual
    PCWSTR
    QueryNotificationType(
        void *
    );
};

class IHttpStoredContext
{
 public:
    virtual
    void
    CleanupStoredContext(
        void *
    );
};

typedef void* HTTP_MODULE_ID;

class IHttpModuleContextContainer
{
 public:
    virtual
    IHttpStoredContext *
    GetModuleContext(
        HTTP_MODULE_ID       moduleId
    );

    virtual
    HRESULT
    SetModuleContext(
        IHttpStoredContext * ppStoredContext,
        HTTP_MODULE_ID       moduleId
    );  
};

class IDispensedHttpModuleContextContainer : public IHttpModuleContextContainer
{
public:
    virtual
    void
    ReleaseContainer(
        void *
    );
};

class IHttpPerfCounterInfo
{
 public:
    virtual
    void
    IncrementCounter(
        DWORD               dwCounterIndex,
        DWORD               dwValue = 1
    );

    virtual
    void
    DecrementCounter(
        DWORD               dwCounterIndex,
        DWORD               dwValue = 1
    );
};

class IHttpApplication
{
 public:
    virtual
    PCWSTR
    GetApplicationPhysicalPath(
        void *
    );

    virtual
    PCWSTR
    GetApplicationId(
        void *
    );

    virtual
    PCWSTR
    GetAppConfigPath(
        void *
    );

    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );
};

class IHttpUrlInfo
{
 public:
    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );

    virtual
    BOOL
    IsFrequentlyHit(
        void *
    );
};

class IScriptMapInfo
{
 public:
    virtual
    PCWSTR
    GetPath(
        void *
    );

    virtual
    PCSTR
    GetAllowedVerbs(
        void *
    );

    virtual
    PCWSTR
    GetModules(
        DWORD *         pcchModules = NULL
    );

    virtual
    PCWSTR
    GetScriptProcessor(
        DWORD *         pcchScriptProcessor = NULL
    );

    virtual
    PCWSTR
    GetManagedType(
        DWORD *         pcchManagedType = NULL
    );

    virtual
    BOOL
    GetAllowPathInfoForScriptMappings(
        void *
    );

    virtual
    DWORD
    GetRequiredAccess(
        void *
    );

    virtual
    DWORD
    GetResourceType(
        void *
    );

    virtual
    BOOL
    GetIsStarScriptMap(
        void *
    );

    virtual
    DWORD
    GetResponseBufferLimit(
        void *
    );

    virtual
    PCWSTR
    GetName(
        void *
    );
};

class IHttpTokenEntry;

class IMetadataInfo
{
 public:
    virtual
    PCWSTR
    GetMetaPath(
        void *
    );

    virtual
    PCWSTR
    GetVrPath(
        void *
    );

    virtual
    IHttpTokenEntry *
    GetVrToken(
        void *
    );

    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );
};

class IHttpRequest
{
 public:
    virtual
    HTTP_REQUEST *
    GetRawHttpRequest(
        void *
    );

    virtual
    const HTTP_REQUEST *
    GetRawHttpRequest(
        void *
    );

    virtual
    PCSTR
    GetHeader(
        PCSTR                pszHeaderName,
        USHORT *            pcchHeaderValue = NULL
    );

    virtual
    PCSTR
    GetHeader(
        HTTP_HEADER_ID      ulHeaderIndex,
        USHORT *            pcchHeaderValue = NULL
    );

    virtual
    HRESULT
    SetHeader(
        PCSTR                pszHeaderName,
        PCSTR                pszHeaderValue,
        USHORT               cchHeaderValue,
        BOOL                 fReplace
    );

    virtual
    HRESULT
    SetHeader(
        HTTP_HEADER_ID       ulHeaderIndex,
        PCSTR                pszHeaderValue,
        USHORT               cchHeaderValue,
        BOOL                 fReplace
    );

    virtual
    HRESULT
    DeleteHeader(
        PCSTR                pszHeaderName
    );

    virtual
    HRESULT
    DeleteHeader(
        HTTP_HEADER_ID       ulHeaderIndex
    );

    virtual
    PCSTR
    GetHttpMethod(
        void *
    );

    virtual
    HRESULT
    SetHttpMethod(
        PCSTR                pszHttpMethod
    );

    virtual
    HRESULT
    SetUrl(
        PCWSTR               pszUrl,
        DWORD                cchUrl,
        BOOL                 fResetQueryString
    );

    virtual
    HRESULT
    SetUrl(
        PCSTR                pszUrl,
        DWORD                cchUrl,
        BOOL                 fResetQueryString
    );

    virtual
    BOOL
    GetUrlChanged(
        void *
    );

    virtual
    PCWSTR
    GetForwardedUrl(
        void *
    );

    virtual
    PSOCKADDR
    GetLocalAddress(
        void *
    );

    virtual
    PSOCKADDR
    GetRemoteAddress(
        void *
    );

    virtual
    HRESULT
    ReadEntityBody(
        void *              pvBuffer,
        DWORD               cbBuffer,
        BOOL                fAsync,
        DWORD *             pcbBytesReceived,
        BOOL *              pfCompletionPending = NULL
    );

    virtual
    HRESULT
    InsertEntityBody(
        void *               pvBuffer,
        DWORD                cbBuffer
    );

    virtual
    DWORD
    GetRemainingEntityBytes(
        void *
    );

    virtual
    void
    GetHttpVersion(
        USHORT *            pMajorVersion,
        USHORT *            pMinorVersion
    );

    virtual
    HRESULT
    GetClientCertificate(
        HTTP_SSL_CLIENT_CERT_INFO **    ppClientCertInfo,
        BOOL *                          pfClientCertNegotiated
    );

    virtual
    HRESULT
    NegotiateClientCertificate(
        BOOL                 fAsync,
        BOOL *              pfCompletionPending = NULL
    );

    virtual
    DWORD
    GetSiteId(
        void *
    );

    virtual
    HRESULT
    GetHeaderChanges(
        DWORD   dwOldChangeNumber,
        DWORD * pdwNewChangeNumber,
        PCSTR   knownHeaderSnapshot[HttpHeaderRequestMaximum],
        DWORD * pdwUnknownHeaderSnapshot,
        PCSTR **ppUnknownHeaderNameSnapshot,
        PCSTR **ppUnknownHeaderValueSnapshot,
        DWORD   diffedKnownHeaderIndices[HttpHeaderRequestMaximum+1],
        DWORD * pdwDiffedUnknownHeaders,
        DWORD **ppDiffedUnknownHeaderIndices
    );
};

class IHttpRequest2 : public IHttpRequest
{
 public:
    virtual
    HRESULT
    GetChannelBindingToken(
        PBYTE *     ppToken,
        DWORD *     pTokenSize
    );
};

class IHttpCachePolicy
{
 public:
    virtual
    HTTP_CACHE_POLICY *
    GetKernelCachePolicy(
        void *
    );

    virtual
    void
    SetKernelCacheInvalidatorSet(
        void *
    );

    virtual
    HTTP_CACHE_POLICY *
    GetUserCachePolicy(
        void *
    );

    virtual
    HRESULT
    AppendVaryByHeader(
        PCSTR   pszHeader
    );

    virtual
    PCSTR
    GetVaryByHeaders(
        void *
    );

    virtual
    HRESULT
    AppendVaryByQueryString(
        PCSTR   pszParam
    );

    virtual
    PCSTR
    GetVaryByQueryStrings(
        void *
    );

    virtual
    HRESULT
    SetVaryByValue(
        PCSTR   pszValue
    );

    virtual
    PCSTR
    GetVaryByValue(
        void *
    );

    virtual
    BOOL
    IsUserCacheEnabled(
        void *
    );

    virtual
    void
    DisableUserCache(
        void *
    );

    virtual
    BOOL
    IsCached(
        void *
    );

    virtual
    void
    SetIsCached(
        void *
    );

    virtual
    BOOL
    GetKernelCacheInvalidatorSet(
        void *
    );
};

class IHttpCachePolicy2 : public IHttpCachePolicy
{
 public:
    virtual
    BOOL
    IsForceUpdateSet(
        void *
    );

    virtual
    void
    SetForceUpdate(
        void *
    );
};

class IHttpResponse
{
 public:
    virtual
    HTTP_RESPONSE *
    GetRawHttpResponse(
        void *
    );

    virtual
    const HTTP_RESPONSE *
    GetRawHttpResponse(
        void *
    );

    virtual
    IHttpCachePolicy *
    GetCachePolicy(
        void *
    );

    virtual
    HRESULT
    SetStatus(
        USHORT                   statusCode,
        PCSTR                    pszReason,
        USHORT                   uSubStatus,
        HRESULT                  hrErrorToReport = S_OK,
        IAppHostConfigException *pException = NULL,
        BOOL                     fTrySkipCustomErrors = FALSE
    );

    virtual
    HRESULT
    SetHeader(
        PCSTR                pszHeaderName,
        PCSTR                pszHeaderValue,
        USHORT               cchHeaderValue,
        BOOL                 fReplace
    );

    virtual
    HRESULT
    SetHeader(
        HTTP_HEADER_ID       ulHeaderIndex,
        PCSTR                pszHeaderValue,
        USHORT               cchHeaderValue,
        BOOL                 fReplace
    );

    virtual
    HRESULT
    DeleteHeader(
        PCSTR                pszHeaderName
    );

    virtual
    HRESULT
    DeleteHeader(
        HTTP_HEADER_ID       ulHeaderIndex
    );

    virtual
    PCSTR
    GetHeader(
        PCSTR                pszHeaderName,
        USHORT *            pcchHeaderValue = NULL
    );

    virtual
    PCSTR
    GetHeader(
        HTTP_HEADER_ID      ulHeaderIndex,
        USHORT *            pcchHeaderValue = NULL
    );

    virtual
    void
    Clear(
        void *
    );

    virtual
    void
    ClearHeaders(
        void *
    );

    virtual
    void
    SetNeedDisconnect(
        void *
    );

    virtual
    void
    ResetConnection(
        void *
    );

    virtual
    void
    DisableKernelCache(
        ULONG reason = 9
    );

    virtual
    BOOL
    GetKernelCacheEnabled(
        void *
    );

    virtual
    void
    SuppressHeaders(
        void *
    );

    virtual
    BOOL
    GetHeadersSuppressed(
        void *
    );

    virtual
    HRESULT
    Flush(
        BOOL                 fAsync,
        BOOL                 fMoreData,
        DWORD *             pcbSent,
        BOOL *              pfCompletionExpected = NULL
    );

    virtual
    HRESULT
    Redirect(
        PCSTR                pszUrl,
        BOOL                 fResetStatusCode = TRUE,
        BOOL                 fIncludeParameters = FALSE
    );

    virtual
    HRESULT
    WriteEntityChunkByReference(
        HTTP_DATA_CHUNK *    pDataChunk,
        LONG                 lInsertPosition = -1
    );

    virtual
    HRESULT
    WriteEntityChunks(
        HTTP_DATA_CHUNK *   pDataChunks,
        DWORD               nChunks,
        BOOL                fAsync,
        BOOL                fMoreData,
        DWORD *             pcbSent,
        BOOL *              pfCompletionExpected = NULL
    );

    virtual
    void
    DisableBuffering(
        void *
    );

    virtual
    void
    GetStatus(
        USHORT *                    pStatusCode,
        USHORT *                    pSubStatus = NULL,
        PCSTR *                     ppszReason = NULL,
        USHORT *                    pcchReason = NULL,
        HRESULT *                   phrErrorToReport = NULL,
        PCWSTR *                    ppszModule = NULL,
        DWORD *                     pdwNotification = NULL,
        IAppHostConfigException **  ppException = NULL,
        BOOL *                      pfTrySkipCustomErrors = NULL
    );

    virtual
    HRESULT
    SetErrorDescription(
        PCWSTR                       pszDescription,
        DWORD                        cchDescription,
        BOOL                         fHtmlEncode = TRUE
    );

    virtual
    PCWSTR
    GetErrorDescription(
        DWORD *                     pcchDescription = NULL
    );

    virtual
    HRESULT
    GetHeaderChanges(
        DWORD   dwOldChangeNumber,
        DWORD * pdwNewChangeNumber,
        PCSTR   knownHeaderSnapshot[HttpHeaderResponseMaximum],
        DWORD * pdwUnknownHeaderSnapshot,
        PCSTR **ppUnknownHeaderNameSnapshot,
        PCSTR **ppUnknownHeaderValueSnapshot,
        DWORD   diffedKnownHeaderIndices[HttpHeaderResponseMaximum+1],
        DWORD * pdwDiffedUnknownHeaders,
        DWORD **ppDiffedUnknownHeaderIndices
    );

    virtual
    void
    CloseConnection(
        void *
    );
};

class IHttpUser
{
 public:
    virtual
    PCWSTR
    GetRemoteUserName(
        void *
    );

    virtual
    PCWSTR
    GetUserName(
        void *
    );

    virtual 
    PCWSTR
    GetAuthenticationType(
        void *
    );

    virtual
    PCWSTR
    GetPassword(
        void *
    );  

    virtual
    HANDLE
    GetImpersonationToken(
        void *
    );

    virtual
    HANDLE
    GetPrimaryToken(
        void *
    );

    virtual
    void
    ReferenceUser(
        void *
    );

    virtual
    void
    DereferenceUser(
        void *
    );

    virtual
    BOOL
    SupportsIsInRole(
        void *
    );

    virtual
    HRESULT
    IsInRole(
        PCWSTR  pszRoleName,
        BOOL *  pfInRole
    );

    virtual
    PVOID
    GetUserVariable(
        PCSTR    pszVariableName
    );
};

#define HTTP_USER_VARIABLE_SID              "SID"
#define HTTP_USER_VARIABLE_CTXT_HANDLE      "CtxtHandle"
#define HTTP_USER_VARIABLE_CRED_HANDLE      "CredHandle"

class IHttpConnectionStoredContext : public IHttpStoredContext
{
 public:
    virtual
    void
    NotifyDisconnect(
        void *
    );
};

class IHttpConnectionModuleContextContainer : public IHttpModuleContextContainer
{
 public:
    virtual
    IHttpConnectionStoredContext *
    GetConnectionModuleContext(
        HTTP_MODULE_ID       moduleId
    );

    virtual
    HRESULT
    SetConnectionModuleContext(
        IHttpConnectionStoredContext *   ppStoredContext,
        HTTP_MODULE_ID                   moduleId
    );  
};

class IHttpConnection
{
 public:
    virtual
    BOOL
    IsConnected(
        void *
    );

    virtual
    void *
    AllocateMemory(
        DWORD               cbAllocation
    );

    virtual
    IHttpConnectionModuleContextContainer *
    GetModuleContextContainer(
        void *
    );
};

enum HTTP_CONTEXT_INTERFACE_VERSION
{
};

typedef enum REQUEST_NOTIFICATION_STATUS{  
   RQ_NOTIFICATION_CONTINUE,  
   RQ_NOTIFICATION_PENDING,  
   RQ_NOTIFICATION_FINISH_REQUEST  
};  

class IHttpTraceContext
{
public:
    virtual
    HRESULT
    GetTraceConfiguration(
        HTTP_TRACE_CONFIGURATION *  pHttpTraceConfiguration
    );
    
    virtual    
    HRESULT
    SetTraceConfiguration(
        HTTP_MODULE_ID              moduleId,
        HTTP_TRACE_CONFIGURATION *  pHttpTraceConfiguration,
        DWORD                       cHttpTraceConfiguration = 1
    );

    virtual
    HRESULT
    RaiseTraceEvent(
        HTTP_TRACE_EVENT * pTraceEvent 
    );

    virtual
    LPCGUID
    GetTraceActivityId(
    );

    virtual
    HRESULT
    QuickTrace(
        PCWSTR   pszData1,
        PCWSTR   pszData2 = NULL,
        HRESULT  hrLastError = S_OK,
        UCHAR    Level = 4
    );
};

class IHttpFileInfo;

class IHttpSite;

class CHttpModule;

class IHttpContext
{
 public:
    virtual
    IHttpSite *
    GetSite(
        void *
    );

    virtual
    IHttpApplication *
    GetApplication(
        void *
    );

    virtual
    IHttpConnection *
    GetConnection(
        void *
    );

    virtual
    IHttpRequest *
    GetRequest(
        void *
    );

    virtual
    IHttpResponse *
    GetResponse(
        void *
    );

    virtual
    BOOL
    GetResponseHeadersSent(
        void *
    );

    virtual
    IHttpUser *
    GetUser(
        void *
    );

    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );

    virtual
    void
    IndicateCompletion(
        REQUEST_NOTIFICATION_STATUS     notificationStatus
    );

    virtual
    HRESULT
    PostCompletion(
        DWORD                cbBytes
    );

    virtual
    void
    DisableNotifications(
        DWORD                dwNotifications,
        DWORD                dwPostNotifications
    );

    virtual
    BOOL
    GetNextNotification(
        REQUEST_NOTIFICATION_STATUS status,
        DWORD *                     pdwNotification,
        BOOL *                      pfIsPostNotification,
        CHttpModule **              ppModuleInfo,
        IHttpEventProvider **       ppRequestOutput
    );

    virtual
    BOOL
    GetIsLastNotification(
        REQUEST_NOTIFICATION_STATUS status
    );    

    virtual
    HRESULT
    ExecuteRequest(
        BOOL                 fAsync,
        IHttpContext *       pHttpContext,
        DWORD                dwExecuteFlags,
        IHttpUser *          pHttpUser,
        BOOL *              pfCompletionExpected = NULL
    );                      

    virtual
    DWORD
    GetExecuteFlags(
        void *
    );

    virtual
    HRESULT
    GetServerVariable(
        PCSTR               pszVariableName,
        PCWSTR * ppszValue,
        DWORD *       pcchValueLength
    );

    virtual
    HRESULT
    GetServerVariable(
        PCSTR               pszVariableName,
        PCSTR * ppszValue,
        DWORD * pcchValueLength
    );

    virtual
    HRESULT
    SetServerVariable(
        PCSTR               pszVariableName,
        PCWSTR              pszVariableValue
    );

    virtual
    void *
    AllocateRequestMemory(
        DWORD                cbAllocation
    );

    virtual
    IHttpUrlInfo *
    GetUrlInfo(
        void *
    );

    virtual
    IMetadataInfo *
    GetMetadata(
        void *
    );

    virtual
    PCWSTR
    GetPhysicalPath(
        DWORD *         pcchPhysicalPath = NULL
    );

    virtual
    PCWSTR
    GetScriptName(
        DWORD *         pcchScriptName = NULL
    );

    virtual
    PCWSTR
    GetScriptTranslated(
        DWORD *         pcchScriptTranslated = NULL
    );

    virtual
    IScriptMapInfo *
    GetScriptMap(
        void *
    );

    virtual
    void
    SetRequestHandled(
        void *
    );

    virtual
    IHttpFileInfo *
    GetFileInfo(
        void *
    );

    virtual
    HRESULT
    MapPath(
        PCWSTR   pszUrl,
        PWSTR    pszPhysicalPath,
        DWORD *  pcbPhysicalPath
    );

    virtual
    HRESULT
    NotifyCustomNotification(
        ICustomNotificationProvider *   pCustomOutput,
        BOOL *                      pfCompletionExpected
    );

    virtual
    IHttpContext *
    GetParentContext(
        void *
    );

    virtual
    IHttpContext *
    GetRootContext(
        void *
    );

    virtual
    HRESULT
    CloneContext(
        DWORD                dwCloneFlags,
        IHttpContext **     ppHttpContext
    );

    virtual
    HRESULT
    ReleaseClonedContext(
        void *
    );

    virtual
    HRESULT
    GetCurrentExecutionStats(
        DWORD * pdwNotification,
        DWORD * pdwNotificationStartTickCount = NULL,
        PCWSTR *  ppszModule = NULL,
        DWORD * pdwModuleStartTickCount = NULL,
        DWORD * pdwAsyncNotification = NULL,
        DWORD * pdwAsyncNotificationStartTickCount = NULL
    );

    virtual
    IHttpTraceContext *
    GetTraceContext(
        void *
    );

    virtual
    HRESULT
    GetServerVarChanges(
        DWORD       dwOldChangeNumber,
        DWORD *     pdwNewChangeNumber,
        DWORD *     pdwVariableSnapshot,
        PCSTR **    ppVariableNameSnapshot,
        PCWSTR **   ppVariableValueSnapshot,
        DWORD *     pdwDiffedVariables,
        DWORD **    ppDiffedVariableIndices
    );

    virtual
    HRESULT
    CancelIo(
        void *
    );

    virtual
    HRESULT
    MapHandler(
        DWORD               dwSiteId,
        PCWSTR              pszSiteName,
        PCWSTR              pszUrl,
        PCSTR               pszVerb,
        IScriptMapInfo **   ppScriptMap,
        BOOL                fIgnoreWildcardMappings = FALSE
    );

    virtual
    HRESULT
    GetExtendedInterface(
        HTTP_CONTEXT_INTERFACE_VERSION  version,
        PVOID *                         ppInterface
    );
};

class IHttpCacheSpecificData
{
 public:
    virtual
    //IHttpCacheKey *
    void *
    GetCacheKey(
        void *
    );

    virtual
    void
    ReferenceCacheData(
        void *
    );

    virtual
    void
    DereferenceCacheData(
        void *
    );

    virtual
    void
    ResetTTL(
        void *
    );

    virtual
    void
    DecrementTTL(
        BOOL    *pfTTLExpired
    );

    virtual
    void
    SetFlushed(
        void *
    );

    virtual
    BOOL
    GetFlushed(
        void *
    );
};

class IHttpCacheKey
{
 public:
    virtual
    DWORD
    GetHash(
        void *
    );

    virtual
    PCWSTR
    GetCacheName(
        void *
    );

    virtual
    bool
    GetIsEqual(
        IHttpCacheKey *         pCacheCompareKey
    );

    virtual
    bool
    GetIsPrefix(
        IHttpCacheKey *         pCacheCompareKey
    );

    virtual
    void
    Enum(
        IHttpCacheSpecificData *
    );
};

class IHttpSite
{
 public:
    virtual
    DWORD
    GetSiteId(
        void *
    );

    virtual
    PCWSTR
    GetSiteName(
        void *
    );

    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );

    virtual
    IHttpPerfCounterInfo *
    GetPerfCounterInfo(
        void *
    );
};

class IHttpFileMonitor
{
 public:
    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );

    virtual
    void
    DereferenceFileMonitor(
        void *
    );
};

class IHttpFileInfo : public IHttpCacheSpecificData
{
 public:
    virtual
    DWORD
    GetAttributes(
        void *
    );

    virtual
    void
    GetSize(
        ULARGE_INTEGER *        pliSize
    );

    virtual
    const BYTE *
    GetFileBuffer(
        void *
    );

    virtual
    HANDLE
    GetFileHandle(
        void *
    );

    virtual
    PCWSTR
    GetFilePath(
        void *
    );

    virtual
    PCSTR
    GetETag(
        USHORT *                pcchETag = NULL
    );

    virtual
    void
    GetLastModifiedTime(
        FILETIME *              pFileTime
    );

    virtual
    PCSTR
    GetLastModifiedString(
        void *
    );

    virtual
    BOOL
    GetHttpCacheAllowed(
        DWORD *     pSecondsToLive
    );

    virtual
    HRESULT
    AccessCheck(
        HANDLE                   hUserToken,
        PSID                     pUserSid
    );

    virtual
    HANDLE
    GetVrToken(
        void *
    );

    virtual
    PCWSTR
    GetVrPath(
        void *
    );

    virtual
    IHttpModuleContextContainer *
    GetModuleContextContainer(
        void *
    );

    virtual
    BOOL
    CheckIfFileHasChanged(
        HANDLE                   hUserToken
    );
};
 
class IHttpTokenEntry : public IHttpCacheSpecificData
{
 public:
    virtual
    HANDLE
    GetImpersonationToken(
        void *
    );

    virtual
    HANDLE
    GetPrimaryToken(
        void *
    );

    virtual
    PSID
    GetSid(
        void *
    );
};

enum HTTP_SERVER_INTERFACE_VERSION
{
    HTTP_SERVER_INTERFACE_V2
};

class IHttpServer
{
 public:
    virtual
    BOOL
    IsCommandLineLaunch(
        void *
    );

    virtual
    PCWSTR
    GetAppPoolName(
        void *
    );

    virtual
    HRESULT
    AssociateWithThreadPool(
        HANDLE                              hHandle,
        LPOVERLAPPED_COMPLETION_ROUTINE     completionRoutine
    );

    virtual
    void
    IncrementThreadCount(
        void *
    );

    virtual
    void
    DecrementThreadCount(
        void *
    );

    virtual
    void
    ReportUnhealthy(
        PCWSTR               pszReasonString,
        HRESULT              hrReason
    );

    virtual
    void
    RecycleProcess(
        PCWSTR                  pszReason
    );

    virtual
    IAppHostAdminManager *
    GetAdminManager(
        void *
    );

    virtual
    HRESULT
    GetFileInfo(
        PCWSTR               pszPhysicalPath,
        HANDLE               hUserToken,
        PSID                 pSid,
        PCWSTR               pszChangeNotificationPath,
        HANDLE               hChangeNotificationToken,
        BOOL                 fCache,
        IHttpFileInfo **     ppFileInfo,
        IHttpTraceContext *  pHttpTraceContext = NULL
    );

    virtual
    HRESULT
    FlushKernelCache(
        PCWSTR               pszUrl
    );

    virtual
    HRESULT
    DoCacheOperation(
        CACHE_OPERATION              cacheOperation,
        IHttpCacheKey *              pCacheKey,
        IHttpCacheSpecificData **   ppCacheSpecificData,
        IHttpTraceContext *         pHttpTraceContext = NULL
    );

    virtual
    GLOBAL_NOTIFICATION_STATUS
    NotifyCustomNotification(
        ICustomNotificationProvider * pCustomOutput
    );

    virtual
    IHttpPerfCounterInfo *
    GetPerfCounterInfo(
        void *
    );

    virtual
    void
    RecycleApplication(
        PCWSTR                  pszAppConfigPath
    );

    virtual
    void
    NotifyConfigurationChange(
        PCWSTR                  pszPath
    );

    virtual
    void
    NotifyFileChange(
        PCWSTR                  pszFileName
    );

    virtual
    IDispensedHttpModuleContextContainer *
    DispenseContainer(
        void *
    );

    virtual
    HRESULT
    AddFragmentToCache(
        HTTP_DATA_CHUNK *    pDataChunk,
        PCWSTR                  pszFragmentName
    );

    virtual
    HRESULT
    ReadFragmentFromCache(
        PCWSTR          pszFragmentName,
        BYTE *      pvBuffer,
        DWORD           cbSize,
        DWORD *     pcbCopied
    );

    virtual
    HRESULT
    RemoveFragmentFromCache(
        PCWSTR          pszFragmentName
    );

    virtual
    HRESULT
    GetWorkerProcessSettings(
        IWpfSettings ** ppWorkerProcessSettings
    );

    virtual
    HRESULT
    GetProtocolManagerCustomInterface(
        PCWSTR       pProtocolManagerDll,
        PCWSTR       pProtocolManagerDllInitFunction,
        DWORD        dwCustomInterfaceId,
        PVOID*      ppCustomInterface
    );

    virtual
    BOOL
    SatisfiesPrecondition(
        PCWSTR          pszPrecondition,
        BOOL *          pfUnknownPrecondition = NULL
    );

    virtual
    IHttpTraceContext *
    GetTraceContext(
        void *
    );

    virtual
    HRESULT
    RegisterFileChangeMonitor(
        PCWSTR                  pszPath,
        HANDLE                  hToken,
        IHttpFileMonitor **     ppFileMonitor
    );

    virtual
    HRESULT
    GetExtendedInterface(
        HTTP_SERVER_INTERFACE_VERSION   version,
        PVOID *                         ppInterface
    );
};

class IHttpServer2 : public IHttpServer
{
 public:

    virtual
    HRESULT
    GetToken(
        PCWSTR              pszUserName,
        PCWSTR              pszPassword,
        DWORD               dwLogonMethod,
        IHttpTokenEntry **  ppTokenEntry,
        PCWSTR              pszDefaultDomain = NULL,
        PSOCKADDR           pSockAddr = NULL,
        IHttpTraceContext * pHttpTraceContext = NULL
    );

    virtual
    PCWSTR
    GetAppPoolConfigFile(
        DWORD * pcchConfigFilePath = NULL
    );

    virtual
    HRESULT
    GetExtendedInterface(
        const GUID &       Version1,
        PVOID              pInput,
        const GUID &       Version2,
        PVOID *     ppOutput
    );
};

class IHttpCompletionInfo
{
 public:
    virtual
    DWORD
    GetCompletionBytes(
        void *
    );

    virtual
    HRESULT
    GetCompletionStatus(
        void *
    );
};

class IAuthenticationProvider : public IHttpEventProvider
{
 public:
    virtual
    void
    SetUser(
        IHttpUser *          pUser
    );
};

class IMapHandlerProvider : public IHttpEventProvider
{
 public:
    virtual
    HRESULT
    SetScriptName(
        PCWSTR                  pszScriptName,
        DWORD                   cchScriptName
    );

    virtual
    void
    SetScriptMap(
        IScriptMapInfo *     pScriptMap
    );

    virtual
    void
    SetFileInfo(
        IHttpFileInfo *      pFileInfo
    );
};

class IMapPathProvider : public IHttpEventProvider
{
 public:
    virtual
    PCWSTR
    GetUrl(
    );

    virtual
    PCWSTR
    GetPhysicalPath(
    );

    virtual
    HRESULT
    SetPhysicalPath(
        PCWSTR pszPhysicalPath,
        DWORD  cchPhysicalPath
    );
};

class ISendResponseProvider : public IHttpEventProvider
{
 public:
    virtual
    BOOL
    GetHeadersBeingSent(
        void *
    );

    virtual
    DWORD
    GetFlags(
        void *
    );

    virtual
    void
    SetFlags(
        DWORD dwFlags
    );

    virtual
    HTTP_LOG_DATA *
    GetLogData(
        void *
    );

    virtual
    HRESULT
    SetLogData(
        HTTP_LOG_DATA *pLogData
    );

    virtual
    BOOL
    GetReadyToLogData(
        void *
    );
};

class IReadEntityProvider : public IHttpEventProvider
{
 public:
    virtual
    void
    GetEntity(
        PVOID *             ppBuffer,
        DWORD *             pcbData,
        DWORD *             pcbBuffer
    );

    virtual
    void
    SetEntity(
        PVOID            pBuffer,
        DWORD               cbData,
        DWORD               cbBuffer
    );
};

class IPreBeginRequestProvider : public IHttpEventProvider
{
 public:
    virtual
    IHttpContext *
    GetHttpContext(
        void *
    );
};

class IHttpApplicationProvider : public IHttpEventProvider
{
 public:
    virtual
    IHttpApplication *
    GetApplication(
        void *
    );
};

typedef IHttpApplicationProvider    IHttpApplicationStartProvider;

class IHttpModuleFactory;

class IHttpApplicationResolveModulesProvider : public IHttpApplicationProvider
{
 public:
    virtual 
    HRESULT
    RegisterModule(
        HTTP_MODULE_ID       parentModuleId,
        IHttpModuleFactory * pModuleFactory,
        PCWSTR               pszModuleName,
        PCWSTR               pszModuleType,
        PCWSTR               pszModulePreCondition,
        DWORD                dwRequestNotifications,
        DWORD                dwPostRequestNotifications
    );

    virtual
    HRESULT
    SetPriorityForRequestNotification(
        PCWSTR               pszModuleName,
        DWORD                dwRequestNotification,
        PCWSTR               pszPriorityAlias
    );
};

typedef IHttpApplicationProvider   IHttpApplicationStopProvider;

class IGlobalRSCAQueryProvider : public IHttpEventProvider
{
 public:
    virtual
    PCWSTR
    GetFunctionName(
        void *
    );

    virtual
    PCWSTR
    GetFunctionParameters(
        void *
    );

    virtual
    HRESULT
    GetOutputBuffer(
        DWORD       cbBuffer,
        BYTE ** ppbBuffer
    );

    virtual
    HRESULT
    ResizeOutputBuffer(
        DWORD          cbNewBuffer,
        DWORD          cbBytesToCopy,
        BYTE ** ppbBuffer
    );

    virtual
    void
    SetResult(
        DWORD       cbData,
        HRESULT     hr
    );
};

class IGlobalStopListeningProvider : public IHttpEventProvider
{
 public:
    virtual
    BOOL
    DrainRequestsGracefully(
        void *
    );
};

class ICacheProvider : public IHttpEventProvider
{
 public:
    virtual
    CACHE_OPERATION
    GetCacheOperation(
        void *
    );

    virtual
    IHttpCacheKey *
    GetCacheKey(
        void *
    );

    virtual
    IHttpCacheSpecificData *
    GetCacheRecord(
        void *
    );

    virtual
    void
    SetCacheRecord(
        IHttpCacheSpecificData *    pCacheRecord
    );

    virtual
    IHttpTraceContext *
    GetTraceContext(
        void *
    );
};

class IGlobalConfigurationChangeProvider : public IHttpEventProvider
{
 public:
    virtual
    PCWSTR
    GetChangePath(
        void *
    );
};

class IGlobalFileChangeProvider : public IHttpEventProvider
{
public:
    virtual
    PCWSTR
    GetFileName(
        void *
    );

    virtual
    IHttpFileMonitor *
    GetFileMonitor(
        void *
    );
};

class IGlobalTraceEventProvider : public IHttpEventProvider
{
 public:
    virtual
    HRESULT
    GetTraceEvent(
        HTTP_TRACE_EVENT ** ppTraceEvent
    );

    virtual
    BOOL
    CheckSubscription(
        HTTP_MODULE_ID   ModuleId    
    );     

    virtual
    HRESULT 
    GetCurrentHttpRequestContext(
        IHttpContext ** ppHttpContext
    );
};

class IGlobalThreadCleanupProvider : public IHttpEventProvider
{
public:
    virtual
    IHttpApplication *
    GetApplication(
        void *
    );
};

class IGlobalApplicationPreloadProvider : public IHttpEventProvider
{
public:
    virtual
    HRESULT
    CreateContext(
        IHttpContext **     ppHttpContext
    );

    virtual
    HRESULT
    ExecuteRequest(
        IHttpContext *       pHttpContext,
        IHttpUser *          pHttpUser
    );
};

class CHttpModule
{
public:
    // RQ_BEGIN_REQUEST

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnBeginRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostBeginRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_AUTHENTICATE_REQUEST

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnAuthenticateRequest(
        IHttpContext *                       pHttpContext,
        IAuthenticationProvider *            pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostAuthenticateRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_AUTHORIZE_REQUEST

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnAuthorizeRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostAuthorizeRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_RESOLVE_REQUEST_CACHE

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnResolveRequestCache(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostResolveRequestCache(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_MAP_REQUEST_HANDLER

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnMapRequestHandler(
        IHttpContext *                       pHttpContext,
        IMapHandlerProvider *                pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostMapRequestHandler(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_ACQUIRE_REQUEST_STATE

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnAcquireRequestState(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostAcquireRequestState(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_PRE_EXECUTE_REQUEST_HANDLER

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPreExecuteRequestHandler(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostPreExecuteRequestHandler(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_EXECUTE_REQUEST_HANDLER

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnExecuteRequestHandler(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostExecuteRequestHandler(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_RELEASE_REQUEST_STATE

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnReleaseRequestState(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostReleaseRequestState(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_UPDATE_REQUEST_CACHE

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnUpdateRequestCache(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostUpdateRequestCache(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_LOG_REQUEST

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnLogRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostLogRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_END_REQUEST

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnEndRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnPostEndRequest(
        IHttpContext *                       pHttpContext,
        IHttpEventProvider *                 pProvider
    );

    // RQ_SEND_RESPONSE

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnSendResponse(
        IHttpContext *                       pHttpContext,
        ISendResponseProvider *              pProvider
    );

    // RQ_MAP_PATH

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnMapPath(
        IHttpContext *                       pHttpContext,
        IMapPathProvider *                   pProvider
    );

    // RQ_READ_ENTITY

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnReadEntity(
        IHttpContext *                       pHttpContext,
        IReadEntityProvider *                pProvider
    );

    // RQ_CUSTOM_NOTIFICATION

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnCustomRequestNotification(
        IHttpContext *                       pHttpContext,
        ICustomNotificationProvider *        pProvider
    );

    // Completion

    virtual 
    REQUEST_NOTIFICATION_STATUS
    OnAsyncCompletion(
        IHttpContext *                       pHttpContext,
        DWORD                                dwNotification,
        BOOL                                 fPostNotification,
        IHttpEventProvider *                 pProvider,
        IHttpCompletionInfo *                pCompletionInfo        
    );

    virtual
    void
    Dispose(
        void *
    );

 protected:

    CHttpModule();

    virtual
    ~CHttpModule();
};

class CGlobalModule
{
 public:

    // GL_STOP_LISTENING

    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalStopListening(
        IGlobalStopListeningProvider  *  pProvider
    );

    // GL_CACHE_CLEANUP
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalCacheCleanup(
        void *
    );

    // GL_CACHE_OPERATION
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalCacheOperation(
        ICacheProvider  *  pProvider
    );

    // GL_HEALTH_CHECK
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalHealthCheck(
        void *
    );

    // GL_CONFIGURATION_CHANGE
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalConfigurationChange(
        IGlobalConfigurationChangeProvider  *  pProvider
    );

    // GL_FILE_CHANGE 
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalFileChange(
        IGlobalFileChangeProvider *  pProvider
    );

    // GL_PRE_BEGIN_REQUEST 
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalPreBeginRequest(
        IPreBeginRequestProvider  *  pProvider
    );

    // GL_APPLICATION_START 
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalApplicationStart(
        IHttpApplicationStartProvider  *  pProvider
    );

    // GL_APPLICATION_RESOLVE_MODULES
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalApplicationResolveModules(
        IHttpApplicationResolveModulesProvider  *  pProvider
    );

    // GL_APPLICATION_STOP

    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalApplicationStop(
        IHttpApplicationStopProvider *   pProvider
    );

    // GL_RSCA_QUERY
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalRSCAQuery(
        IGlobalRSCAQueryProvider  *  pProvider
    );

    // GL_TRACE_EVENT
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalTraceEvent(
        IGlobalTraceEventProvider  *  pProvider
    );

    // GL_CUSTOM_NOTIFICATION
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalCustomNotification(
        ICustomNotificationProvider *    pProvider
    );

    virtual
    void
    Terminate(
        void *
    );

    // GL_THREAD_CLEANUP
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalThreadCleanup(
        IGlobalThreadCleanupProvider *    pProvider
    );

    // GL_APPLICATION_PRELOAD
    
    virtual 
    GLOBAL_NOTIFICATION_STATUS
    OnGlobalApplicationPreload(
        IGlobalApplicationPreloadProvider *    pProvider
    );

};

class IModuleAllocator
{
 public:
    virtual
    void *
    AllocateMemory(
        DWORD                    cbAllocation
    );
};

class IHttpModuleFactory
{
 public:
    virtual
    HRESULT
    GetHttpModule(
        CHttpModule **          ppModule, 
        IModuleAllocator *      pAllocator
    );

    virtual
    void
    Terminate(
        void *
    );
};

class IHttpModuleRegistrationInfo
{
 public:
    virtual 
    PCWSTR
    GetName(
        void *
    );

    virtual 
    HTTP_MODULE_ID
    GetId(
        void *
    );

    virtual 
    HRESULT
    SetRequestNotifications(
        IHttpModuleFactory * pModuleFactory,
        DWORD                dwRequestNotifications,
        DWORD                dwPostRequestNotifications
    );

    virtual 
    HRESULT
    SetGlobalNotifications(
        CGlobalModule *      pGlobalModule,
        DWORD                dwGlobalNotifications
    );

    virtual
    HRESULT
    SetPriorityForRequestNotification(
        DWORD                dwRequestNotification,
        PCWSTR               pszPriority
    );

    virtual
    HRESULT
    SetPriorityForGlobalNotification(
        DWORD                dwGlobalNotification,
        PCWSTR               pszPriority
    );
};"""

IIS_CLASSES_UPDATE = """class IHttpCacheSpecificData
{
 public:
    virtual
    IHttpCacheKey *
    GetCacheKey(
        void *
    );

    virtual
    void
    ReferenceCacheData(
        void *
    );

    virtual
    void
    DereferenceCacheData(
        void *
    );

    virtual
    void
    ResetTTL(
        void *
    );

    virtual
    void
    DecrementTTL(
        BOOL    *pfTTLExpired
    );

    virtual
    void
    SetFlushed(
        void *
    );

    virtual
    BOOL
    GetFlushed(
        void *
    );
};"""