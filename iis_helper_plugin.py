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

import idc
import ida_typeinf
import ida_srclang
import ida_bytes
import idautils
import ida_funcs
import ida_name
import ida_segment
import ida_hexrays
import idaapi

import iis_helper_classes

class IISHelper:

    cglobalmodule_funcs = [
        "OnGlobalStopListening",
        "OnGlobalCacheCleanup",
        "OnGlobalCacheOperation",
        "OnGlobalHealthCheck",
        "OnGlobalConfigurationChange",
        "OnGlobalFileChange",
        "OnGlobalPreBeginRequest",
        "OnGlobalApplicationStart",
        "OnGlobalApplicationResolveModules",
        "OnGlobalApplicationStop",
        "OnGlobalRSCAQuery",
        "OnGlobalTraceEvent",
        "OnGlobalCustomNotification",
        "Terminate\x00",
        "OnGlobalThreadCleanup",
        "OnGlobalApplicationPreload"
    ]
    
    chttpmodule_funcs = [
        "OnBeginRequest",
        "OnPostBeginRequest",
        "OnAuthenticateRequest",
        "OnPostAuthenticateRequest",
        "OnAuthorizeRequest",
        "OnPostAuthorizeRequest",
        "OnResolveRequestCache",
        "OnPostResolveRequestCache",
        "OnMapRequestHandler",
        "OnPostMapRequestHandler",
        "OnAcquireRequestState",
        "OnPostAcquireRequestState",
        "OnPreExecuteRequestHandler",
        "OnPostPreExecuteRequestHandler",
        "OnExecuteRequestHandler",
        "OnPostExecuteRequestHandler",
        "OnReleaseRequestState",
        "OnPostReleaseRequestState",
        "OnUpdateRequestCache",
        "OnPostUpdateRequestCache",
        "OnLogRequest",
        "OnPostLogRequest",
        "OnEndRequest",
        "OnPostEndRequest",
        "OnSendResponse",
        "OnMapPath",
        "OnReadEntity",
        "OnCustomRequestNotification",
        "OnAsyncCompletion",
        "Dispose\x00"
    ]
    
    cglobalmodule_func_prototypes = {
        "OnGlobalStopListening": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalStopListening(CGlobalModule* this, IGlobalStopListeningProvider* pProvider);",
        "OnGlobalCacheCleanup": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalCacheCleanup(CGlobalModule* this);",
        "OnGlobalCacheOperation": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalCacheOperation(CGlobalModule* this, ICacheProvider* pProvider);",
        "OnGlobalHealthCheck": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalHealthCheck(CGlobalModule* this);",
        "OnGlobalConfigurationChange": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalConfigurationChange(CGlobalModule* this, IGlobalConfigurationChangeProvider* pProvider);",
        "OnGlobalFileChange": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalFileChange(CGlobalModule* this, IGlobalFileChangeProvider* pProvider);",
        "OnGlobalPreBeginRequest": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalPreBeginRequest(CGlobalModule* this, IPreBeginRequestProvider* pProvider);",
        "OnGlobalApplicationStart": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStart(CGlobalModule* this, IHttpApplicationStartProvider* pProvider);",
        "OnGlobalApplicationResolveModules": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationResolveModules(CGlobalModule* this, IHttpApplicationResolveModulesProvider* pProvider);",
        "OnGlobalApplicationStop": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStop(CGlobalModule* this, IHttpApplicationStopProvider* pProvider);",
        "OnGlobalRSCAQuery": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalRSCAQuery(CGlobalModule* this, IGlobalRSCAQueryProvider* pProvider);",
        "OnGlobalTraceEvent": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalTraceEvent(CGlobalModule* this, IGlobalTraceEventProvider* pProvider);",
        "OnGlobalCustomNotification": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalCustomNotification(CGlobalModule* this, ICustomNotificationProvider* pProvider);",
        "Terminate\x00": "virtual __thiscall void Terminate(CGlobalModule* this);",
        "OnGlobalThreadCleanup": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS OnGlobalThreadCleanup(CGlobalModule* this, IGlobalThreadCleanupProvider* pProvider);",
        "OnGlobalApplicationPreload": "virtual __thiscall GLOBAL_NOTIFICATION_STATUS IGlobalApplicationPreloadProvider(CGlobalModule* this);"
    }
    
    chttpmodule_func_prototypes = {
        "OnBeginRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnBeginRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostBeginRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostBeginRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnAuthenticateRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnAuthenticateRequest(CHttpModule* this, IHttpContext* pHttpContext, IAuthenticationProvider*);",
        "OnPostAuthenticateRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostAuthenticateRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnAuthorizeRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnAuthorizeRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostAuthorizeRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostAuthorizeRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnResolveRequestCache": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnResolveRequestCache(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostResolveRequestCache": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostResolveRequestCache(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnMapRequestHandler": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnMapRequestHandler(CHttpModule* this, IHttpContext* pHttpContext, IMapHandlerProvider* pProvider);",
        "OnPostMapRequestHandler": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostMapRequestHandler(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnAcquireRequestState": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnAcquireRequestState(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostAcquireRequestState": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostAcquireRequestState(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPreExecuteRequestHandler": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPreExecuteRequestHandler(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostPreExecuteRequestHandler": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostPreExecuteRequestHandler(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnExecuteRequestHandler": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnExecuteRequestHandler(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostExecuteRequestHandler": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostExecuteRequestHandler(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnReleaseRequestState": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnReleaseRequestState(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostReleaseRequestState": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostReleaseRequestState(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnUpdateRequestCache": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnUpdateRequestCache(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostUpdateRequestCache": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostUpdateRequestCache(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnLogRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnLogRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostLogRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostLogRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnEndRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnEndRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnPostEndRequest": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnPostEndRequest(CHttpModule* this, IHttpContext* pHttpContext, IHttpEventProvider* pProvider);",
        "OnSendResponse": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnSendResponse(CHttpModule* this, IHttpContext* pHttpContext, ISendResponseProvider* pProvider);",
        "OnMapPath": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnMapPath(CHttpModule* this, IHttpContext* pHttpContext, IMapPathProvider* pProvider);",
        "OnReadEntity": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnReadEntity(CHttpModule* this, IHttpContext* pHttpContext, IReadEntityProvider* pProvider);",
        "OnCustomRequestNotification": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnCustomRequestNotification(CHttpModule* this, IHttpContext* pHttpContext, ICustomNotificationProvider* pProvider);",
        "OnAsyncCompletion": "virtual __thiscall REQUEST_NOTIFICATION_STATUS OnAsyncCompletion(CHttpModule* this, IHttpContext* pHttpContext, DWORD dwNotification, BOOL fPostNotification, IHttpEventProvider* pProvider, IHttpCompletionInfo* pCompletionInfo);",
        "Dispose\x00": "virtual __thiscall REQUEST_NOTIFICATION_STATUS Dispose(CHttpModule* this);"
    }

    def __init__(self):
        self.is_cglobalmodule = False
        self.is_chttpmodule = False
        
        self.ida_strings = idautils.Strings()
        
    def create_classes(self):
        # Add initial classes
        ida_srclang.parse_decls_with_parser("<default>", None, iis_helper_classes.IIS_CLASSES, False)
    
        # Cleanup other classes
        # We have to do this, as some of the class definitions rely on each other, and can't be loaded in at the same time
        ida_srclang.parse_decls_with_parser("<default>", None, iis_helper_classes.IIS_CLASSES_UPDATE, False)
        
    def create_enums(self):
        
        rdn_enum_id = idc.add_enum(-1, "iis_request_deterministic_notifications", ida_bytes.hex_flag())
        idc.add_enum_member(rdn_enum_id, "RQ_BEGIN_REQUEST", 0x00000001, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_AUTHENTICATE_REQUEST", 0x00000002, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_AUTHORIZE_REQUEST", 0x00000004, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_RESOLVE_REQUEST_CACHE", 0x00000008, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_MAP_REQUEST_HANDLER", 0x00000010, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_ACQUIRE_REQUEST_STATE", 0x00000020, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_PRE_EXECUTE_REQUEST_HANDLER", 0x00000040, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_EXECUTE_REQUEST_HANDLER", 0x00000080, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_RELEASE_REQUEST_STATE", 0x00000100, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_UPDATE_REQUEST_CACHE", 0x00000200, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_LOG_REQUEST", 0x00000400, -1)
        idc.add_enum_member(rdn_enum_id, "RQ_END_REQUEST", 0x00000800, -1)
        
        rndn_enum_id = idc.add_enum(-1, "iis_request_non_deterministic_notifications", ida_bytes.hex_flag())
        idc.add_enum_member(rndn_enum_id, "RQ_CUSTOM_NOTIFICATION", 0x10000000, -1)
        idc.add_enum_member(rndn_enum_id, "RQ_SEND_RESPONSE", 0x20000000, -1)
        idc.add_enum_member(rndn_enum_id, "RQ_READ_ENTITY", 0x40000000, -1)
        idc.add_enum_member(rndn_enum_id, "RQ_MAP_PATH", 0x80000000, -1)
        
        gn_enum_id = idc.add_enum(-1, "iis_global_notifications", ida_bytes.hex_flag())
        idc.add_enum_member(gn_enum_id, "GL_STOP_LISTENING", 0x00000002, -1)
        idc.add_enum_member(gn_enum_id, "GL_CACHE_CLEANUP", 0x00000004, -1)
        idc.add_enum_member(gn_enum_id, "GL_CACHE_OPERATION", 0x00000010, -1)
        idc.add_enum_member(gn_enum_id, "GL_HEALTH_CHECK", 0x00000020, -1)
        idc.add_enum_member(gn_enum_id, "GL_CONFIGURATION_CHANGE", 0x00000040, -1)
        idc.add_enum_member(gn_enum_id, "GL_FILE_CHANGE", 0x00000080, -1)
        idc.add_enum_member(gn_enum_id, "GL_PRE_BEGIN_REQUEST", 0x00000100, -1)
        idc.add_enum_member(gn_enum_id, "GL_APPLICATION_START", 0x00000200, -1)
        idc.add_enum_member(gn_enum_id, "GL_APPLICATION_RESOLVE_MODULES", 0x00000400, -1)
        idc.add_enum_member(gn_enum_id, "GL_APPLICATION_STOP", 0x00000800, -1)
        idc.add_enum_member(gn_enum_id, "GL_RSCA_QUERY", 0x00001000, -1)
        idc.add_enum_member(gn_enum_id, "GL_TRACE_EVENT", 0x00002000, -1)
        idc.add_enum_member(gn_enum_id, "GL_CUSTOM_NOTIFICATION", 0x00004000, -1)
        idc.add_enum_member(gn_enum_id, "GL_THREAD_CLEANUP", 0x00008000, -1)
        idc.add_enum_member(gn_enum_id, "GL_APPLICATION_PRELOAD", 0x00010000, -1)
        
    def determine_iis_module_type(self):
        for ida_string in self.ida_strings:
            if str(ida_string) == ".?AVCGlobalModule@@":
                self.is_cglobalmodule = True
                return True
                
            elif str(ida_string) == ".?AVCHttpModule@@":
                self.is_chttpmodule = True
                return True
                
        print("Could not determine IIS module type.")
        return False
        
    def label_not_implemented_funcs(self, iis_module_func_names):
        not_implemented_func_addresses = {}
        
        for func_name in iis_module_func_names:
            not_implemented_func_addresses[func_name] = set()

        for ida_string in self.ida_strings:
            
            for iis_module_func_name in iis_module_func_names:
                if iis_module_func_name in str(ida_string):
                    
                    string_address = ida_string.ea
                    
                    string_xrefs = idautils.XrefsTo(string_address)
                    
                    # TODO: handle multiple xrefs
                    for xref in string_xrefs:
                        address_in_func = xref.frm
                        
                    func_name = ida_funcs.get_func_name(address_in_func)
                    func = ida_funcs.get_func(address_in_func)
                    
                    # https://www.hex-rays.com/products/ida/support/idadoc/203.shtml
                    ida_name.set_name(func.start_ea, f"not_impl_{iis_module_func_name}", ida_name.SN_FORCE)
                    
                    not_implemented_func_addresses[iis_module_func_name].add(func.start_ea)
                    
                    break
                    
        return not_implemented_func_addresses
        
    def label_implemented_funcs(self, iis_module_func_names, not_implemented_func_addresses):
        implemented_func_addresses = {}
        addresses_checked = set()
        
        for func_name in iis_module_func_names:
            implemented_func_addresses[func_name] = set()
        
        to_forward_check = len(iis_module_func_names) - 1
        to_backward_check = 0
        
        for iis_func_name in iis_module_func_names:
            if not_implemented_func_addresses[iis_func_name]:
                # TODO: iterate over all not implemented addresses
                xrefs = idautils.XrefsTo(list(not_implemented_func_addresses[iis_func_name])[0])
                
                for xref in xrefs:
                    segm_name = ida_segment.get_segm_name(ida_segment.getseg(xref.frm))
                    
                    if segm_name != ".pdata":
                        
                        forward_check_addr = xref.frm
                        backward_check_addr = xref.frm
                        
                        # Iterate forward through unknown routines
                        for i in range(0, to_forward_check - 1):
                            forward_check_addr = idc.next_head(forward_check_addr)
                            
                            if forward_check_addr in addresses_checked:
                                continue
                            
                            func_addr_to_check = idc.get_qword(forward_check_addr)
                            # This value may not always be a function
                            if not ida_funcs.get_func(func_addr_to_check):
                                continue
                            func_name_to_check = ida_funcs.get_func_name(func_addr_to_check)
                            
                            if func_name_to_check.startswith("sub_"):
                                
                                func_name = iis_module_func_names[i+1]
                                
                                ida_name.set_name(func_addr_to_check, func_name, ida_name.SN_FORCE)
                                
                                implemented_func_addresses[func_name].add(func_addr_to_check)
                                
                            addresses_checked.add(forward_check_addr)
                                
                        # Also iterate backwards if we need to
                        for i in range(0, to_backward_check):
                            backward_check_addr = idc.prev_head(backward_check_addr)
                            
                            if backward_check_addr in addresses_checked:
                                continue
                            
                            func_addr_to_check = idc.get_qword(backward_check_addr)
                            # This value may not always be a function
                            if not ida_funcs.get_func(func_addr_to_check):
                                continue
                            func_name_to_check = ida_funcs.get_func_name(func_addr_to_check)
                            
                            if func_name_to_check.startswith("sub_"):
                                # TODO: check whether I can make this less hacky...
                                func_name = iis_module_func_names[-(i+3)]
                                
                                ida_name.set_name(func_addr_to_check, func_name, ida_name.SN_FORCE)
                                
                                implemented_func_addresses[func_name].add(func_addr_to_check)
                                
                            addresses_checked.add(backward_check_addr)
                                
                        
            to_forward_check -= 1
            to_backward_check += 1
            
        return implemented_func_addresses
    
    def relabel_iis_funcs(self):
        
        if not self.determine_iis_module_type():
            return
            
        if self.is_cglobalmodule:
            not_implemented_func_addresses = self.label_not_implemented_funcs(self.cglobalmodule_funcs)
            implemented_func_addresses = self.label_implemented_funcs(self.cglobalmodule_funcs, not_implemented_func_addresses)
            
        elif self.is_chttpmodule:
            not_implemented_func_addresses = self.label_not_implemented_funcs(self.chttpmodule_funcs)
            implemented_func_addresses = self.label_implemented_funcs(self.chttpmodule_funcs, not_implemented_func_addresses)

        return implemented_func_addresses
        
    def retype_registermodule_export(self):
        for entry in idautils.Entries():
            export_address = entry[2]
            export_name = entry[3]
            
            if export_name == "RegisterModule":
                
                register_module_func = ida_funcs.get_func(export_address)
                
                register_module_export_addr = register_module_func.start_ea
                
                break

        idc.SetType(register_module_export_addr, "HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo* pModuleInfo, IHttpServer* pGlobalInfo);")
        
    def retype_iis_funcs(self, implemented_func_addresses):
        
        self.retype_registermodule_export()
        
        for func_name, addresses in implemented_func_addresses.items():
            for func_addr in addresses:
                if self.is_cglobalmodule:
                    idc.SetType(func_addr, self.cglobalmodule_func_prototypes[func_name])
                    
                elif self.is_chttpmodule:
                    idc.SetType(func_addr, self.chttpmodule_func_prototypes[func_name])
                    
    def iis_variable_retype_handler(self, func_ea):
        max_iter = 100
        edited_variable_names = []
        
        cfunc_t = ida_hexrays.decompile(func_ea)
        ctree_visitor = iis_ctree_visitor(cfunc_t)
        
        while max_iter:
            vars_edited = False
            
            ctree_visitor.apply_to(cfunc_t.body, None)
        
            cfunc_t.build_c_tree()
            cfunc_t.refresh_func_ctext()
            
            # These variables may change between updates of the ctree_visitor
            # But it is good enough to make sure we don't run it too many times
            updated_edited_variable_names = ctree_visitor.get_edited_variable_names()
            
            for var_name in updated_edited_variable_names:
                if var_name not in edited_variable_names:
                    edited_variable_names.append(var_name)
                    vars_edited = True
                    
            if not vars_edited:
                break
            
            max_iter -= 1
    
    def retype_iis_variables(self, implemented_func_addresses):
        max_retype_rerun = 3
        
        for func_name, addresses in implemented_func_addresses.items():
            for func_addr in addresses:
                for i in range(0, max_retype_rerun):
                    self.iis_variable_retype_handler(func_addr)
        
    def main(self):
        self.create_classes()
        self.create_enums()
        
        implemented_func_addresses = self.relabel_iis_funcs()
        
        self.retype_iis_funcs(implemented_func_addresses)

        self.retype_iis_variables(implemented_func_addresses)
        
class iis_ctree_visitor(idaapi.ctree_visitor_t):
    
    iis_class_names = [
        "IHttpEventProvider",
        "ICustomNotificationProvider",
        "IHttpStoredContext",
        "IHttpModuleContextContainer",
        "IDispensedHttpModuleContextContainer",
        "IHttpPerfCounterInfo",
        "IHttpApplication",
        "IHttpUrlInfo",
        "IScriptMapInfo",
        "IHttpTokenEntry",
        "IMetadataInfo",
        "IHttpRequest",
        "IHttpCachePolicy",
        "IHttpResponse",
        "IHttpUser",
        "IHttpConnectionStoredContext",
        "IHttpConnectionModuleContextContainer",
        "IHttpConnection",
        "IHttpTraceContext",
        "IHttpFileInfo",
        "IHttpSite",
        "CHttpModule",
        "IHttpContext",
        "IHttpCacheSpecificData",
        "IHttpCacheKey",
        "IHttpFileMonitor",
        "IHttpServer",
        "IHttpCompletionInfo",
        "IAuthenticationProvider",
        "IMapHandlerProvider",
        "IMapPathProvider",
        "ISendResponseProvider",
        "IReadEntityProvider",
        "IPreBeginRequestProvider",
        "IHttpApplicationProvider",
        "IHttpModuleFactory",
        "IHttpApplicationResolveModulesProvider",
        "IGlobalRSCAQueryProvider",
        "IGlobalStopListeningProvider",
        "ICacheProvider",
        "IGlobalConfigurationChangeProvider",
        "IGlobalFileChangeProvider",
        "IGlobalTraceEventProvider",
        "IGlobalThreadCleanupProvider",
        "IGlobalApplicationPreloadProvider",
        "CGlobalModule",
        "IModuleAllocator",
        "IHttpModuleRegistrationInfo"
    ]
    
    def __init__(self, cfunc_t):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc_t = cfunc_t
        
        self.variable_names_edited = []
        
    def get_edited_variable_names(self):
        return self.variable_names_edited

    def permanent_change_variable_type(self, variable, cast_type):
        # https://reverseengineering.stackexchange.com/questions/30348/idapython-how-to-reset-pointer-type-for-variables
        variable.set_final_lvar_type(cast_type)

        lsi = ida_hexrays.lvar_saved_info_t()
        lsi.ll = variable
        lsi.type = ida_typeinf.tinfo_t(variable.tif)
        
        ida_hexrays.modify_user_lvar_info(self.cfunc_t.entry_ea, ida_hexrays.MLI_TYPE, lsi)
        
    def get_calling_class_name(self, calling_class_type):
        for iis_class_name in self.iis_class_names:
            if iis_class_name in str(calling_class_type):
                return iis_class_name
                
        return 0
        
    def retype_handler(self, cast_var, var_to_retype, y_op=None):

        calling_class_type = cast_var.type
            
        if not self.get_calling_class_name(calling_class_type):
            return 0
        
        # The try/excepts are pretty hacky, but do a decent enough job
        if y_op == "var":
            try:
                cast_type = cast_var.type.get_rettype()
                
            except:
                cast_type = cast_var.type
        
        else:
            try:
                cast_type = cast_var.x.type.get_rettype()
                
            except:
                try:
                    cast_type = cast_var.x.type
                    
                except:
                    cast_type = cast_var.type
        
        if cast_type and len(str(cast_type)) != 0:
            self.permanent_change_variable_type(var_to_retype, cast_type)
            self.variable_names_edited.append(var_to_retype.name)
    
    def visit_insn(self, i):
        return 0

    def visit_expr(self, e):
        if e.op != idaapi.cot_asg:
            return 0
        
        if e.x.op != idaapi.cot_var:
            return 0
           
        var_to_retype = e.x.v.getv()
        
        if e.y.op == idaapi.cot_call:
                
            if e.y.x.op == idaapi.cot_cast:
                
                if e.y.x:
                    self.retype_handler(e.y.x, var_to_retype, y_op="call")
                
        elif e.y.op == idaapi.cot_cast:
            
            if e.y.x.x:
                self.retype_handler(e.y.x.x, var_to_retype, y_op="cast")
        
        elif e.y.op == idaapi.cot_var:
            self.retype_handler(e.y, var_to_retype, y_op="var")
        
        return 0

class IISHelper_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IIS Helper Plugin"
    wanted_hotkey = "CTRL-ALT-I"
    help = "Plugin to help analyse native IIS modules"
    wanted_name = "IISHelper"
    hook = None

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        iis_helper = IISHelper()
    
        iis_helper.main()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return IISHelper_t()
