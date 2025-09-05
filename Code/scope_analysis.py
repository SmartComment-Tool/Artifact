from slither import Slither
from slither.core.declarations import Function, FunctionContract, Contract
from slither.slithir.operations import  EventCall, SolidityCall, HighLevelCall, LowLevelCall, InternalCall, TypeConversion
from slither.core.cfg.node import NodeType

def get_function_call_recursively(func, func_calls):
    if (func) not in func_calls:
        if isinstance(func, FunctionContract) or isinstance(func, Function):
            func_calls.append(func)
        else:
            return
        if isinstance(func, FunctionContract) or isinstance(func, Function):
            for callee in func.internal_calls:
                get_function_call_recursively(callee, func_calls)
            for (callee_contract, callee_func) in func.high_level_calls:
                get_function_call_recursively(callee_func, func_calls)
            for (callee_contract, callee_func) in func.library_calls:
                get_function_call_recursively(callee_func, func_calls)
    else:
        return
    return

def contain_external_call_to_unknown_address(func: Function, isconstructor: bool = False):
    function_called_by_func = [func]
    if isconstructor:
        if func:
            for node in func.nodes:
                for ir in node.irs:
                    if isinstance(ir, TypeConversion):
                        if ir.variable in func.parameters and (hasattr(ir._type, "_type") and isinstance(ir._type._type, Contract)):
                            return True
    get_function_call_recursively(func, function_called_by_func)
    for func in function_called_by_func:
        if not hasattr(func, 'nodes') :
            continue
        in_if_or_try = False
        for node in func.nodes:
            if node.type == NodeType.TRY or node.type == NodeType.IF:
                in_if_or_try = True
            elif node.type == NodeType.ENDIF or node.type == NodeType.CATCH:
                in_if_or_try = False
            for ir in node.irs:
                if isinstance(ir, HighLevelCall):
                    if hasattr(ir.function, 'is_implemented') and ir.function.is_implemented != True and not in_if_or_try: 
                        return True
                elif isinstance(ir, LowLevelCall) and hasattr(ir, 'destination') and hasattr(ir.destination, 'is_constant') and not ir.destination.is_constant and ir._call_value is None and not in_if_or_try:
                    return True
    return False

def functions_implementation_shadowed(func):
    candidates = [c.functions for c in func.contract.inheritance]
    candidates = [candidate for sublist in candidates for candidate in sublist]
    return [f for f in candidates if f.full_name == func.full_name]

def funcs_ever_been_called_by_external_function(slither_instance: Slither, main_contract_name):
    def func_called_by_relation(slither_instance: Slither):
        func_called_by = {}
        def add_direct_call_relation(caller_contract, caller_func, callee_contract, callee_func):
            if (callee_contract.name, callee_func.signature_str) not in func_called_by:
                func_called_by[(callee_contract.name, callee_func.signature_str)] = []
            if (caller_contract.name, caller_func.signature_str) not in func_called_by[(callee_contract.name, callee_func.signature_str)]:
                func_called_by[(callee_contract.name, callee_func.signature_str)].append((caller_contract.name, caller_func.signature_str))
        def build_indirect_call_relation():
            indirect_calls = True
            while indirect_calls:
                indirect_calls = False
                new_relations = {}
                for callee_key, callers in func_called_by.items():
                    for caller in callers:
                        if caller in func_called_by:
                            for indirect_caller in func_called_by[caller]:
                                if indirect_caller not in callers:
                                    if callee_key not in new_relations:
                                        new_relations[callee_key] = []
                                    new_relations[callee_key].append(indirect_caller)
                                    indirect_calls = True
                for callee_key, new_callers in new_relations.items():
                    func_called_by[callee_key].extend(new_callers)
        for contract in slither_instance.contracts:
            for func in contract.functions:
                if (contract.name, func.signature_str) not in func_called_by:
                    func_called_by[(contract.name, func.signature_str)] = []
                for callee in func.internal_calls:  
                    if isinstance(callee, FunctionContract) and hasattr(callee, 'contract'):
                        add_direct_call_relation(contract, func, callee.contract, callee)
                    elif isinstance(callee, Function) and hasattr(callee, 'contract'):
                        add_direct_call_relation(contract, func, callee.contract, callee)
                for (callee_contract, callee_func) in func.high_level_calls:
                    if isinstance(callee_func, Function) :
                        add_direct_call_relation(contract, func, callee_contract, callee_func)
                for (callee_contract, callee_func) in func.library_calls:
                    if isinstance(callee_func, Function):
                        add_direct_call_relation(contract, func, callee_contract, callee_func)
        build_indirect_call_relation()
        return func_called_by
    def func_is_public_or_external(func_signature_str, contract_name, slither_instance):
        for contract in slither_instance.contracts:
            if contract.name == contract_name:
                for func in contract.functions:
                    if func.signature_str == func_signature_str:
                        if func.visibility == 'external' or func.visibility == 'public':
                            return True
        return False
    func_called_by = func_called_by_relation(slither_instance)
    result = []
    for contract in slither_instance.contracts:
        for func in contract.functions:
            if (contract.name, func.signature_str) in func_called_by:
                for caller_contract, caller_function in func_called_by[(contract.name, func.signature_str)]:
                    if caller_contract == main_contract_name:
                        if func_is_public_or_external(caller_function, caller_contract, slither_instance):
                            result.append((contract.name, func.signature_str))
                            break
    return result, func_called_by

def func_is_implemented(func: Function):
    implemented = (func._is_implemented == True)
    implemented = implemented or ('{' in func.source_mapping.content)
    return implemented

def scope_analysis(slither_instance: Slither, main_contract_name: str):
    not_in_scope = []
    in_scope = []
    all_funcs_called, func_called_by = funcs_ever_been_called_by_external_function(slither_instance, main_contract_name)
    for contract in slither_instance.contracts:
        for func in contract.functions:
            if not func_is_implemented(func):
                continue
            if contract.is_interface:
                not_in_scope.append((contract.name, func.solidity_signature))
            elif contain_external_call_to_unknown_address(func):
                not_in_scope.append((contract.name, func.solidity_signature)) 
            elif (func.visibility == 'internal' or func.visibility == 'private') and (contract.name, func.signature_str) not in all_funcs_called:
                not_in_scope.append((contract.name, func.solidity_signature))
            else:
                pass
            if (contract.name, func.solidity_signature) not in not_in_scope:
                in_scope.append((contract.name, func.solidity_signature))
    in_scope = list(set(in_scope))
    not_in_scope = list(set(not_in_scope))
    in_scope = function_scope_refine_based_on_shadow_relation(slither_instance, in_scope)
    in_scope = list(set(in_scope) - set(not_in_scope))

    return in_scope, func_called_by

def function_scope_refine_based_on_shadow_relation(slither_instance: Slither, function_in_scope):
    function_to_remove = []
    for contract_name, func_sig in function_in_scope:
        contract_instance = slither_instance.get_contract_from_name(contract_name)[0]
        for func in contract_instance.functions:
            if func.is_shadowed:
                continue
            if func.solidity_signature == func_sig:
                checks = functions_implementation_shadowed(func)
                for func_shadowed in checks:
                    if func_shadowed.is_implemented and func_shadowed.source_mapping.content == func.source_mapping.content:
                        function_to_remove.append((func.contract.name, func.solidity_signature))
                        function_in_scope.append((func_shadowed.contract.name, func.solidity_signature))
                    elif func_shadowed.is_implemented and func_shadowed.source_mapping.content != func.source_mapping.content:
                        function_to_remove.append((func_shadowed.contract.name, func_shadowed.solidity_signature))
                function_to_remove.extend(list(set(function_to_remove) & set(function_in_scope)))
    function_to_remove = list(set(function_to_remove))
    function_in_scope = list(set(function_in_scope) - set(function_to_remove))
    return function_in_scope