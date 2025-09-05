
import itertools
from slither.slithir.operations import EventCall, InternalCall, SolidityCall, InternalDynamicCall
from slither.core.declarations import Function, FunctionContract
from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityFunction,
    SolidityVariableComposed,
)

def get_func_call_relation(slither_instance):
    def merge_calls(func_name, visited):
        if func_name in visited:
            return set()
        visited.add(func_name)
        
        all_calls = set(func2called_func[func_name])
        for called_name in list(func2called_func[func_name]):
            if called_name in func2called_func:
                all_calls.update(merge_calls(called_name, visited))
    
        func2called_func[func_name] = list(all_calls)

        return all_calls
    
    func2called_func = {}
    for func in slither_instance.functions:
        if func.signature_str not in func2called_func:
            func2called_func[func.signature_str] = []
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) or isinstance(ir, InternalDynamicCall) or isinstance(ir, SolidityCall):
                    if ir.function in slither_instance.functions or ir.function in slither_instance.modifiers :
                        func2called_func[func.signature_str].append(ir.function.signature_str)

    for func_name in func2called_func.keys():
        merge_calls(func_name, set())
    return func2called_func
    
def get_func_data_dependency_relation(slither_instance, func2call):
    func2write_state = {}
    func2read_state = {}
    is_self_contained = {}
    for function in slither_instance.functions:
        if function.signature_str not in func2read_state:
            func2read_state[function.signature_str] = set()
        if function.signature_str not in func2write_state:
            func2write_state[function.signature_str] = set()
        for i in function.state_variables_read:
            func2read_state[function.signature_str].add(i.signature_str)
        for i in function.state_variables_written:
            
            func2write_state[function.signature_str].add(i.signature_str)
    for caller in func2call:
        for callee in func2call[caller]:
            matched = False
            for ff in (slither_instance.functions):
                if ff.signature_str == callee:
                    callee = ff
                    matched = True
            for ff in (slither_instance.modifiers):
                if ff.signature_str == callee:
                    callee = ff
                    matched = True
            if not matched:
                continue
            for i in callee.state_variables_read:
                func2read_state[caller].add(i.signature_str)
            for i in callee.state_variables_written:
                func2write_state[caller].add(i.signature_str)
    for func in func2read_state:
        if func2read_state[func] <= func2write_state[func]:
            is_self_contained[func] = True
        else:
            is_self_contained[func] = False
                
    func2influenced_func = {}
    for func1, func2 in itertools.permutations(slither_instance.functions, 2):
        if func1.signature_str not in func2influenced_func:
            func2influenced_func[func1.signature_str] = set()
        if len(func2write_state[func1.signature_str] & (func2read_state[func2.signature_str])) > 0:
            func2influenced_func[func1.signature_str].add(func2.signature_str)
            
    for caller in func2influenced_func:
        for callee in func2call[caller]:
            if callee in func2influenced_func:
                func2influenced_func[caller].update(func2influenced_func[callee])
        if caller not in func2influenced_func[caller]:
            func2influenced_func[caller].add(caller)
    
    return func2influenced_func, is_self_contained



def get_all_possible_function_in_main_contract(main_contract_instance):
    result = []
    excluded_functions = set()
    
    
    for func in main_contract_instance.functions:
        if func.is_implemented == False:
            continue
        function_called_by_func = []
        def add_function_calls_recursively(func):
            if func not in function_called_by_func:
                
                    function_called_by_func.append(func)
            for callee in func.internal_calls:
                if (isinstance(callee, FunctionContract) or isinstance(callee, Function)):
                    add_function_calls_recursively(callee)
            for (callee_contract, callee_func) in func.high_level_calls:
                if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                    add_function_calls_recursively(callee_func)
            for (callee_contract, callee_func) in func.library_calls:
                if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                    add_function_calls_recursively(callee_func)
        add_function_calls_recursively(func)
        
        tainted_by_conrtact_address = False
        for callee in function_called_by_func:
            if any([is_dependent(arg, SolidityVariable("this"), callee) for arg in callee.state_variables_read]):
                tainted_by_conrtact_address = True
                break
            elif any([is_dependent(arg, SolidityVariable("this"), callee) for arg in callee.state_variables_written]):
                tainted_by_conrtact_address = True
                break
            elif SolidityVariable("this") in callee.variables_read:
                tainted_by_conrtact_address = True
                break
        if tainted_by_conrtact_address:
            
            excluded_functions.add(func.signature_str)
    for func in main_contract_instance.functions:
        if func.is_implemented == False:
            continue
        if func.signature_str not in excluded_functions:
            result.append(func.signature_str)
    
    return list(set(result))
    
def get_tainted_functions_in_main_contract(main_contract_instance, function_contract_slither_instance, taint_source_functions, func_called_by):
    result = taint_source_functions
    for func in main_contract_instance.functions:
        for callee in func.internal_calls:
            if isinstance(callee, FunctionContract) or isinstance(callee, Function):
                if callee.signature_str in taint_source_functions:
                    result.append(func.signature_str)
        for (callee_contract, callee_func) in func.high_level_calls:
            if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                if callee_func.signature_str in taint_source_functions:
                    result.append(func.signature_str)
        for (callee_contract, callee_func) in func.library_calls:
            if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                if callee_func.signature_str  in taint_source_functions:
                    result.append(func.signature_str)
                    
    influenced_main_contract_funcs = set(result)
    for res in result:    
        influenced_main_contract_funcs = influenced_main_contract_funcs | set([x[1] for x in func_called_by[(main_contract_instance.name, res)] if x[0] == main_contract_instance.name])

    return influenced_main_contract_funcs

def get_external_public_functions(slither_instance, taint_source_functions):
    external_functions = set()
    for func in slither_instance.functions:
        if (func.visibility == 'public' or func.visibility == 'external') and func.signature_str in taint_source_functions:
            external_functions.add(func.signature_str)
    return external_functions

def get_tainted_functions(contract_slither_instance, taint_source_functions):
    func2call = get_func_call_relation(contract_slither_instance)
    func2influenced_func, is_self_contained = get_func_data_dependency_relation(contract_slither_instance, func2call)
    tainted_functions = set()
    for func in taint_source_functions:
        if func in func2influenced_func:
            tainted_functions.update(func2influenced_func[func])
        if func in func2call:
            tainted_functions.update(func2call[func])
    return tainted_functions