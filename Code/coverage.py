import os
import json
from slither import Slither
from slither.core.declarations import Function, FunctionContract


def func_called_by_relation(slither_instance: Slither):
    func_called_by = {}
    def add_direct_call_relation(caller_contract, caller_func, callee_contract, callee_func):
        if (callee_contract.name, callee_func.name) not in func_called_by:
            func_called_by[(callee_contract.name, callee_func.name)] = []
        if (caller_contract, caller_func) not in func_called_by[(callee_contract.name, callee_func.name)]:
            func_called_by[(callee_contract.name, callee_func.name)].append((caller_contract, caller_func))

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
                if isinstance(callee, FunctionContract):
                    
                    add_direct_call_relation(contract, func, callee.contract, callee)
                elif isinstance(callee, Function):
                    add_direct_call_relation(contract, func, callee.contract, callee)
            for (callee_contract, callee_func) in func.high_level_calls:
                if isinstance(callee_func, Function):
                    add_direct_call_relation(contract, func, callee_contract, callee_func)
            for (callee_contract, callee_func) in func.library_calls:
                if isinstance(callee_func, Function):
                    add_direct_call_relation(contract, func, callee_contract, callee_func)


    build_indirect_call_relation()
    return func_called_by




def find_assert_lines(solidity_file, fn_name):
    result = {}
    with open(solidity_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_function = False
    function_name = None
    function_start = None
    results = {}
    brace_count = 0

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        
        if stripped.startswith('function '):
            in_function = True
            function_start = idx
            
            fn = stripped.split('function', 1)[1].split('(')[0].strip()
            function_name = fn
            brace_count = line.count('{') - line.count('}')
            results[function_name] = []
            continue

        if in_function:
            brace_count += line.count('{') - line.count('}')
            if 'assert' in stripped:
                results[function_name].append(idx)
            if brace_count <= 0:
                in_function = False
                function_name = None

    for fn, lines in results.items():
        if len(lines) > 0 and fn.endswith('_' + fn_name):
            return lines
    
    return []



def check_covered(function_name, contract_name, diff_dir, slither: Slither):
    contract_instance = slither.get_contract_from_name(contract_name)[0]
    current_func = [func for func in contract_instance.functions if func.name == function_name][0]
    if current_func.visibility == 'public' or current_func.visibility == 'external':
        return check_covered_single_function(function_name, diff_dir)
    elif function_name == 'constructor' or function_name == contract_name:
        return True
    else:
        function_called_by = func_called_by_relation(slither)
        if (contract_name, function_name) not in function_called_by:
            return False
        for contract, func in function_called_by[contract_name, function_name]:
            if func.visibility == 'public' or func.visibility == 'external':
                covered = check_covered_single_function(func.name, diff_dir)
                if covered:
                    return covered
    return False
        

def check_covered_single_function(function_name, diff_dir):
    
    if not os.path.exists(diff_dir):
        return False
    coverage_dir = os.path.join(diff_dir,'corpus')
    if not os.path.exists(coverage_dir):
        return False
    solidity_file = os.path.join(diff_dir, 'DiffFuzz.sol')
    
    lcov_files = [os.path.join(coverage_dir, f) for f in os.listdir(coverage_dir) if f.lower().endswith('.lcov')]
    if not lcov_files:
        return False


    coverage_file = max(lcov_files, key=os.path.getmtime)
    
    
    func_assert_line = find_assert_lines(solidity_file, function_name)
    if len(func_assert_line) < 2:
        return False
    assert_line = func_assert_line[1]
    covered_lines = []
    with open(coverage_file, 'r') as f:
        for x in f.readlines():
            if 'DA:' in x:
                line_number = x.split(',')[0].split(':')[1]
                covered = int(x.split(',')[-1]) > 0
                if covered:
                    covered_lines.append(int(line_number))
    return (assert_line in covered_lines)

def is_public_or_external(func):
    if '{' in func:
        func = func.split('{')[0]
        if 'public' in func or 'external' in func:
            return True
        
    return False

