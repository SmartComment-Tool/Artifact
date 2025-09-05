import copy
import json
import re
from solc_select.solc_select import (
    switch_global_version,
)
import requests
from differential_testing import check_inconsistency_static, write_diff_test_to_file, execute_diff_test_to_file, all_function_contains_external_call_to_unknown_address
from diffusc.utils.helpers import get_pragma_versions_from_file
from parse_comments import parse_contract
import os
import hashlib
from slither import Slither
from slither.core.declarations import Function, FunctionContract, Contract

from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityFunction,
)
from coverage import check_covered

from multi_task import check_function_inconsistency_multi_task, confirm_function_inconsistency_using_LLM_multi_task
from chat import check_function_inconsistency, match_comments_to_entities
from propagate_comments import function_comment_propagation, function_comment_propagation_multi_task, pre_propagate_comments, get_comments
from rewrite_smart_contracts import smart_contract_rewrite_with_diff_func, check_and_fix_compilation_error
from scope_analysis import scope_analysis, contain_external_call_to_unknown_address
from taint_analysis import get_tainted_functions, get_tainted_functions_in_main_contract, get_external_public_functions, get_all_possible_function_in_main_contract
from get_slither_instance import get_slither_instance_from_crytic_export


import concurrent.futures
import threading





def extract_comments(contract_code):
    comment_pattern = re.compile(r'(//.*?$|/\*.*?\*/)', re.DOTALL | re.MULTILINE)
    lines = contract_code.split('\n')
    lines = [x for x in lines if x.strip() != '']
    comments = []
    current_comment = []
    inside_multiline_comment = False

    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("/*") and stripped_line.endswith("*/"):
            current_comment.append(stripped_line)
        elif stripped_line.startswith("/*"):
            current_comment.append(stripped_line)
            inside_multiline_comment = True
        elif stripped_line.endswith("*/"):
            current_comment.append(stripped_line)
            inside_multiline_comment = False
            comments.append(' '.join(current_comment))
            current_comment = []
        elif inside_multiline_comment:
            current_comment.append(stripped_line)
        elif comment_pattern.match(stripped_line):
            current_comment.append(stripped_line)
        else:
            if current_comment:
                comments.append(' '.join(current_comment))
                current_comment = []
            if stripped_line:  # Reset current_comment if the line is not empty
                current_comment = []

    if current_comment:
        comments.append(' '.join(current_comment))
    return comments


def remove_comments(code):

    single_line_comment_pattern = re.compile(r'^\s*//.*$')  
    multi_line_comment_start_pattern = re.compile(r'^\s*/\*.*$') 
    multi_line_comment_end_pattern = re.compile(r'^.*\*/\s*$') 

    lines = code.split('\n')
    result = []
    inside_multiline_comment = False

    for line in lines:
        stripped_line = line.strip()

        if inside_multiline_comment:
            if multi_line_comment_end_pattern.match(stripped_line):
                inside_multiline_comment = False 
            continue  

        if single_line_comment_pattern.match(stripped_line):
            continue  

        if multi_line_comment_start_pattern.match(stripped_line):
            if not multi_line_comment_end_pattern.match(stripped_line):  
                inside_multiline_comment = True
            continue  

        result.append(line)

    return '\n'.join(result)

def get_function_declartaion(function_code):
    return function_code.split('{')[0].strip()

def interface_for_contract(contract:Contract):
    result = ''
    functions = []
    vars = []
    for func in contract.functions:
        functions.append(get_function_declartaion(func.source_mapping.content))
    for var in contract.state_variables_declared:
        vars.append(var.name + '(' + str(var.type) + ')')
    result = f""" functions : {sorted(functions)}, state variables: {sorted(vars)}"""
    return result               

def code_slice_for_func(slither_instance, contract_instance: Contract, function_instance, deep_func_call = True, include_called_by=False):
    result = {"func": '', "calls": [], 'called_by': []}

    def add_function_calls_recursively(func):
        if remove_comments(func.source_mapping.content) not in result['calls'] and func_is_implemented(func):
            if remove_comments(func.source_mapping.content) not in result['calls']:
                result['calls'].append(remove_comments(func.source_mapping.content))
            for callee in func.internal_calls:
                if (isinstance(callee, FunctionContract) or isinstance(callee, Function)) and func_is_implemented(callee):
                    add_function_calls_recursively(callee)
            for (callee_contract, callee_func) in func.high_level_calls:
                if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                    if func_is_implemented(callee_func):
                        add_function_calls_recursively(callee_func)
            for (callee_contract, callee_func) in func.library_calls:
                if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                    if func_is_implemented(callee_func):
                        add_function_calls_recursively(callee_func)
    def add_direct_call_relation(func):
        for callee in func.internal_calls:
            if (isinstance(callee, FunctionContract) or isinstance(callee, Function)) and func_is_implemented(callee):
                if remove_comments(callee.source_mapping.content) not in result['calls']:
                    result['calls'].append(remove_comments(callee.source_mapping.content))
        for (callee_contract, callee_func) in func.high_level_calls:
            if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                if func_is_implemented(callee_func):
                    if remove_comments(callee_func.source_mapping.content) not in result['calls']:
                        result['calls'].append(remove_comments(callee_func.source_mapping.content))   
        for (callee_contract, callee_func) in func.library_calls:
            if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                if func_is_implemented(callee_func):
                     if remove_comments(callee_func.source_mapping.content) not in result['calls']:
                        result['calls'].append(remove_comments(callee_func.source_mapping.content))   
    if deep_func_call:
        add_function_calls_recursively(function_instance)
    else:
        add_direct_call_relation(function_instance)
    
    if include_called_by:
        for func in contract_instance.functions:
            if not (isinstance(func, FunctionContract) or isinstance(func, Function)):
                continue
            for callee in func.internal_calls:
                if isinstance(callee, FunctionContract) or isinstance(callee, Function):
                    if callee.signature_str == function_instance.signature_str:
                        result['called_by'].append(remove_comments(func.source_mapping.content))
            for (callee_contract, callee_func) in func.high_level_calls:
                if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                    if callee_func.signature_str == function_instance.signature_str:
                        result['called_by'].append(remove_comments(func.source_mapping.content))
            for (callee_contract, callee_func) in func.library_calls:
                if isinstance(callee_func, FunctionContract) or isinstance(callee_func, Function):
                    if callee_func.signature_str == function_instance.signature_str:
                        result['called_by'].append(remove_comments(func.source_mapping.content))

    result['func'] = remove_comments(function_instance.source_mapping.content)
    result_str = f"""
=== Implementation of Function {function_instance.solidity_signature} ===
{result['func']}
    """

    if result['calls']:
        result_str += f"""
=== Functions that function {function_instance.name} internally calls ===
"""
        result_str += '\n'.join(sorted(result['calls']))

    if include_called_by:
        if len(result['called_by']) > 0:
            result_str += f"""
    === Functions that call {function_instance.name} ===
    """
            result_str += '\n'.join(sorted(result['called_by']))
            
    return result_str
  

def func_is_implemented(func: Function):
    implemented = (func._is_implemented == True)
    implemented = implemented or ('{' in func.source_mapping.content)
    return implemented

def extract_comments_related_to_function(function_signature, contract_name, comments):
    result = []
    for comment in comments:
        if comment['level'] == 'contract':
            continue
        elif comment['level'] == 'function':
            if comment['entity'] == function_signature:
                result.append(comment)
        elif comment['level'] == 'variable':
            if function_signature == comment['entity'].split(':')[0]:
                result.append(comment)
        elif comment['level'] == 'statement':
            if function_signature == comment['entity'].split(':')[0]:
                result.append(comment)
    return result

def pack_comments_related_to_functions(function_instance: Function, comments):
    pack_comments = []
    for current_comment in comments:
        new_comment = {}
        new_comment['entity'] = current_comment['entity']
        new_comment['level'] = current_comment['level']
        new_comment['comment'] = (current_comment['comment'])
        pack_comments.append(new_comment)
    return pack_comments




def process_functions_multi_task(func_contract_pairs, contracts, comments, main_contract_name, in_scope, func_called_by, solc_version, max_tasks_per_prompt, agent_number, need_to_propagate_comments):
    
    tasks = []
    func_contract_tasks = func_contract_pairs
    main_contract_instance = contracts.get_contract_from_name(main_contract_name)[0]
    if not func_contract_tasks:
        return []

    propagated_comments_batches = {}
    if need_to_propagate_comments:
        for i in range(0, len(func_contract_tasks), 10):
            task_batch = func_contract_tasks[i:i + 10]

            propagated_comments_this_batch = function_comment_propagation_multi_task(task_batch, comments, contracts, max_tasks_per_prompt)
            if propagated_comments_this_batch is None:
                continue
            elif len(propagated_comments_this_batch) != len(task_batch):
                continue 
            
            for j in range(0, len(task_batch)):
                propagated_comments_batches[task_batch[j]] = propagated_comments_this_batch[task_batch[j]]
    else:
        for func, contract in func_contract_tasks:
            propagated_comments = get_comments(comments, contract.name, func.solidity_signature)
            propagated_comments_batches[(func, contract)] = propagated_comments
    tasks = []
    for func, contract in func_contract_tasks:
        propagated_comments = propagated_comments_batches[(func, contract)]

        function_related_comments = propagated_comments
        if len([x for x in function_related_comments]) == 0 or not func_is_implemented(func):
            continue
        
        code_slice = code_slice_for_func(contracts, contract, func, include_called_by=False, deep_func_call=False)
        contract_interface = interface_for_contract(contract)

        task = {
            'contract_name': contract.name,
            'function_name': func.name,
            'function_comment': pack_comments_related_to_functions(func, function_related_comments),
            'function_related_code': code_slice,
            'contract_interface': contract_interface,
            'solc_version': solc_version
        }
        tasks.append(task)

    if not tasks:
        return []

    inconsistencies = []
    for i in range(0, len(tasks), max_tasks_per_prompt):
        task_batch = tasks[i:i + max_tasks_per_prompt]
        aggregated_check_result = [
            {"task": x+1, 'result': True, 'flagged_detector_agents': []} for x in range (0,len(task_batch))
        ]
        for j in range (1, agent_number+1):
            check_results = check_function_inconsistency_multi_task(task_batch, solc_version, j)
            if check_results is None:
                continue
            for idx, task_result in enumerate(check_results):
                if (aggregated_check_result[idx]['result'] == True) and (task_result['result'] != True):
                    aggregated_check_result[idx] = check_results[idx]
                    aggregated_check_result[idx]['flagged_detector_agents'] = [j]
                elif (aggregated_check_result[idx]['result'] != True and task_result['result'] != True):
                    aggregated_check_result[idx]['flagged_detector_agents'].append(j)

        
        check_results = sorted(aggregated_check_result, key=lambda x: x['task'])
        inconsistency_tasks = []
        for j, check_result in enumerate(check_results):
            if check_result['result'] == False or check_result['result'] == 'False':
                func, contract = func_contract_pairs[i + j]
                influenced_main_contract_funcs = get_all_possible_function_in_main_contract(main_contract_instance)

                check_result_without_explain = check_result.copy()
                check_result_without_explain.pop('explanation')
                check_result_without_explain.pop('flagged_detector_agents')
                inconsistency_to_check = {
                    'contract': task_batch[j]['contract_name'],
                    'function': task_batch[j]['function_name'],
                    'function_comment': task_batch[j]['function_comment'],
                    'contract_code': task_batch[j]['function_related_code'],
                    'influenced_funcs': list(influenced_main_contract_funcs),
                    'rewritten_code': check_result['improved_implementation'],
                    'explanation': check_result['explanation'],
                    'flagged_detector_agents': check_result['flagged_detector_agents'],
                    'check_result_without_explain': check_result_without_explain
                }

                inconsistency_tasks.append(inconsistency_to_check)

        if inconsistency_tasks:
            inconsistency_to_check_tasks = []
            for x in inconsistency_tasks:
                inconsistency_to_check_tasks.append({
                    'function_name': x['function'],
                    'function_comment': x['function_comment'],
                    'contract_code': x['contract_code'],
                    'contract_full_code': contracts.get_contract_from_name(x['contract'])[0].source_mapping.content,
                    'inconsistency_info': x['check_result_without_explain']
                })
            
            aggregated_check_result = [
                {"task": x+1, 'result': False, 'explanation': "default", 'flagged_verifier_agents': []} for x in range (0,len(inconsistency_to_check_tasks))
            ]
            
            false_reason = {}
            for j in range (1, agent_number+1):
                check_results_by_LLMs = confirm_function_inconsistency_using_LLM_multi_task(inconsistency_to_check_tasks, j)
                if check_results_by_LLMs is None:
                    continue
                for k, check_result_by_LLM in enumerate(check_results_by_LLMs):
                    if (aggregated_check_result[k]['result'] == False) and (check_result_by_LLM['result'] != False and check_result_by_LLM['result'] != 'False'):
                        aggregated_check_result[k]['result'] = check_results_by_LLMs[k]['result']
                        aggregated_check_result[k]['explanation'] = check_results_by_LLMs[k]['explanation']
                        aggregated_check_result[k]['flagged_verifier_agents'].append(j)
                    elif  (check_result_by_LLM['result'] != False and check_result_by_LLM['result'] != 'False'):
                        aggregated_check_result[k]['flagged_verifier_agents'].append(j)
                    elif (aggregated_check_result[k]['result'] == False and aggregated_check_result[k]['explanation'] == "default") :
                        aggregated_check_result[k]['result'] = check_results_by_LLMs[k]['result']
                        aggregated_check_result[k]['explanation'] = check_results_by_LLMs[k]['explanation']

                    if check_result_by_LLM['result'] == False or check_result_by_LLM['result'] == 'False':
                        false_reason[k] = check_result_by_LLM['explanation']
            
            check_results_by_LLMs = sorted(aggregated_check_result, key=lambda x: x['task'])

            
            if check_results_by_LLMs is None:
                for inconsistency_to_check in inconsistency_tasks:
                    inconsistency_to_check['confirmed_by_LLM'] = False
                    inconsistency_to_check['confirmed_by_LLM_reason'] = 'No response from LLM'
                    inconsistencies.append(inconsistency_to_check)
            else:
                for k, check_result_by_LLM in enumerate(check_results_by_LLMs):
                    if len(check_result_by_LLM['flagged_verifier_agents']) < (agent_number+1)/2 :
                        check_result_by_LLM['result'] = False
                        if k in false_reason:
                            check_result_by_LLM['explanation'] = false_reason[k]
                        else:
                            check_result_by_LLM['explanation'] = 'Not Enough Verifier Agents Confirmed'
                        
                        
            
                for k, check_result_by_LLM in enumerate(check_results_by_LLMs):
                    inconsistency_to_check = inconsistency_tasks[k]
                    inconsistency_to_check['confirmed_by_LLM'] = check_result_by_LLM['result']
                    inconsistency_to_check['flagged_verifier_agents'] = check_result_by_LLM['flagged_verifier_agents']
                    if inconsistency_to_check['confirmed_by_LLM'] == False or check_result_by_LLM['result'] == 'False':
                        inconsistency_to_check['confirmed_by_LLM'] = False
                        inconsistency_to_check['confirmed_by_LLM_reason'] = check_result_by_LLM['explanation']
                    inconsistencies.append(inconsistency_to_check)

    return inconsistencies


def process_functions(func_contract_pairs, contracts, comments, main_contract_name, in_scope, func_called_by, solc_version, max_tasks_per_prompt=5):
    tasks = []
    for func, contract in func_contract_pairs:
        if func.is_shadowed:
            continue
        
        if (contract.name, func.solidity_signature) not in in_scope:
            continue
        
        propagated_comments = function_comment_propagation(contract, func, comments, contracts)

        function_related_comments = extract_comments_related_to_function(func.solidity_signature, contract.name, propagated_comments)
        if len([x for x in function_related_comments]) == 0 or not func_is_implemented(func):
            continue


        code_slice = code_slice_for_func(contracts, contract, func, include_called_by=False, deep_func_call=False)
        contract_interface = interface_for_contract(contract)

        task = {
            'function_name': func.name,
            'function_comment': pack_comments_related_to_functions(func, function_related_comments),
            'function_related_code': code_slice,
            'contract_interface': contract_interface,
            'solc_version': solc_version
        }
        tasks.append(task)

    if not tasks:
        return []

    inconsistencies = []
    for i in range(0, len(tasks), max_tasks_per_prompt):
        task_batch = tasks[i:i + max_tasks_per_prompt]
        check_results = check_function_inconsistency_multi_task(task_batch, solc_version)
        if check_results is None:
            continue

        for j, check_result in enumerate(check_results):
            
            if check_result['result'] == False or check_result['result'] == 'False':
                func, contract = func_contract_pairs[i + j]
                influenced_main_contract_funcs = set([x[1] for x in func_called_by[(contract.name, func.signature_str)] if x[0] == main_contract_name])
                influenced_main_contract_funcs.add(func.signature_str)
                influenced_main_contract_funcs = get_tainted_functions(contract, influenced_main_contract_funcs)

                inconsistency_to_check = {
                    'contract': contract.name,
                    'function': func.name,
                    'rewritten_code': check_result['improved_implementation'],
                    'explanation': check_result['explanation'],
                    'influenced_funcs': list(influenced_main_contract_funcs),
                }

                check_result_without_explain = check_result.copy()
                check_result_without_explain.pop('explanation')

                check_result_by_LLM = confirm_function_inconsistency_using_LLM_multi_task([{
                    'function_name': func.name,
                    'function_comment': pack_comments_related_to_functions(func, function_related_comments),
                    'contract_code': code_slice_for_func(contracts, contract, func, include_called_by=True),
                    'inconsistency_info': check_result_without_explain
                }])
                if check_result_by_LLM is None or not check_result_by_LLM:
                    inconsistency_to_check['confirmed_by_LLM'] = False
                    inconsistency_to_check['confirmed_by_LLM_reason'] = 'No response from LLM'
                else:
                    check_result_by_LLM = check_result_by_LLM[0]
                    inconsistency_to_check['confirmed_by_LLM'] = check_result_by_LLM['result']
                    if inconsistency_to_check['confirmed_by_LLM'] == False or check_result_by_LLM['result'] == 'False':
                        inconsistency_to_check['confirmed_by_LLM'] = False
                        inconsistency_to_check['confirmed_by_LLM_reason'] = check_result_by_LLM['explanation']
                inconsistencies.append(inconsistency_to_check)

    return inconsistencies



def process_function(func, contract, contracts, comments, main_contract_name, in_scope, func_called_by, solc_version):
    if func.is_shadowed:
        return []
    
    if (contract.name, func.solidity_signature) not in in_scope:
        return []
    
    propagated_comments = function_comment_propagation(contract, func, comments, contracts)

    function_related_comments = extract_comments_related_to_function(func.solidity_signature, contract.name, propagated_comments)
    if len([x for x in function_related_comments]) == 0 or not func_is_implemented(func):
        return []


    code_slice = code_slice_for_func(contracts, contract, func, include_called_by=False, deep_func_call = False)
    contract_interface = interface_for_contract(contract)

    check_result = check_function_inconsistency(code_slice, func.name, pack_comments_related_to_functions(func, function_related_comments), contract_interface, solc_version)
    if check_result is None:
        return []

    inconsistencies = []
    if check_result['result'] == False or check_result['result'] == 'False':
        influenced_main_contract_funcs = set([x[1] for x in func_called_by[(contract.name, func.signature_str)] if x[0] == main_contract_name])
        influenced_main_contract_funcs.add(func.signature_str)
        influenced_main_contract_funcs = get_tainted_functions(contract, influenced_main_contract_funcs)

        inconsistency_to_check = {
            'contract': contract.name,
            'function': func.name,
            'rewritten_code': check_result['improved_implementation'],
            'explanation': check_result['explanation'],
            'influenced_funcs': list(influenced_main_contract_funcs),
        }

        check_result_without_explain = check_result.copy()
        check_result_without_explain.pop('explanation')

        check_result_by_LLM = confirm_function_inconsistency_using_LLM(func.name, pack_comments_related_to_functions(func, function_related_comments), code_slice_for_func(contracts, contract, func, include_called_by=True), check_result_without_explain)
        if check_result_by_LLM is None:
            inconsistency_to_check['confirmed_by_LLM'] = False
            inconsistency_to_check['confirmed_by_LLM_reason'] = 'No response from LLM'
        else:
            inconsistency_to_check['confirmed_by_LLM'] = check_result_by_LLM['result']
            if inconsistency_to_check['confirmed_by_LLM'] == False or check_result_by_LLM['result'] == 'False':
                inconsistency_to_check['confirmed_by_LLM'] = False
                inconsistency_to_check['confirmed_by_LLM_reason'] = check_result_by_LLM['explanation']
        inconsistencies.append(inconsistency_to_check)

    return inconsistencies


from multiprocessing import Pool

def process_diff_test_task(args):
    """
    Helper function to process a single diff test task.
    Returns True if the inconsistency is valid, otherwise False.
    """
    idx, task_args = args
    diff_diff_test = execute_diff_test_to_file(*task_args)
    return idx, diff_diff_test  # Return the index and the result (True/False)



def compare_contract_with_comments_with_multi_task(contracts: Slither, file_path, contract_address, contract_codes, comments, main_contract_name, construtor_arguments=None, solc_version='0.8.0', use_cache_insonsistency_file = False, need_to_confirm_inconsistency = False, need_to_propagate_comments = True, agent_number = 3):


    max_tasks_per_prompt = 5
    inconsistencies = []
    in_scope, func_called_by = scope_analysis(contracts, main_contract_name)

    func_contract_pairs = []
    for contract in contracts.contracts:
        if contract.is_interface:
            continue
        if contract.name not in contract_codes or contract.name not in comments:
            continue
        for func in contract.functions:
            if func.is_shadowed:
                continue
            if (contract.name, func.solidity_signature) not in in_scope:
                continue
            if not func_is_implemented(func):
                continue
            func_contract_pairs.append((func, contract))
    func_contract_pairs = list(set(func_contract_pairs))

    min_chunk_size = 15
    max_workers = min(8, (len(func_contract_pairs) + min_chunk_size - 1) // min_chunk_size) + 1  
    chunk_size = max(min_chunk_size, (len(func_contract_pairs) + max_workers - 1) // max_workers) 

    if chunk_size < 1:
        return []

    task_batches = [func_contract_pairs[i:i + chunk_size] for i in range(0, len(func_contract_pairs), chunk_size)]
    with concurrent.futures.ThreadPoolExecutor(max_workers= max_workers) as executor:
        futures = []
        for task_batch in task_batches:
            futures.append(executor.submit(process_functions_multi_task, task_batch, contracts, comments, main_contract_name, in_scope, func_called_by, solc_version, 5, agent_number, need_to_propagate_comments)) # 5 is the max_tasks_per_prompt, 3 is the agent number

        for future in concurrent.futures.as_completed(futures):
            new_inconsistencies = future.result()
            if new_inconsistencies:
                inconsistencies.extend(new_inconsistencies.copy())


    Diff_Test_Tasks = {}
    # Assign indices to inconsistencies
    for idx, inconsistency_to_check in enumerate(inconsistencies):
        inconsistency_to_check['idx'] = idx
        if not inconsistency_to_check['confirmed_by_LLM']:
            continue
        if 'flagged_detector_agents' in inconsistency_to_check and len(inconsistency_to_check['flagged_detector_agents']) < (agent_number+1)/2:
            inconsistency_to_check['confirmed_by_LLM'] = False
            inconsistency_to_check['confirmed_by_LLM_reason'] = 'Not Enough Detector Agents Confirmed'
            continue

        
        influenced_main_contract_funcs = inconsistency_to_check['influenced_funcs']
        new_file_path = check_and_fix_compilation_error(file_path, main_contract_name, inconsistency_to_check, influenced_main_contract_funcs, solc_version)
        if new_file_path is None:
            inconsistency_to_check['diff_and_can_be_compiled'] = False
            continue
        else:
            inconsistency_to_check['diff_and_can_be_compiled'] = True

        diff_static = check_inconsistency_static(file_path, new_file_path, inconsistency_to_check['contract'], influenced_main_contract_funcs, solc_version, inconsistency_to_check)
        if diff_static:
            inconsistency_to_check['confirmed_by_static'] = True
            inconsistency_to_check['valid_inconsistency'] = True
            continue
        else:
            inconsistency_to_check['confirmed_by_static'] = False
        
        if all_function_contains_external_call_to_unknown_address(file_path, new_file_path, main_contract_name, influenced_main_contract_funcs, solc_version, inconsistency_to_check):
            inconsistency_to_check['confirmed_by_diff_test'] = False
            continue
        
        inconsistency_to_check['confirmed_by_diff_test'] = None
        
        
        _ = write_diff_test_to_file(file_path, new_file_path, main_contract_name, influenced_main_contract_funcs, solc_version, construtor_arguments, idx)
        Diff_Test_Tasks[idx] = [file_path, new_file_path, main_contract_name, influenced_main_contract_funcs, solc_version, construtor_arguments, idx, inconsistency_to_check]
    
    
    # Main processing logic
    tasks_to_process = [
        (idx, Diff_Test_Tasks[idx])
        for idx in Diff_Test_Tasks
    ]

    switch_global_version("0.8.0", always_install=True)

    with Pool(processes= 16) as pool:  # Adjust the number of processes as needed
        results = pool.map(process_diff_test_task, tasks_to_process)

    # Update inconsistencies based on the results
    for idx, diff_diff_test in results:
        inconsistency_to_check = inconsistencies[idx]
        
        if diff_diff_test:
            inconsistency_to_check['confirmed_by_diff_test'] = True
            inconsistency_to_check['valid_inconsistency'] = True
        else:
            inconsistency_to_check['confirmed_by_diff_test'] = False
    

    filtered = []
    for inc in inconsistencies:
        violated_comment = None
        if 'check_result_without_explain' in inc and isinstance(inc['check_result_without_explain'], dict):
            violated_comment = inc['check_result_without_explain'].get('violated_comment')
        filtered.append({
            'contract': inc.get('contract'),
            'function': inc.get('function'),
            'explanation': inc.get('explanation'),
            'violated_comment': violated_comment,
            'contract_code': inc.get('contract_code') if 'contract_code' in inc else inc.get('function_related_code'),
            'rewritten_code': inc.get('rewritten_code')
        })
    return filtered


def compare_contract_with_comments(contracts: Slither, file_path, contract_address, contract_codes, comments, main_contract_name, construtor_arguments=None, solc_version = '0.8.0'):
    inconsistencies = []
    in_scope, func_called_by = scope_analysis(contracts, main_contract_name)

    with concurrent.futures.ThreadPoolExecutor(max_workers = 8) as executor:
        futures = []
        for contract in contracts.contracts:
            if contract.is_interface:
                continue
            if contract.name not in contract_codes or contract.name not in comments:
                continue
            for func in contract.functions:
                futures.append(executor.submit(process_function, func, contract, contracts, comments, main_contract_name, in_scope, func_called_by, solc_version))

        for future in concurrent.futures.as_completed(futures):
            new_inconsistencies = future.result()
            if new_inconsistencies:
                inconsistencies.extend(new_inconsistencies.copy())
    

    # Assign indices to inconsistencies
    for idx, inconsistency_to_check in enumerate(inconsistencies):
        inconsistency_to_check['idx'] = idx
        if not inconsistency_to_check['confirmed_by_LLM']:
            continue
        influenced_main_contract_funcs = inconsistency_to_check['influenced_funcs']
        new_file_path = check_and_fix_compilation_error(file_path, main_contract_name, inconsistency_to_check, influenced_main_contract_funcs, solc_version)
        if new_file_path is None:
            inconsistency_to_check['diff_and_can_be_compiled'] = False
            continue
        else:
            inconsistency_to_check['diff_and_can_be_compiled'] = True

        diff_static = check_inconsistency_static(file_path, new_file_path, inconsistency_to_check['contract'], influenced_main_contract_funcs, solc_version, inconsistency_to_check)
        if diff_static:
            inconsistency_to_check['confirmed_by_static'] = True
            inconsistency_to_check['valid_inconsistency'] = True
            continue
        else:
            inconsistency_to_check['confirmed_by_static'] = False
        diff_diff_test = check_inconsistency_with_diff_test(file_path, new_file_path, main_contract_name, influenced_main_contract_funcs, solc_version, construtor_arguments)
        if diff_diff_test:
            inconsistency_to_check['confirmed_by_diff_test'] = True
            inconsistency_to_check['valid_inconsistency'] = True
        else:
            inconsistency_to_check['confirmed_by_diff_test'] = False
    return inconsistencies


def store_comments_to_json(comments, file_path):
    """
    Store the comments in a local JSON file.

    :param comments: List of comments to be stored
    :param file_path: Path to the file where comments will be stored
    """
    with open(file_path, 'w+') as file:
        json.dump(comments, file, indent=4)






def contains_comment(contract_code):
    return '//' in contract_code or '/*' in contract_code



def analyze(file_path, contract_address, main_contract_name, contracts_slither_instance, contract_constructor_arguments, solc_version,  use_cache_insonsistency_file, need_to_confirm_inconsistency, need_to_propagate_comments, agent_number):
    
    def process_contract(contract_name, contract_code):
        if not contains_comment(contract_code):
            entities = []
        else:
            entities = match_comments_to_entities(contract_name, contract_code)
        if entities is None:
            return contract_name, []

        contract_comments = []
        for entity in entities:
            if entity['level'] in ['variable', 'statement'] and ':' not in entity['entity']:
                continue
            contract_comments.append(entity)
        return contract_name, contract_comments
    contract_codes = parse_contract(file_path)
    
    main_contract_instance = contracts_slither_instance.get_contract_from_name(main_contract_name)[0]

    
    comments = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers = 8) as executor:
        futures = {executor.submit(process_contract, contract_name, contract_code): contract_name for contract_name, contract_code in contract_codes.items()}
        for future in concurrent.futures.as_completed(futures):
            contract_name, contract_comments = future.result()
            if contract_comments:
                comments[contract_name] = contract_comments

      
    if need_to_propagate_comments:
        comments = pre_propagate_comments(comments, contracts_slither_instance)


    inconsistencies = compare_contract_with_comments_with_multi_task(contracts_slither_instance, file_path, contract_address, contract_codes, comments, main_contract_name, contract_constructor_arguments, solc_version,  use_cache_insonsistency_file, need_to_confirm_inconsistency, need_to_propagate_comments, agent_number)

    return inconsistencies