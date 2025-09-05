import os
import json
import re
import shutil
from diffusc.utils.helpers import get_pragma_versions_from_file
from diffusc.utils.slither_provider import FileSlitherProvider
from parse_comments import parse_contract
from chat import fix_compile_error, fix_compile_error_source_code_level
from solc_select.solc_select import switch_global_version
from get_slither_instance import get_slither_instance_from_crytic_export

def check_compile(new_file_path, main_contract_name, solc_version):
    switch_global_version(solc_version, True)
    provider = FileSlitherProvider()
    try:
        slither = get_slither_instance_from_crytic_export(new_file_path, main_contract_name, solc_version)
    except Exception as e:
        return False, e
    return True, None

def check_and_fix_compilation_error(file_path, main_contract_name, inconsistency_to_check, influenced_main_contract_funcs, solc_version, max_attempts = 2):
    if not has_new_implementation(file_path,  inconsistency_to_check['contract'], inconsistency_to_check['rewritten_code']):
        return None
    new_file_path = smart_contract_rewrite_with_diff_func(file_path, inconsistency_to_check['contract'], inconsistency_to_check['rewritten_code'])
    attempt = 0
    err_msg = ''
    while attempt <= max_attempts:
        attempt += 1
        pass_compile, err_msg = check_compile(new_file_path, main_contract_name, solc_version)
        if pass_compile:
            return new_file_path
        elif attempt < max_attempts:
            contracts = parse_contract(new_file_path)
            if main_contract_name not in contracts:
                return None
            contract_code_block = contracts[main_contract_name]
            new_contract_code_block = fix_compile_error(contract_code_block, inconsistency_to_check['contract_code'],  inconsistency_to_check['rewritten_code'], err_msg, solc_version)
            if new_contract_code_block is None:
                continue
            inconsistency_to_check['rewritten_code'] = new_contract_code_block
            smart_contract_rewrite_with_diff_func(file_path, inconsistency_to_check['contract'], inconsistency_to_check['rewritten_code'])
    contracts = parse_contract(new_file_path)
    contract_code_block = contracts[main_contract_name]
    new_contract_code_block = fix_compile_error_source_code_level(contract_code_block, influenced_main_contract_funcs, err_msg, solc_version)
    if new_contract_code_block is None:
        return None
    smart_contract_rewrite_with_diff_contract(file_path, main_contract_name, new_contract_code_block)
    if check_compile(new_file_path, main_contract_name, solc_version)[0]:
        return new_file_path
    return None

def smart_contract_rewrite_with_diff_contract(origin_file_path, diff_contract_name, diff_contract_source):
    if os.path.isdir(origin_file_path):
        is_multi_contract = True
        new_file_path = origin_file_path + '_variant'
        if not os.path.exists(new_file_path):
            shutil.copytree(origin_file_path, new_file_path, dirs_exist_ok=True)
    else:
        is_multi_contract = False
        new_file_path = origin_file_path.replace('.sol', '_variant.sol')
    if not is_multi_contract:
        contracts = parse_contract(origin_file_path)
        with open(origin_file_path, 'r') as file:
            contract_code = file.read()
        contract_code_block = contracts[diff_contract_name]
        contract_code = contract_code.replace(contract_code_block, diff_contract_source)
        with open(new_file_path, 'w') as file:
                file.write(contract_code)
    else:
        all_files = []
        for root, _, files in os.walk(new_file_path):
            for file in files:
                if file.endswith(".sol"):
                    all_files.append(os.path.join(root, file))
        diff_file_path = [x for x in all_files if diff_contract_name + '.sol' == os.path.basename(x)][0]
        contracts = parse_contract(diff_file_path)
        with open(diff_file_path, 'r') as file:
            contract_code = file.read()
        contract_code_block = contracts[diff_contract_name]
        contract_code = contract_code.replace(contract_code_block, diff_contract_source)
        if "SPDX-License-Identifier" not in contract_code:
            contract_code = '// SPDX-License-Identifier: MIT' + '\n' + contract_code
        with open(diff_file_path, 'w') as file:
            file.write(contract_code)
    return new_file_path

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

def remove_comments_and_space(code):
    comment_pattern = re.compile(r'(//.*?$|/\*.*?\*/)', re.DOTALL | re.MULTILINE)
    code_without_comments = comment_pattern.sub('', code)
    lines = code_without_comments.split('\n')
    non_empty_lines = [line for line in lines if line.strip() != '']
    code_without_empty_lines = '\n'.join(non_empty_lines)
    code_without_space = code_without_empty_lines.replace(' ', '')
    return code_without_space

def has_new_implementation(origin_file_path, contract_name, function_dict):
    has_new_implenmentation = False
    if os.path.isdir(origin_file_path):
        new_file_path = origin_file_path + '_variant'
        if not os.path.exists(new_file_path):
            shutil.copytree(origin_file_path, new_file_path, dirs_exist_ok=True)
        all_files = []
        for root, _, files in os.walk(new_file_path):
            for file in files:
                if file.endswith(".sol"):
                    all_files.append(os.path.join(root, file))
        target_contract_file_path = [x for x in all_files if contract_name + '.sol' == os.path.basename(x)][0]
        contracts = parse_contract(target_contract_file_path)
        contract_code_block = contracts[contract_name]
        with open(target_contract_file_path, 'r') as file:
            contract_code = file.read()
    else:
        target_contract_file_path = origin_file_path.replace('.sol', '_variant.sol')
        new_file_path = target_contract_file_path 
        contracts = parse_contract(origin_file_path)
        contract_code_block = contracts[contract_name]
        with open(origin_file_path, 'r') as file:
            contract_code = file.read()
    for func in function_dict:
        function_string = function_dict[func]
        if function_string == 'None' or function_string is None:
            continue
        if 'constructor' not in function_string:
            function_pattern = re.compile(r'function\s+(\w+)\s*')
        else:
            function_pattern = re.compile(r'(constructor)+')
        function_match = function_pattern.search(function_string)
        if function_match:
            function_name = function_match.group(1)
            new_implementation = function_string
            if 'constructor' not in function_string:
                function_pattern = re.compile(rf"function\s+{function_name}\s*", re.DOTALL)
            else:
                function_pattern = re.compile(rf"constructor\s*", re.DOTALL)
            function_match = function_pattern.search(contract_code_block)
            if function_match:
                start_index = function_match.start()
                bracket_count = 0
                end_index = start_index
                have_seen_left = False
                while end_index < len(contract_code_block):
                    if contract_code_block[end_index] == '{':
                        bracket_count += 1
                        have_seen_left = True
                    elif contract_code_block[end_index] == '}':
                        bracket_count -= 1
                    end_index += 1
                    if bracket_count == 0 and end_index > start_index and have_seen_left:
                        break
                old_function_code = contract_code_block[start_index:end_index]
                if remove_comments_and_space(old_function_code) != remove_comments_and_space(new_implementation):
                    has_new_implenmentation = True
                    break
    return has_new_implenmentation

def smart_contract_rewrite_with_diff_func(origin_file_path, contract_name, function_dict):
    if os.path.isdir(origin_file_path):
        new_file_path = origin_file_path + '_variant'
        if not os.path.exists(new_file_path):
            shutil.copytree(origin_file_path, new_file_path, dirs_exist_ok=True)
        all_files = []
        for root, _, files in os.walk(new_file_path):
            for file in files:
                if file.endswith(".sol"):
                    all_files.append(os.path.join(root, file))
        target_contract_file_path = [x for x in all_files if contract_name + '.sol' == os.path.basename(x)][0]
        contracts = parse_contract(target_contract_file_path)
        contract_code_block = contracts[contract_name]
        with open(target_contract_file_path, 'r') as file:
            contract_code = file.read()
    else:
        target_contract_file_path = origin_file_path.replace('.sol', '_variant.sol')
        new_file_path = target_contract_file_path 
        contracts = parse_contract(origin_file_path)
        contract_code_block = contracts[contract_name]
        with open(origin_file_path, 'r') as file:
            contract_code = file.read()
    for func in function_dict:
        function_string = function_dict[func]
        if function_string == 'None' or function_string is None:
            continue
        if 'constructor' not in function_string:
            function_pattern = re.compile(r'function\s+(\w+)\s*')
        else:
            function_pattern = re.compile(r'(constructor)+')
        function_match = function_pattern.search(function_string)
        if function_match:
            function_name = function_match.group(1)
            new_implementation = function_string
            if 'constructor' not in function_string:
                function_pattern = re.compile(rf"function\s+{function_name}\s*", re.DOTALL)
            else:
                function_pattern = re.compile(rf"constructor\s*", re.DOTALL)
            function_matches = list(re.finditer(function_pattern, contract_code_block))
            for function_match in function_matches:
                start_index = function_match.start()
                bracket_count = 0
                end_index = start_index
                have_seen_left = False
                while end_index < len(contract_code_block):
                    if contract_code_block[end_index] == '{':
                        bracket_count += 1
                        have_seen_left = True
                    elif contract_code_block[end_index] == '}':
                        bracket_count -= 1
                    end_index += 1
                    if bracket_count == 0 and end_index > start_index and have_seen_left:
                        break
                old_function_code = contract_code_block[start_index:end_index]
                try:
                    signature_old = old_function_code.split(function_name)[1].split(')')[0]
                    signature_new = new_implementation.split(function_name)[1].split(')')[0]
                    if signature_old != signature_new:
                        param_number_1, param_number_2 = len(signature_old.split(',')), len(signature_new.split(','))
                        if param_number_1 != param_number_2 and signature_new in contract_code_block:
                            continue
                        elif signature_new in contract_code_block:
                            param_types_1 = [x.split(' ')[0] for x in signature_old.split(',')]
                            param_types_2 = [x.split(' ')[0] for x in signature_new.split(',')]
                            for i in range(0, len(param_number_1)):
                                if param_types_1[i] != param_types_2[i]:
                                    continue
                except:
                    pass
                if old_function_code not in contract_code:
                    return new_file_path
                contract_code = contract_code.replace(old_function_code, new_implementation)
    contract_code = remove_comments(contract_code)
    contract_code = '// SPDX-License-Identifier: MIT' + '\n' + contract_code 
    with open(target_contract_file_path, 'w') as file:
        file.write(contract_code)
    return new_file_path