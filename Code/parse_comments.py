import re
import os


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


def parse_contract(file_path):
    contracts = {}
    contract_file_list = []
    if os.path.isfile(file_path):
        contract_file_list = [file_path]
    else:
        for root, _, files in os.walk(file_path):
            for file in files:
                if file.endswith(".sol") and 'variant' not in file:
                    contract_file_list.append(os.path.join(root, file))
    for file_path in contract_file_list:
        with open(file_path, 'r') as file:
            file_content = file.read()
        lines = file_content.split('\n')
        contract_pattern = re.compile(r'(abstract contract|contract|interface|library)\s+(\w+)')
        current_contract = []
        current_contract_name = None
        bracket_count = 0
        for line in lines:
            if current_contract_name is None:
                match = contract_pattern.match(line)
                if match:
                    current_contract_name = match.group(2)
                    current_contract.append(line)
                    bracket_count += remove_comments(line).count('{')
                    bracket_count -= remove_comments(line).count('}')
                else:
                    current_contract.append(line)
            else:
                current_contract.append(line)
                bracket_count += remove_comments(line).count('{')
                bracket_count -= remove_comments(line).count('}')
                already_included_content = ''.join(current_contract).strip()
                if '{' in already_included_content and bracket_count == 0:
                    contracts[current_contract_name] = '\n'.join(current_contract)
                    current_contract = []
                    current_contract_name = None
        if current_contract_name is not None:
            contracts[current_contract_name] = '\n'.join(current_contract)
    return contracts