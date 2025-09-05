import os
from rewrite_smart_contracts import smart_contract_rewrite_with_diff_func
from diffusc.diff import write_diff_test, execute_diff_test
from diffusc.utils.slither_provider import FileSlitherProvider
from solc_select.solc_select import switch_global_version
from slither import Slither
from slither.core.declarations import Function, SolidityFunction
from slither.slithir.operations import EventCall
from get_slither_instance import get_slither_instance_from_crytic_export
from slither.core.declarations.modifier import Modifier
from slither.slithir.operations import BinaryType, Binary
from slither.slithir.variables.constant import Constant
from slither.slithir.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from get_slither_instance import get_slither_instance_from_crytic_export
from coverage import check_covered, is_public_or_external
from scope_analysis import contain_external_call_to_unknown_address, get_function_call_recursively

def write_diff_test_to_file(file_path, new_file_path, contract_name, influenced_main_contract_funcs, solc_version, construtor_arguments, inconsistency_idx):
    output_dir = os.path.join(os.path.dirname(os.path.abspath(file_path)), 'Diff_' + str(inconsistency_idx))
    analysis_result = write_diff_test(file_path, new_file_path, contract_name, output_dir, influenced_main_contract_funcs, solc_version, construtor_arguments)
    return analysis_result

def execute_diff_test_to_file(file_path, new_file_path, contract_name, influenced_main_contract_funcs, solc_version, construtor_arguments, inconsistency_idx, inconsistency):
    output_dir = os.path.join(os.path.dirname(os.path.abspath(file_path)), 'Diff_' + str(inconsistency_idx))
    diff = execute_diff_test(file_path, new_file_path, contract_name, output_dir, influenced_main_contract_funcs, solc_version, construtor_arguments)
    switch_global_version(solc_version, True)
    slither = Slither(new_file_path)
    covered = check_covered(inconsistency['function'], inconsistency['contract'], output_dir, slither)
    if diff:
        return True
    elif (not covered):
        return True
    elif not diff and covered:
        return False
    raise Exception("Diff test failed to execute")

def check_inconsistency_with_diff_test(file_path, new_file_path, contract_name, influenced_main_contract_funcs, solc_version, construtor_arguments, inconsistency_idx):
    output_dir = os.path.join(os.path.dirname(os.path.abspath(file_path)), 'Diff_' + str(inconsistency_idx))
    analysis_result = write_diff_test(file_path, new_file_path, contract_name, output_dir, influenced_main_contract_funcs, solc_version, construtor_arguments)
    diff = execute_diff_test(file_path, new_file_path, contract_name, output_dir, influenced_main_contract_funcs, solc_version, construtor_arguments, analysis_result)
    return diff

def all_function_contains_external_call_to_unknown_address(file_path, new_file_path, contract_name, influenced_main_contract_funcs, solc_version, inconsistency_to_check):
    try:
        slither_V1 = get_slither_instance_from_crytic_export(file_path, contract_name, solc_version)
        slither_V2 = get_slither_instance_from_crytic_export(new_file_path, contract_name, solc_version)
        contract_V1 = slither_V1.get_contract_from_name(contract_name)[0]
        contract_V2 = slither_V2.get_contract_from_name(contract_name)[0]
    except Exception as e:
        return False, e
    all_check_contains_external_call_to_unknown_address = False
    for func in inconsistency_to_check['rewritten_code']:
        func_V1 = get_function_instance_from_name(contract_V1, func)
        if not contain_external_call_to_unknown_address(func_V1):
            all_check_contains_external_call_to_unknown_address = False
            break
    if all_check_contains_external_call_to_unknown_address:
        return True
    else:
        return False

def get_function_instance_from_signature(contract, signature):
    for func in contract.functions:
        if func.signature_str == signature and func.is_implemented:
            return func
    return None

def get_function_instance_from_name(contract, name):
    for func in contract.functions:
        if func.name == name:
            return func
    return None

def get_function_instances_from_name(contract1, contract2, name):
    if '(' in name:
        name = name.split('(')[0]
    matched_pairs = []
    signature_mismatch = False
    potential_function_1s = []
    potential_function_2s = []
    already_added_1 = set()
    already_added_2 = set()
    for func in contract1.functions:
        if func.name == name and func.is_implemented:
            if func.signature_str not in already_added_1:
                already_added_1.add(func.signature_str)
                potential_function_1s.append(func)
    for func in contract2.functions:
        if func.name == name and func.is_implemented:
            if func.signature_str not in already_added_2:
                already_added_2.add(func.signature_str)
                potential_function_2s.append(func)
    if len(already_added_1) == 0 and len(already_added_2) == 0:
        return None, False
    if len(already_added_1) != len(already_added_2):
        return None, True
    for func1 in potential_function_1s:
        for func2 in potential_function_2s:
            if func1.signature_str == func2.signature_str:
                external_or_public_func1 = (func1.visibility =='external' or func1.visibility =='public') 
                external_or_public_func2 = func2.visibility =='external' or func2.visibility =='public'
                if external_or_public_func1 != external_or_public_func2:
                    return None, True
                matched_pairs.append((func1, func2))
                already_added_1.remove(func1.signature_str)
                already_added_2.remove(func2.signature_str)
                break
    if len(already_added_1) == 0 and len(already_added_2) == 0:
        return matched_pairs, False
    else:
        return matched_pairs, True

def check_inconsistency_static(file_path, new_file_path, contract_name, influenced_main_contract_funcs, solc_version, inconsistency_to_check):
    def different_function_call(func_V1, func_V2):
        for var in [x.name for x in  func_V1.modifiers]:
            if var not in [x.name for x in func_V2.modifiers]:
                return True
        for var in [x.name for x in  func_V2.modifiers]:
            if var not in [x.name for x in func_V1.modifiers]:
                return True
        for var in [x.signature_str for x in func_V1.internal_calls if isinstance(x, Function) and not x.view]:
            if var not in [x.signature_str for x in func_V2.internal_calls if isinstance(x, Function) and not x.view]:
                return True
        for var in [x.signature_str for x in func_V2.internal_calls  if isinstance(x, Function)  and not x.view]:
            if var not in [x.signature_str for x in func_V1.internal_calls  if isinstance(x, Function)  and not x.view]:
                return True
        return False
    def different_state_written(func_V1: Function, func_V2: Function):
        function_called_by_func1 = []
        get_function_call_recursively(func_V1, function_called_by_func1)
        function_called_by_func2 = []
        get_function_call_recursively(func_V2, function_called_by_func2)
        var_1 = [x.name for x in func_V1.state_variables_written]
        var_2 = [x.name for x in func_V2.state_variables_written]
        for func in function_called_by_func1:
            var_1.extend([x.name for x in func.state_variables_written])
        for func in function_called_by_func2:
            var_2.extend([x.name for x in func.state_variables_written])
        if (len(set(var_1)) != 0 or len(set(var_2))!=0) and (set(var_1) != set(var_2)):
            return True
        read_var1 = [x.name for x in func_V1.state_variables_read]
        read_var2 = [x.name for x in func_V2.state_variables_read]
        for func in function_called_by_func1:
            read_var1.extend([x.name for x in func.state_variables_read])
        for func in function_called_by_func2:
            read_var2.extend([x.name for x in func.state_variables_read])
        if (len(set(read_var1)) != 0 or len(set(read_var2))!=0) and (set(read_var1) != set(read_var2)):
            return True
        return False
    def different_event_param(func_V1: Function, func_V2: Function):
        def get_events_with_params_in_funcs(func):
            result = {}
            for node in func.nodes:
                for ir in node.irs:
                    if isinstance(ir, EventCall):
                        result[ir.name] = [x.name for x in ir.arguments]
            return result
        events_V1 = get_events_with_params_in_funcs(func_V1)
        events_V2 = get_events_with_params_in_funcs(func_V2)
        for event_name in events_V1:
            if event_name not in events_V2:
                continue
            for param in events_V1[event_name]:
                if param not in events_V2[event_name]:
                    continue
                idx_V1 = events_V1[event_name].index(param)
                idx_V2 = events_V2[event_name].index(param)
                if idx_V1 != idx_V2:
                    return True
        return False
    def call_less_or_more_function(func_V1: Function, func_V2: Function):
        function_called_in_condition_1 = set()
        function_called_in_condition_2 = set()
        for node in func_V1.nodes:
            if node.is_conditional():
                for func in node.internal_calls:
                    if isinstance(func, Function) and len(func.state_variables_read) > 0:
                        function_called_in_condition_1.add(func.signature_str)
        for node in func_V2.nodes:
            if node.is_conditional():
                for func in node.internal_calls:
                    if isinstance(func, Function) and len(func.state_variables_read) > 0:
                        function_called_in_condition_2.add(func.signature_str)
        if function_called_in_condition_1!= function_called_in_condition_2:
            return True
    def call_less_or_more_modifier(func_V1: Function, func_V2: Function):
        function_called_by_func1 = []
        get_function_call_recursively(func_V1, function_called_by_func1)
        function_called_by_func2 = []
        get_function_call_recursively(func_V2, function_called_by_func2)
        function_1_modifiers = set()
        function_2_modifiers = set()
        for callee in function_called_by_func1:
            if isinstance(callee, Modifier) :
                function_1_modifiers.add(callee.signature_str)
        for callee in function_called_by_func2:
            if isinstance(callee, Modifier) :
                function_2_modifiers.add(callee.signature_str)
        if function_1_modifiers.issubset(function_2_modifiers) and len(function_1_modifiers) < len(function_2_modifiers):
            return True
        if function_2_modifiers.issubset(function_1_modifiers) and len(function_2_modifiers) < len(function_1_modifiers):
            return True
        if function_1_modifiers == function_2_modifiers:
            return False
        return False
    def different_condition_operator_or_operand(func_V1: Function, func_V2: Function):
        def get_condition_operations_in_funcs(func):
            result = []
            for node in func.nodes:
                for ir in node.irs:
                    if isinstance(ir, Binary) and ir.type.return_bool(ir.type):
                        result.append((ir.lvalue.name, ir.variable_left, ir.variable_right, ir.type))
            return result
        conditions_1 = get_condition_operations_in_funcs(func_V1)
        conditions_2 = get_condition_operations_in_funcs(func_V2)
        for condition_1 in conditions_1:
            for condition_2 in conditions_2:
                if condition_1[0] == condition_2[0]:
                    if not isinstance(condition_1[1], Constant) and not isinstance(condition_1[2], Constant):
                        if not (isinstance(condition_1[1], Variable) and condition_1[1].is_constant) and not (isinstance(condition_1[2], Variable) and condition_1[2].is_constant):
                            continue
                    if not isinstance(condition_2[1], Constant) and not isinstance(condition_2[2], Constant):
                        if not (isinstance(condition_2[1], Variable) and condition_2[1].is_constant) and not (isinstance(condition_2[2], Variable) and condition_2[2].is_constant):
                            continue
                    if (condition_1[1].name != condition_2[1].name and condition_1[2].name == condition_2[2].name) or (condition_1[1].name == condition_2[1].name and condition_1[2].name != condition_2[2].name):
                        return True
                    if condition_1[3] != condition_2[3] and condition_1[1].name == condition_2[1].name and condition_1[2].name == condition_2[2].name:
                        return True
        constant_number_in_condition_1 = set()
        constant_number_in_condition_2 = set()
        for condition_1 in conditions_1:
            if isinstance(condition_1[1], Constant):
                constant_number_in_condition_1.add(condition_1[1].value)
            if isinstance(condition_1[2], Constant):
                constant_number_in_condition_1.add(condition_1[2].value)
        for condition_2 in conditions_2:
            if isinstance(condition_2[1], Constant):
                constant_number_in_condition_2.add(condition_2[1].value)
            if isinstance(condition_2[2], Constant):
                constant_number_in_condition_2.add(condition_2[2].value)
        if len(set(constant_number_in_condition_1) & set(constant_number_in_condition_2)) == 0 and (len(set(constant_number_in_condition_1)) != 0 and len(set(constant_number_in_condition_2)) != 0):
            return True
        state_var_in_revert_or_assert_v1 = set()
        state_var_in_revert_or_assert_v2 = set()
        for node in func_V1.nodes:
            if node.contains_require_or_assert():
                state_var_in_revert_or_assert_v1.update([x.name for x in node.state_variables_read])
        for node in func_V2.nodes:
            if node.contains_require_or_assert():
                state_var_in_revert_or_assert_v2.update([x.name for x in node.state_variables_read])
        if (state_var_in_revert_or_assert_v1 < state_var_in_revert_or_assert_v2 or state_var_in_revert_or_assert_v2 < state_var_in_revert_or_assert_v1):
            return True
        else:
            return False
        return False
    def different_event_emit(func_V1: Function, func_V2: Function):
        def get_events_in_funcs(func):
            result = []
            for node in func.nodes:
                for ir in node.irs:
                    if isinstance(ir, EventCall):
                        result.append(ir.name + ''.join([str(x.type) for x in ir.arguments]))
            return result
        function_called_by_func1 = []
        get_function_call_recursively(func_V1, function_called_by_func1)
        function_called_by_func2 = []
        get_function_call_recursively(func_V2, function_called_by_func2)
        events_V1 = set(get_events_in_funcs(func_V1))
        events_V2 = set(get_events_in_funcs(func_V2))
        for func in function_called_by_func1:
            events_V1.update(get_events_in_funcs(func))
        for func in function_called_by_func2:
            events_V2.update(get_events_in_funcs(func))
        if len(events_V1) != len(events_V2):
            return True
        for event in events_V1:
            if event not in events_V2:
                return True
        return False
    switch_global_version(solc_version, True)
    try:
        slither_V1 = get_slither_instance_from_crytic_export(file_path, contract_name, solc_version)
        slither_V2 = get_slither_instance_from_crytic_export(new_file_path, contract_name, solc_version)
        contract_V1 = slither_V1.get_contract_from_name(contract_name)[0]
        contract_V2 = slither_V2.get_contract_from_name(contract_name)[0]
    except Exception as e:
        return False
    func = inconsistency_to_check['function']
    function_pairs, mismatched_siganture = get_function_instances_from_name(contract_V1, contract_V2, func)
    if mismatched_siganture:
        return True
    for func_V1, func_V2 in function_pairs:
        if  (func_V1 and not func_V2) or (not func_V1 and func_V2):
            continue
        if not func_V1 and not func_V2:
            continue
        if func_V1.is_constructor and func_V2.is_constructor:
            continue
        if different_state_written(func_V1, func_V2):
            return True
        elif different_event_emit(func_V1, func_V2):
            return True
        elif different_event_param(func_V1, func_V2):
            return True
        elif call_less_or_more_modifier(func_V1, func_V2):
            return True
        elif call_less_or_more_function(func_V1, func_V2):
            return True
        elif different_condition_operator_or_operand(func_V1, func_V2):
            return True
    return False

