import copy
import json
from slither.slithir.operations import  EventCall, SolidityCall
from slither import Slither
from slither.core.declarations import Function
from slither.core.declarations.modifier import Modifier
from multi_task import propagate_comments_through_LLM_and_static_analysis_with_multiple_task
from chat import propagate_comments_through_LLM_and_static_analysis

def get_comments(comments, contract_name, function_signature):
    function_name = function_signature.split('(')[0]
    if contract_name not in comments:
        return []
    result = []
    added = set()
    for x in comments[contract_name]:
        if function_signature == x['entity'] :
            if x['comment'] in added:
                continue
            added.add(x['comment'])
            result.append(x)
        if (':' in x['entity'] and x['entity'].split(':')[0] == function_name) and (x['level'] == 'variable' or x['level'] == 'statement') and contract_name != function_name:
            if x['comment'] in added:
                continue
            added.add(x['comment'])
            result.append(x)
    return copy.deepcopy(result)

def get_only_function_comments(comments, contract_name, function_signature):
    function_name = function_signature.split('(')[0]
    if contract_name not in comments:
        return []
    result = []
    added = set()
    for x in comments[contract_name]:
        if x['entity'] == function_signature:
            if x['comment'] in added:
                continue
            added.add(x['comment'])
            result.append(x)
    return copy.deepcopy(result)


def get_variable_comments(comments,variable_name):
    result = []
    for contract_name in comments:
        for x in comments[contract_name]:
            if ':' in x['entity'] and x['level'] == 'variable':
                if x['entity'].split(':')[1] == variable_name:
                    result.append(x)
    return result

def get_error_comments(comments, error_function_name):
    result = []
    for contract_name in comments:
        for x in comments[contract_name]:
            if ':' in x['entity'] and x['level'] == 'variable':
                if x['entity'].split(':')[1] in error_function_name:
                    result.append(x)
    return result


def functions_implementation_shadowed(func):
    """
        Return the list of functions shadowed
    Returns:
        list(core.Function)

    """
    candidates = [c.functions for c in func.contract.inheritance]
    candidates = [candidate for sublist in candidates for candidate in sublist]
    return [f for f in candidates if f.full_name == func.full_name]



def get_related_code_and_comments(comments, function: Function, slither_instance):
    result = []
    for shadowed_function in functions_implementation_shadowed(function):
        if shadowed_function.is_constructor:
            continue
        if shadowed_function.contract.is_interface:
            comments_to_propagate = get_comments(comments, shadowed_function.contract.name, shadowed_function.solidity_signature)
            for x in comments_to_propagate:
                x['contract'] =  shadowed_function.contract.name

            if comments_to_propagate:
                
                result.append(
                    {
                        'type': f"Implement",
                        'comments_to_propagate': comments_to_propagate.copy(),
                    }
                )

        else:
            if shadowed_function.view and function.view and (function.source_mapping.content != shadowed_function.source_mapping.content):
                continue
            comments_to_propagate = get_comments(comments, shadowed_function.contract.name, shadowed_function.solidity_signature)
            for x in comments_to_propagate:
                x['contract'] =  shadowed_function.contract.name
            if comments_to_propagate:
                
                result.append(
                    { 
                        'type': f"Override",
                        'comments_to_propagate': comments_to_propagate,
                    }
                )
    comments_to_propagate = []
    for other_function in function.contract.functions:
        if other_function.signature_str == function.signature_str or other_function.is_constructor:
            continue
        if other_function.name == function.name:
            comments_to_propagate = get_only_function_comments(comments, other_function.contract.name, other_function.solidity_signature)
            for x in comments_to_propagate:
                x['contract'] =  other_function.contract.name
            if comments_to_propagate:
                
                result.append(
                    { 
                        'type': f"Overload",
                        'comments_to_propagate': comments_to_propagate,
                    }
                )
    called_functions = function.internal_calls
    called_functions.extend([x[0] for x in function.library_calls])     
    called_functions.extend([x[0] for x in function.high_level_calls])        
    called_functions.extend(function.modifiers)    
       
    comments_to_propagate = []
    for callee in called_functions:
        if isinstance(callee, Function) and not isinstance(callee, Modifier):
            if callee.signature_str == function.signature_str:
                continue
            comments_to_propagate = get_only_function_comments(comments, callee.contract_declarer.name, callee.solidity_signature)
            for x in comments_to_propagate:
                x['contract'] =  callee.contract.name
            
            if len(comments_to_propagate) > 0:
                new_comment = comments_to_propagate[0]
                merged_comment_content = ' '.join([x['comment'] for x in comments_to_propagate])
                new_comment['comment'] = merged_comment_content
                result.append(
                    { 
                        'type': f"Call",
                        'comments_to_propagate': [new_comment],
                    }
                )
        elif isinstance(callee, Modifier):
            comments_to_propagate = get_only_function_comments(comments, callee.contract_declarer.name, callee.name)
            for x in comments_to_propagate:
                x['contract'] =  function.contract.name

            if comments_to_propagate:
                
                result.append(
                    { 
                        'type': f"Call",
                        'comments_to_propagate': comments_to_propagate,
                    }
                )
 
    def_use_comments = []
    comments_to_propagate = []
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, EventCall):
                event_name  = ir.name
                comments_to_propagate.extend(get_variable_comments(comments, event_name))
    for x in comments_to_propagate:
        x['level'] = 'variable:event'
        x['comment'] = 'The definition of the event ' + x['entity'] + ':' + x['comment']
    def_use_comments.extend(comments_to_propagate)
    
    comments_to_propagate = []
    
    
    
    
    
    
    

    comments_to_propagate = []
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                comments_to_propagate = get_error_comments(comments, ir.function.name)
    for x in comments_to_propagate:
        x['level'] = 'variable:error'
        x['comment'] = 'The definition of the error ' + x['entity'] + ':' + x['comment']

    def_use_comments.extend(comments_to_propagate)
    if def_use_comments:
        result.append(
            { 
                'type': f"Def-Use",
                'comments_to_propagate': def_use_comments,
            }
        )
        
            

    return result


def function_comment_propagation_multi_task(func_contract_pairs, comments, slither_instance, max_tasks_per_prompt=5):
    tasks = []
    propagated_comments = {}

    for func, contract in func_contract_pairs:
        propagated_comments[(func, contract)] = []
        comments_related_to_function = get_related_code_and_comments(comments, func, slither_instance)
        comments_for_function = get_comments(comments, contract.name, func.solidity_signature)
        comments_related_to_function = remove_already_included_comments(comments_for_function, comments_related_to_function)
        if len(comments_related_to_function) == 0:
            propagated_comments[(func, contract)] = comments_for_function
            continue
        tasks.append({
            'contract': contract,
            'function': func,
            'comments': comments_for_function,
            'comments_to_propagate': comments_related_to_function
        })
        propagated_comments[(func, contract)] = comments_for_function

    if not tasks:
        return propagated_comments

    for i in range(0, len(tasks), max_tasks_per_prompt):
        task_batch = tasks[i:i + max_tasks_per_prompt]
        propagated_comments_batch = propagate_comments_through_LLM_and_static_analysis_with_multiple_task(task_batch)
        if propagated_comments_batch is None:
            continue
        if len(propagated_comments_batch) != len(task_batch):
            continue
        for j in range(len(task_batch)):
            func_contract_pair = (task_batch[j]['function'], task_batch[j]['contract'])
            task_batch[j]['comments'].extend(propagated_comments_batch[j]['comments'])
            propagated_comments[func_contract_pair] = task_batch[j]['comments']

    return propagated_comments

def function_comment_propagation(contract, function, comments, slither_instance):
    comments_related_to_function = get_related_code_and_comments(comments, function, slither_instance)
    comments_for_function = get_comments(comments, contract.name, function.solidity_signature)
    if len(comments_related_to_function) == 0:
        return comments_for_function
    comments_related_to_function = remove_already_included_comments(comments_for_function, comments_related_to_function)
    if len(comments_related_to_function) == 0:
        return comments_for_function
    propagated_comments = propagate_comments_through_LLM_and_static_analysis(contract, function, comments_for_function, comments_related_to_function)
    if propagated_comments:
        return propagated_comments
    else:
        return comments_for_function


def pre_propagate_comments(comments, slither_instance):
    new_comments = propagate_comments_through_contract_relation(comments, slither_instance)
    return new_comments

def remove_spaces_from_text(text):
    text = text.replace(" ", "").replace("\n", "")
    return text

def remove_already_included_comments(comments_target, comments_to_propagate):
    left_comments_to_propagate = []
    comments_target_content = [x['comment'] for x in comments_target]
    for x in comments_to_propagate:
        comments_to_propagate_cotent = [y['comment'] for y in x['comments_to_propagate']]
        is_not_contained = False
        for x_content in comments_to_propagate_cotent:
            for target_comment in comments_target_content:
                if x_content not in target_comment:
                    is_not_contained = True
                    break
        if is_not_contained:
            left_comments_to_propagate.append(x)
        else:
            continue
        left_comments_to_propagate.append(x)
    
    
    seen_comments = set()  
    unique_comments_to_propagate = []

    for item in left_comments_to_propagate:
        unique_comments = []
        for comment in item['comments_to_propagate']:
            included_by_seen = False
            for seen_comment in seen_comments:
                if remove_spaces_from_text(comment['comment']) in seen_comment:
                    included_by_seen = True
                    break
            if included_by_seen:
                continue
            else:
                unique_comments.append(comment)
                seen_comments.add(remove_spaces_from_text(comment['comment']))
        
        if unique_comments:
            item['comments_to_propagate'] = unique_comments
            unique_comments_to_propagate.append(item)

            
    return unique_comments_to_propagate

































def propagate_comments_through_define_and_use(comments, slither_instance:Slither):
    
    propagated_comments = comments.copy()
    contract_variable = {}
    contract_event = {}
    contract_error = {}
    for contract in slither_instance.contracts:
        contract_name = contract.name
        if contract_name not in contract_variable:
            contract_variable[contract_name] = {}
            contract_event[contract_name] = {}
            contract_error[contract_name] = {}
    for contract_name, contract_comments in comments.items():
        contract_variable_comments = [x for x in contract_comments if x['level'] == 'variable' and x['entity'].split(':')[0] == contract_name]
        contract = slither_instance.get_contract_from_name(contract_name)[0]
        for event in contract.events:
            for comment in contract_variable_comments:
                if comment['entity'].split(':')[1] == event.name:
                    if event.name not in contract_event[contract_name]:
                        contract_event[contract_name][event.name] = [comment]
                    else:
                        contract_event[contract_name][event.name].append(comment)
        for var in contract.variables:
            for comment in contract_variable_comments:
                if comment['entity'].split(':')[1] == var.name:
                    if var.name not in contract_variable[contract_name]:
                        contract_variable[contract_name][var.name] = [comment]
                    else:
                        contract_variable[contract_name][var.name].append(comment)
        for error in contract.custom_errors :
            for comment in contract_variable_comments:
                if comment['entity'].split(':')[1] == error.name:
                    if error.name not in contract_error[contract_name]:
                        contract_error[contract_name][error.name] = [comment]
                    else:
                        contract_error[contract_name][error.name].append(comment)
    
    for contract in slither_instance.contracts:
        for function in contract.functions:
            variables = function.variables
            variables.extend(function.state_variables_read)
            variables.extend(function.state_variables_written)
            for var in variables:
                if var.name in contract_variable[contract.name]:
                    for comment in contract_variable[contract.name][var.name]:
                        new_comment = comment.copy()
                        new_comment['entity'] = function.name + ':' + var.name 
                        propagated_comments[contract.name].append(new_comment)
                        
    
    for contract in slither_instance.contracts:
        for function in contract.functions:
            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, EventCall):
                        if ir.name in contract_event[contract.name]:
                            for comment in contract_event[contract.name][ir.name]:
                                new_comment = comment.copy()
                                new_comment['entity'] = function.name + ':' + ir.name 
                                propagated_comments[contract.name].append(new_comment)
                                
    
    for contract in slither_instance.contracts:
        for function in contract.functions:
            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, SolidityCall):
                        
                        for error_name in contract_error[contract.name]:
                            if error_name not in ir.function.name:
                                continue
                            for comment in contract_error[contract.name][error_name]:
                                new_comment = comment.copy()
                                new_comment['entity'] = function.name + ':' + error_name 
                                propagated_comments[contract.name].append(new_comment)
                                
    

    return propagated_comments



def propagate_comments_through_contract_relation(comments, slither_instance):
    contract_relations = {}
    for contract in slither_instance.contracts:
        contract_relations[contract.name] = {
            'inherited_contracts': [base for base in contract.inheritance],
            'functions': [],
        }
        for function in contract.functions:
            contract_relations[contract.name]['functions'].append(function.solidity_signature)

    propagated_comments = {}
    for contract_name, contract_comments in comments.items():
        propagated_comments[contract_name] = contract_comments.copy()
        if contract_name not in contract_relations:
            continue
        
        for inherited_contract in contract_relations[contract_name]['inherited_contracts']:
            if inherited_contract.name in comments and inherited_contract.is_interface:
                for comment_to_propagate in comments[inherited_contract.name]:
                    if comment_to_propagate['level'] == 'function':
                        is_public_and_view = False
                        try:
                            function_instance = inherited_contract.get_function_from_signature(comment_to_propagate['entity'])
                            if function_instance.visibility == 'public' or function_instance.visibility == 'external':
                                if function_instance.view or function_instance.pure:
                                    is_public_and_view = True
                        except:
                            is_public_and_view = False

                        
                        if comment_to_propagate['entity'] in contract_relations[contract_name]['functions']:
                            if not is_public_and_view:
                                
                                propagated_comments[contract_name].append(comment_to_propagate)
                            
                                
                        
    
    
    

        
                        
                    
                    
                    
                    
                    


    return propagated_comments
