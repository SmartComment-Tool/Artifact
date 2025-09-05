import json


def check_function_inconsistency_prompt_v1(tasks, solc_version):
    prompt = f'''Imagine you are a smart contract analyzer specializing in detecting inconsistencies between code and comments in functions.
Your task is to evaluate whether a function's implementation explicitly contradicts the functional logic described in its comments.
Each analysis task should be handled independently. Follow this structured process:


    Analyze all comments individually. Treat all comments as authoritative and assume they describe the intended behavior of the function accurately.
    Consider all provided function implementations, including those called by the target function and those that call the target function.

The common types of inconsistencies include:
    (1) Missing Access Controls: For instance, if the comment specifies owner-only access but the implementation lacks such control.
    (2) Missing Variable/Parameter Checks: For example, if the comment specifies input validation, but the function (or the functions it calls) does not perform the required checks. If the check is already performed in a called function, do NOT flag it as inconsistent.
    (3) Missing Key Operations: For example, if the comment specifies emitting an event, but the function (or the functions it calls) does not emit the event. If the operation is performed in a called function, do NOT flag it as inconsistent.
    (4) Incorrect Key Logic: If the implementation clearly violates the comments, such as transferring tokens to an incorrect address.
    (5) Mismatched Input/Output Interface: For example, if the comment specifies a return value, but the function does not return anything.

Focus only on inconsistencies that cause functional differences. For example, if the function has improper visibility (pure/view), but the comment does not explicitly specify the required visibility, do NOT flag it as inconsistent. Similarly, do not flag inconsistencies based on recommendations, optimizations, or ambiguous comments.
If the inconsistency arises from a missing check or operation, verify whether it is already performed in a called function. If yes, do NOT flag it as inconsistent. If the comment lacks sufficient detail to determine correctness, do NOT flag it as inconsistent.
If the comment assumes some condition will be pre-checked, but the implementation check it again, do NOT flag it as inconsistent.
If the comments are too short or ambiguous to determine whether the implementation is incorrect, do not flag as inconsistent.
You should only check the comment that explicilty provided to you. For example, if the comment is not self-contained, such as refering to external interface/documentation/links, do not flag as inconsistent.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.



Comments related to the target function are provided in a JSON list with the following fields:
- 'comment': The text of the comment.
- 'entity': The entity the comment belongs to.
- 'level': The level of the entity, which can be 'contract', 'function', 'statement', or 'variable'.
    (1) 'contract' level comments describe the overall functionality of the contract.
    (2) 'function' level comments describe the functionality of the function and are critical for detecting inconsistencies.
    (3) 'statement' level comments explain the purpose of specific statements and help in understanding the code logic.
    (4) 'variable' level comments describe the definition and usage of variables, events, or errors in Solidity.


If an inconsistency is detected, you must provide a corrected and self-contained implementation of the target function:
    (1) 'explanation': A brief reason (up to 50 words) for the inconsistency.
    (2) 'violated_comment': The specific part of the comment that the function contradicts. Concatenate multiple comments into a single string, sorted in their original order.
    (3) 'improved_implementation': A dictionary suggesting corrections. You can only modify the target function, rather than all functions in the analysis. If the target function needs changes, use its name as the key and the new implementation as the value. You need to provide the full corrected code of the target function. You corrected implementation should only use the functions that exist in the provided contract interface when modifying the code.
    The new implementation of the target function will be compiled using the Solidity compiler version {solc_version}.



==== Output Requirements ====
OUTPUT: Generate a JSON Array object. Each array item should be with the following structure:
    (1) If no inconsistency exists: {{"task": Task number, "result": true}}
    (2) If an inconsistency exists:
    {{
        "task": Task number,
        "result": false,
        "explanation": "Brief technical reason for mismatch ≤50 words",
        "violated_comment": "Exact contradictory comment fragment",
        "improved_implementation": {{
            "function_name": "Full corrected code of the function",
        }}
    }}
Strictly adhere to JSON formatting. Do not include any additional text outside the JSON.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        function_related_code = task['function_related_code']
        contract_interface = task['contract_interface']
        
        prompt += f'''

=== Comments to Check ===
{function_comment}

=== The implementation of the Target Function {function_name} ===
{function_related_code}

=== Interface of the Contract ===
{contract_interface}
'''

    return prompt



def check_function_inconsistency_prompt_v2(tasks, solc_version):
    prompt = f'''Imagine you are a smart contract analyzer with expertise in identifying inconsistencies between code and comments in functions.
Your task is to determine whether a function's implementation explicitly contradicts the functional logic described in its comments.
Each task must be handled independently. Follow this structured process:


    Review all comments one by one. Treat all comments as the authoritative source of truth, assuming they accurately describe the intended behavior of the function.
    In your analysis, consider all provided function implementations, including those invoked by the target function and those that invoke the target function.

The common types of inconsistencies include, but are not limited to:
    (1) Missing Access Controls: For example, if the comment specifies that the function should only be accessible by the owner, but the implementation lacks such access control.
    (2) Missing Variable/Parameter Checks: For instance, if the comment specifies that an input parameter should be validated, but the function (or the functions it calls) does not perform the required validation. If the check is already performed in a called function, do NOT flag it as inconsistent.
    (3) Missing Key Operations: For example, if the comment specifies that an event should be emitted, but the function (or the functions it calls) does not emit the event. If the operation is performed in a called function, do NOT flag it as inconsistent.
    (4) Incorrect Key Logic: If the implementation clearly violates the comments, such as transferring tokens to an incorrect address.
    (5) Mismatched Input/Output Interface: For example, if the comment specifies a return value, but the function does not return anything.

Focus only on inconsistencies that cause functional differences. For example, if the function has improper visibility (pure/view), but the comment does not explicitly specify the required visibility, do NOT flag it as inconsistent. Similarly, do not flag inconsistencies based on recommendations, optimizations, or ambiguous comments.
If the inconsistency arises from a missing check or operation, verify whether it is already performed in a called function. If yes, do NOT flag it as inconsistent. If the comment lacks sufficient detail to determine correctness, do NOT flag it as inconsistent.
If the comment assumes some condition will be pre-checked, but the implementation check it again, do NOT flag it as inconsistent.
If the comments are too short or ambiguous to determine whether the implementation is incorrect, do not flag as inconsistent.
You should only check the comment that explicilty provided to you. For example, if the comment is not self-contained, such as refering to external interface/documentation/links, do not flag as inconsistent.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.



Comments related to the target function are provided in a JSON list with the following fields:
- 'comment': The text of the comment.
- 'entity': The entity the comment belongs to.
- 'level': The level of the entity, which can be 'contract', 'function', 'statement', or 'variable'.
    (1) 'contract' level comments describe the overall functionality of the contract.
    (2) 'function' level comments describe the functionality of the function and are critical for detecting inconsistencies.
    (3) 'statement' level comments explain the purpose of specific statements and help in understanding the code logic.
    (4) 'variable' level comments describe the definition and usage of variables, events, or errors in Solidity.


If an inconsistency is detected, you must provide a corrected and self-contained implementation of the target function:
    (1) 'explanation': A brief reason (up to 50 words) for the inconsistency.
    (2) 'violated_comment': The specific part of the comment that the function contradicts. Concatenate multiple comments into a single string, sorted in their original order.
    (3) 'improved_implementation': A dictionary suggesting corrections. You can only modify the target function, rather than all functions in the analysis. If the target function needs changes, use its name as the key and the new implementation as the value. You need to provide the full corrected code of the target function. You corrected implementation should only use the functions that exist in the provided contract interface when modifying the code.
    The new implementation of the target function will be compiled using the Solidity compiler version {solc_version}.


==== Output Requirements ====
OUTPUT: Generate a JSON Array object. Each array item should be with the following structure:
    (1) If no inconsistency exists: {{"task": Task number, "result": true}}
    (2) If an inconsistency exists:
    {{
        "task": Task number,
        "result": false,
        "explanation": "Brief technical reason for mismatch ≤50 words",
        "violated_comment": "Exact contradictory comment fragment",
        "improved_implementation": {{
            "function_name": "Full corrected code of the function",
        }}
    }}
Strictly adhere to JSON formatting. Do not include any additional text outside the JSON.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        function_related_code = task['function_related_code']
        contract_interface = task['contract_interface']
        
        prompt += f'''

=== Comments to Check ===
{function_comment}

=== The implementation of the Target Function {function_name} ===
{function_related_code}

=== Interface of the Contract ===
{contract_interface}
'''

    return prompt



def check_function_inconsistency_prompt_v3(tasks, solc_version):
    prompt = f'''Assume you are a smart contract analyzer specialized in analyzing code-comment inconsistencies in functions.
Your need to evaluate whether a function's implementation explicitly contradicts the functional logic described in its comments.
You need to handle the following analysis tasks. Each task should be processed separately. 
Follow the following structured analysis process:


    Examine all comments one by one. You should treat all comments as authoritative truth, i.e., assume the comments are correct and describe the intended behavior of the function.
    In your analysis, consider all provided function implementations, including those called by the target function and those that call the target function.

The common inconsistencies include, but are not limited to:
    (1) Lack of Access controls. For example, the comment specifies owner-only access but the implementation lacks such control.
    (2) Lack of Variable/Parameter checks (require/revert/if statements). For example, the comment says the function should check the range of an input parameter, but the function (and the function it calls) do not have any check.  You need also to verify whether other functions it internally calls have already performed this check. If yes, do NOT flag as inconsistent.
    (3) Missing Key Operations explicitly required by the comments. For example, the comment says the function should emit an event, but the function (and the function it calls) do not emit that specific event. You need also to verify whether other functions it internally calls have already performed this operation. If yes, do NOT flag as inconsistent.
    (4) Wrong Key Function Logic. If comments lack sufficient information to determine incorrect implementation, do not flag as inconsistent. Flag only when implementation clearly violates comments, such as transferring tokens to the wrong address.
    (5) Different Input/Output Interface. For example, the comment declares return value but function returns none.

You should only focus on inconsistencies that cause real functional differences. For example, if you find the function has improper visibility(pure/view), but the comment does not explictly specify it must use which visability, the inconsistency is NOT valid. If the comment is a suggestion/recommendation/usage description of a function, do NOT flag as inconsistent.
If the comments are too short or ambiguous to determine whether the implementation is incorrect, do not flag as inconsistent.
If the comment assumes some condition will be pre-checked, but the implementation check it again, do NOT flag it as inconsistent.
You should only check the comment that explicilty provided to you. For example, if the comment is not self-contained, such as refering to external interface/documentation/links, do not flag as inconsistent.
If the inconsistency is due to a missing check/operation in the target function, verify whether other functions it internally calls have already performed this check/operation. If yes, do NOT flag as inconsistent.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.

Comments related to the target function are provided in a JSON list, with each item containing a 'level', 'comment', and 'entity'.
- 'comment' is the text of the comment.
- 'entity' is the entity the comment belongs to.
- 'level' specifies the entity's level, which can be 'contract', 'function', 'statement', or 'variable'.
    (1) the 'contract' level comments usually describes the main definition/functionality/operation/interface about the contract.
    (2) the 'function' level comments usually describes the main definition/functionality/operation/interface about the function. It is essential for the detection of code-comment inconsistencies.
    (3) the 'statement' level comments typically explain the intended purpose of a specific statement. It can help you understand the hign-level code logic.
    (4) the 'variable' level comments usually describes the definition and usage of a variable/event/error in Solidity. It can help you understand the semantic of the variable/event/error used in the function.


If an inconsistency is detected, you must provide a corrected and self-contained implementation of the target function:
    (1) 'explanation': A brief reason (up to 50 words) for the inconsistency.
    (2) 'violated_comment': The specific part of the comment that the function contradicts. If there are multiple comments, you need to concatenate them into a single string. The comments should be sorted in the same order as they appear in the original code.
    (3) 'improved_implementation': A dictionary suggesting corrections. You can only modify the target function, rather than all functions in the analysis. If the target function needs changes, use its name as the key and the new implementation as the value. You need to provide the full corrected code of the target function. You corrected implementation should only use the functions that exist in the provided contract interface when modifying the code.
    The new implementation of the target function will be compiled using the Solidity compiler version {solc_version}.


==== Output Requirements ====
OUTPUT: Generate a JSON Array object. Each array item should be with the following structure:
    (1) If there is no inconsistency, each result item should be a JSON object: {{"task": Task number,"result": true}}
    (2) If the implementation violates the comments, each result item should be the JSON object:
    {{
        "task": Task number,
        "result": false,
        "explanation": "Brief technical reason for mismatch ≤50 words",
        "violated_comment": "Exact contradictory comment fragment", 
        "improved_implementation": {{
            "function_name": "Full corrected code of the target function",
        }}
    }}
You need to follow strict JSON formatting. No additional text outside JSON.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        function_related_code = task['function_related_code']
        contract_interface = task['contract_interface']
        
        prompt += f'''

=== Comments to Check ===
{function_comment}

=== The implementation of the Target Function {function_name} ===
{function_related_code}

=== Interface of the Contract ===
{contract_interface}
'''

    return prompt

def check_function_inconsistency_prompt_v4(tasks, solc_version):
    prompt = f'''Assume you are a smart contract analyzer specializing in detecting inconsistencies between code and comments in functions.
Your task is to evaluate whether a function's implementation explicitly contradicts the functional logic described in its comments.
Each analysis task should be handled independently. Follow this structured process:


    Analyze all comments individually. Treat all comments as authoritative and assume they describe the intended behavior of the function accurately.
    Consider all provided function implementations, including those called by the target function and those that call the target function.

The common types of inconsistencies include:
    (1) Missing Access Controls: For instance, if the comment specifies owner-only access but the implementation lacks such control.
    (2) Missing Variable/Parameter Checks: For example, if the comment specifies input validation, but the function (or the functions it calls) does not perform the required checks. If the check is already performed in a called function, do NOT flag it as inconsistent.
    (3) Missing Key Operations: For example, if the comment specifies emitting an event, but the function (or the functions it calls) does not emit the event. If the operation is performed in a called function, do NOT flag it as inconsistent.
    (4) Incorrect Key Logic: If the implementation clearly violates the comments, such as transferring tokens to an incorrect address.
    (5) Mismatched Input/Output Interface: For example, if the comment specifies a return value, but the function does not return anything.

Focus only on inconsistencies that cause functional differences. For example, if the function has improper visibility (pure/view), but the comment does not explicitly specify the required visibility, do NOT flag it as inconsistent.
If the inconsistency arises from a missing check or operation, verify whether it is already performed in a called function. If yes, do NOT flag it as inconsistent. If the comment lacks sufficient detail to determine correctness, do NOT flag it as inconsistent.
If the comment assumes some condition will be pre-checked, but the implementation check it again, do NOT flag it as inconsistent.
If the comments are too short or ambiguous to determine whether the implementation is incorrect, do not flag as inconsistent.
You should only check the comment that explicilty provided to you. For example, if the comment is not self-contained, such as refering to external interface/documentation/links, do not flag as inconsistent.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.



Comments related to the target function are provided in a JSON list with the following fields:
- 'comment': The text of the comment.
- 'entity': The entity the comment belongs to.
- 'level': The level of the entity, which can be 'contract', 'function', 'statement', or 'variable'.
    (1) 'contract' level comments describe the overall functionality of the contract.
    (2) 'function' level comments describe the functionality of the function and are critical for detecting inconsistencies.
    (3) 'statement' level comments explain the purpose of specific statements and help in understanding the code logic.
    (4) 'variable' level comments describe the definition and usage of variables, events, or errors in Solidity.


If an inconsistency is detected, you must provide a corrected and self-contained implementation of the target function:
    (1) 'explanation': A brief reason (up to 50 words) for the inconsistency.
    (2) 'violated_comment': The specific part of the comment that the function contradicts. Concatenate multiple comments into a single string, sorted in their original order.
    (3) 'improved_implementation': A dictionary suggesting corrections. You can only modify the target function, rather than all functions in the analysis. If the target function needs changes, use its name as the key and the new implementation as the value. You need to provide the full corrected code of the target function. You corrected implementation should only use the functions that exist in the provided contract interface when modifying the code.
    The new implementation of the target function will be compiled using the Solidity compiler version {solc_version}.



==== Output Requirements ====
OUTPUT: Generate a JSON Array object. Each array item should be with the following structure:
    (1) If no inconsistency exists: {{"task": Task number, "result": true}}
    (2) If an inconsistency exists:
    {{
        "task": Task number,
        "result": false,
        "explanation": "Brief technical reason for mismatch ≤50 words",
        "violated_comment": "Exact contradictory comment fragment",
        "improved_implementation": {{
            "function_name": "Full corrected code of the function",
        }}
    }}
Strictly adhere to JSON formatting. Do not include any additional text outside the JSON.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        function_related_code = task['function_related_code']
        contract_interface = task['contract_interface']
        
        prompt += f'''

=== Comments to Check ===
{function_comment}

=== The implementation of the Target Function {function_name} ===
{function_related_code}

=== Interface of the Contract ===
{contract_interface}
'''

    return prompt






def check_function_inconsistency_prompt_v5(tasks, solc_version):
    prompt = f'''Imagine you are a smart contract analyzer specialized in analyzing code-comment inconsistencies in functions.
Your need to evaluate whether a function's implementation explicitly contradicts the functional logic described in its comments.
You need to handle the following analysis tasks. Each task should be processed separately. 
Follow the following structured analysis process:


    Examine all comments one by one. You should treat all comments as authoritative truth, i.e., assume the comments are correct and describe the intended behavior of the function.
    In your analysis, consider all provided function implementations, including those called by the target function and those that call the target function.

The common inconsistencies include, but are not limited to:
    (1) Lack of Access controls. For example, the comment specifies owner-only access but the implementation lacks such control.
    (2) Lack of Variable/Parameter checks (require/revert/if statements). For example, the comment says the function should check the range of an input parameter, but the function (and the function it calls) do not have any check.  You need also to verify whether other functions it internally calls have already performed this check. If yes, do NOT flag as inconsistent.
    (3) Missing Key Operations explicitly required by the comments. For example, the comment says the function should emit an event, but the function (and the function it calls) do not emit that specific event. You need also to verify whether other functions it internally calls have already performed this operation. If yes, do NOT flag as inconsistent.
    (4) Wrong Key Function Logic. If comments lack sufficient information to determine incorrect implementation, do not flag as inconsistent. Flag only when implementation clearly violates comments, such as transferring tokens to the wrong address.
    (5) Different Input/Output Interface. For example, the comment declares return value but function returns none.

You should only focus on inconsistencies that cause real functional differences. For example, if you find the function has improper visibility(pure/view), but the comment does not explictly specify it must use which visability, the inconsistency is NOT valid. If the comment is a suggestion/recommendation/usage description of a function, do NOT flag as inconsistent.
If the comments are too short or ambiguous to determine whether the implementation is incorrect, do not flag as inconsistent.
If the comment assumes some condition will be pre-checked, but the implementation check it again, do NOT flag it as inconsistent.
You should only check the comment that explicilty provided to you. For example, if the comment is not self-contained, such as refering to external interface/documentation/links, do not flag as inconsistent.
If the inconsistency is due to a missing check/operation in the target function, verify whether other functions it internally calls have already performed this check/operation. If yes, do NOT flag as inconsistent.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.

Comments related to the target function are provided in a JSON list, with each item containing a 'level', 'comment', and 'entity'.
- 'comment' is the text of the comment.
- 'entity' is the entity the comment belongs to.
- 'level' specifies the entity's level, which can be 'contract', 'function', 'statement', or 'variable'.
    (1) the 'contract' level comments usually describes the main definition/functionality/operation/interface about the contract.
    (2) the 'function' level comments usually describes the main definition/functionality/operation/interface about the function. It is essential for the detection of code-comment inconsistencies.
    (3) the 'statement' level comments typically explain the intended purpose of a specific statement. It can help you understand the hign-level code logic.
    (4) the 'variable' level comments usually describes the definition and usage of a variable/event/error in Solidity. It can help you understand the semantic of the variable/event/error used in the function.


If an inconsistency is detected, you must provide a corrected and self-contained implementation of the target function:
    (1) 'explanation': A brief reason (up to 50 words) for the inconsistency.
    (2) 'violated_comment': The specific part of the comment that the function contradicts. If there are multiple comments, you need to concatenate them into a single string. The comments should be sorted in the same order as they appear in the original code.
    (3) 'improved_implementation': A dictionary suggesting corrections. You can only modify the target function, rather than all functions in the analysis. If the target function needs changes, use its name as the key and the new implementation as the value. You need to provide the full corrected code of the target function. You corrected implementation should only use the functions that exist in the provided contract interface when modifying the code.
    The new implementation of the target function will be compiled using the Solidity compiler version {solc_version}.


==== Output Requirements ====
OUTPUT: Generate a JSON Array object. Each array item should be with the following structure:
    (1) If there is no inconsistency, each result item should be a JSON object: {{"task": Task number,"result": true}}
    (2) If the implementation violates the comments, each result item should be the JSON object:
    {{
        "task": Task number,
        "result": false,
        "explanation": "Brief technical reason for mismatch ≤50 words",
        "violated_comment": "Exact contradictory comment fragment", 
        "improved_implementation": {{
            "function_name": "Full corrected code of the target function",
        }}
    }}
You need to follow strict JSON formatting. No additional text outside JSON.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        function_related_code = task['function_related_code']
        contract_interface = task['contract_interface']
        
        prompt += f'''

=== Comments to Check ===
{function_comment}

=== The implementation of the Target Function {function_name} ===
{function_related_code}

=== Interface of the Contract ===
{contract_interface}
'''

    return prompt
