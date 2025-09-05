import json

def confirm_function_inconsistency_prompt_v1(tasks):
    prompt = '''As a smart contract developer, a code review agent has informed you that several functions in your Solidity smart contract do not align with the intent expressed in your comments. They have suggested specific modifications to these functions.
Your task is to analyze these analysis results and determine whether the inconsistencies are valid.
Each task is independent and should be processed separately.

Each inconsistency information provided by the code review agent includes the following fields:
- 'result': Indicates whether the implementation aligns with the comments (True or False).
- 'violated_comment': The specific part of the comment that the function contradicts.
- 'improved_implementation': A dictionary suggesting corrections. This dictionary includes:
    - The names of the functions that need changes as keys.
    - The new implementation of the functions as values.


You need to focus on two aspects:
    1. Whether the inconsistency do exist. Only the implemenation explictly violates the comments can cause a code-comment inconsistency. Note that comments may not detail all expected functional logics. If the information in the comments is insufficient to determine whether the implementation is incorrect, e.g., it is ambiguous or incomplete (such as See \{...\}), such cases should NOT be treated as inconsistencies. If the code includes a check that you believe is valid and necessary, such as more strict access control, it is acceptable for the comment not to explicitly state the check. You should NOT mark the inconsistency as valid.
    2. Whether the inconsistency do lead to any functional differences. If there is no functional difference between the original implementation and the improved_implementation, the inconsistency is NOT valid. Otherwise, the inconsistency is valid.
    
Only consider inconsistencies related to comment-code mismatches. For example, if a function has improper visibility (pure/view) but the comment does not explicitly specify the required visibility, the inconsistency is NOT valid.
You need to carefully examine the function and the functions called by it. If the inconsistency is due to a missing check/operation in this function, verify whether other functions it internally calls have already performed the check/operation. If the internal check is equivalent to the missed check under Any situations, the inconsistency is NOT valid. Otherwise, you should mark it as valid for further analysis.
You should assume all comments are correct and describe the intended behavior of the function. If the functionality of the implementation differs from the comments, it is a valid inconsistency, and you should return true. 
You should make sure that the 'violated_comment' is a comment for the target function itself. For example, if the 'violated_comment' is a comment for another function, you should not consider it as a valid inconsistency.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.


Please generate a JSON array as your response. Each item in the array should include three keys: "task", "result", and "explanation".
- "task": The task number.
- "result": Set to True if you agree that the inconsistency is valid. Otherwise, set to False.
- "explanation": Provide a brief reason (up to 50 words) for your decision.

Ensure your response strictly adheres to JSON formatting. Only return a JSON array as the final output.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        
        contract_code = json.dumps(task['contract_code'], sort_keys=True)
        contract_full_code = json.dumps(task['contract_full_code'], sort_keys=True)
        inconsistency_info = json.dumps(task['inconsistency_info'], sort_keys=True)
        
        prompt += f'''
        

=== Function Implementation ===
{contract_code}

=== Contract Implementation ===
{contract_full_code}

=== Comment Related to the Function {function_name} ===
{function_comment}

=== Inconsistency Information Provided by Automated Code Review Agent ===
{inconsistency_info}

'''

    return prompt



def confirm_function_inconsistency_prompt_v2(tasks):
    prompt = '''You are a Solidity developer reviewing potential inconsistencies between function implementations and their comments. A code review agent has flagged these inconsistencies and provided suggested fixes.
Your task is to validate whether these inconsistencies are valid.
Each task is independent and should be reviewed separately.
The inconsistency details include:
- 'result': True if the implementation aligns with the comments, False otherwise.
- 'violated_comment': The specific part of the comment that contradicts the implementation.
- 'improved_implementation': A dictionary where:
    - Keys are function names requiring changes.
    - Values are the suggested new implementations.

You need to focus on two aspects:
    1. Whether the inconsistency do exist. Only the implemenation explictly violates the comments can cause a code-comment inconsistency. Note that comments may not detail all expected functional logics. If the information in the comments is insufficient to determine whether the implementation is incorrect, e.g., it is ambiguous or incomplete (such as See \{...\}), such cases should NOT be treated as inconsistencies. If the code includes a check that you believe is valid and necessary, such as more strict access control, it is acceptable for the comment not to explicitly state the check. You should NOT mark the inconsistency as valid.
    2. Whether the inconsistency do lead to any functional differences. If there is no functional difference between the original implementation and the improved_implementation, the inconsistency is NOT valid. Otherwise, the inconsistency is valid.

Only consider inconsistencies related to comment-code mismatches. For example, if a function's visibility is incorrect but the comment does not specify the required visibility, the inconsistency is NOT valid.
Analyze the function and any functions it calls. If a missing check or operation is identified, confirm whether it is already performed by the called functions. If the internal check is equivalent in all cases, the inconsistency is NOT valid. Otherwise, it should be marked as valid.
Assume all comments are correct and describe the intended behavior of the function. If the implementation deviates from the comments, the inconsistency is valid, and you should return true.
You should make sure that the 'violated_comment' is a comment for the target function itself. For example, if the 'violated_comment' is a comment for another function, you should not consider it as a valid inconsistency.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.


Please generate a JSON array as your response. Each item in the array should include three keys: "task", "result", and "explanation".
- "task": The task number.
- "result": True if the inconsistency is valid, False otherwise.
- "explanation": A concise reason (up to 50 words) for your decision.

Ensure your response is strictly in JSON format. Only return a JSON array as the output.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        contract_code = json.dumps(task['contract_code'], sort_keys=True)
        contract_full_code = json.dumps(task['contract_full_code'], sort_keys=True)
        inconsistency_info = json.dumps(task['inconsistency_info'], sort_keys=True)
        
        prompt += f'''
        

=== Function Implementation ===
{contract_code}

=== Contract Implementation ===
{contract_full_code}

=== Comment Related to the Function {function_name} ===
{function_comment}

=== Inconsistency Information Provided by Automated Code Review Agent ===
{inconsistency_info}

'''

    return prompt




def confirm_function_inconsistency_prompt_v3(tasks):
    prompt = '''You are a smart contract developer. A code review agent has flagged several functions in your Solidity smart contract as inconsistent with their comments. The agent has also suggested modifications to these functions.
Your task is to evaluate these flagged inconsistencies and determine their validity.
Each task is independent and should be analyzed separately.
The inconsistency information provided by the code review agent includes the following fields:
- 'result': Indicates whether the implementation aligns with the comments (True or False).
- 'violated_comment': The specific part of the comment that the function contradicts.
- 'improved_implementation': A dictionary suggesting corrections. This dictionary includes:
    - The names of the functions that need changes as keys.
    - The new implementation of the functions as values.

You need to focus on two aspects:
    1. Whether the inconsistency do exist. Only the implemenation explictly violates the comments can cause a code-comment inconsistency. Note that comments may not detail all expected functional logics. If the information in the comments is insufficient to determine whether the implementation is incorrect, e.g., it is ambiguous or incomplete (such as See \{...\}), such cases should NOT be treated as inconsistencies. If the code includes a check that you believe is valid and necessary, such as more strict access control, it is acceptable for the comment not to explicitly state the check. You should NOT mark the inconsistency as valid.
    2. Whether the inconsistency do lead to any functional differences. If there is no functional difference between the original implementation and the improved_implementation, the inconsistency is NOT valid. Otherwise, the inconsistency is valid.

Only consider inconsistencies related to comment-code inconsistencies. For example, if a function has improper visibility (pure/view) but the comment does not explicitly specify the required visibility, the inconsistency is NOT valid. 


Carefully examine the function and the functions it calls. If the inconsistency is due to a missing check/operation, verify whether other functions it internally calls already perform the check/operation. If the internal check is equivalent under all situations, the inconsistency is NOT valid. Otherwise, mark it as valid for further analysis.
Assume all comments are correct and describe the intended behavior of the function. If the implementation differs from the comments, it is a valid inconsistency, and you should return true.
You should make sure that the 'violated_comment' is a comment for the target function itself. For example, if the 'violated_comment' is a comment for another function, you should not consider it as a valid inconsistency.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.


Please generate a JSON array as your response. Each item in the array should include three keys: "task", "result", and "explanation".
- "task": The task number.
- "result": Set to True if you agree that the inconsistency is valid. Otherwise, set to False.
- "explanation": Provide a brief reason (up to 50 words) for your decision.

Ensure your response strictly adheres to JSON formatting. Only return a JSON array as the final output.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        
        contract_code = json.dumps(task['contract_code'], sort_keys=True)
        contract_full_code = json.dumps(task['contract_full_code'], sort_keys=True)
        inconsistency_info = json.dumps(task['inconsistency_info'], sort_keys=True)
        
        prompt += f'''
        

=== Function Implementation ===
{contract_code}

=== Contract Implementation ===
{contract_full_code}

=== Comment Related to the Function {function_name} ===
{function_comment}

=== Inconsistency Information Provided by Automated Code Review Agent ===
{inconsistency_info}

'''

    return prompt




def confirm_function_inconsistency_prompt_v4(tasks):
    prompt = '''Assume you are a smart contract developer. A code review agent has flagged several functions in your Solidity smart contract as inconsistent with their comments. The agent has also suggested modifications to these functions.
Your task is to evaluate these flagged inconsistencies and determine their validity.
Each task is independent and should be analyzed separately.
The inconsistency information provided by the code review agent includes the following fields:
- 'result': Indicates whether the implementation aligns with the comments (True or False).
- 'violated_comment': The specific part of the comment that the function contradicts.
- 'improved_implementation': A dictionary suggesting corrections. This dictionary includes:
    - The names of the functions that need changes as keys.
    - The new implementation of the functions as values.

You need to focus on two aspects:
    1. Whether the inconsistency do exist. Only the implemenation explictly violates the comments can cause a code-comment inconsistency. Note that comments may not detail all expected functional logics. If the information in the comments is insufficient to determine whether the implementation is incorrect, e.g., it is ambiguous or incomplete (such as See \{...\}), such cases should NOT be treated as inconsistencies. If the code includes a check that you believe is valid and necessary, such as more strict access control, it is acceptable for the comment not to explicitly state the check. You should NOT mark the inconsistency as valid.
    2. Whether the inconsistency do lead to any functional differences. If there is no functional difference between the original implementation and the improved_implementation, the inconsistency is NOT valid. Otherwise, the inconsistency is valid.

Only consider inconsistencies related to comment-code inconsistencies. For example, if a function has improper visibility (pure/view) but the comment does not explicitly specify the required visibility, the inconsistency is NOT valid. 


Carefully examine the function and the functions it calls. If the inconsistency is due to a missing check/operation, verify whether other functions it internally calls already perform the check/operation. If the internal check is equivalent under all situations, the inconsistency is NOT valid. Otherwise, mark it as valid for further analysis.
Assume all comments are correct and describe the intended behavior of the function. If the implementation differs from the comments, it is a valid inconsistency, and you should return true.
You should make sure that the 'violated_comment' is a comment for the target function itself. For example, if the 'violated_comment' is a comment for another function, you should not consider it as a valid inconsistency.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.


Please generate a JSON array as your response. Each item in the array should include three keys: "task", "result", and "explanation".
- "task": The task number.
- "result": Set to True if you agree that the inconsistency is valid. Otherwise, set to False.
- "explanation": Provide a brief reason (up to 50 words) for your decision.

Ensure your response strictly adheres to JSON formatting. Only return a JSON array as the final output.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        
        contract_code = json.dumps(task['contract_code'], sort_keys=True)
        contract_full_code = json.dumps(task['contract_full_code'], sort_keys=True)
        inconsistency_info = json.dumps(task['inconsistency_info'], sort_keys=True)
        
        prompt += f'''
        

=== Function Implementation ===
{contract_code}

=== Contract Implementation ===
{contract_full_code}

=== Comment Related to the Function {function_name} ===
{function_comment}

=== Inconsistency Information Provided by Automated Code Review Agent ===
{inconsistency_info}

'''

    return prompt







def confirm_function_inconsistency_prompt_v5(tasks):
    prompt = '''As a smart contract developer, a code review agent has informed you that several functions in your Solidity smart contract do not align with the intent expressed in your comments. They have suggested specific modifications to these functions.
Your task is to analyze these results and determine whether the inconsistencies are valid.
Each task is independent and should be processed separately. 

Each inconsistency information provided by the code review agent includes the following fields:
- 'result': Indicates whether the implementation aligns with the comments (True or False).
- 'violated_comment': The specific part of the comment that the function contradicts.
- 'improved_implementation': A dictionary suggesting corrections. This dictionary includes:
    - The names of the functions that need changes as keys.
    - The new implementation of the functions as values.


You need to focus on two aspects:
    1. Whether the inconsistency do exist. Only the implemenation explictly violates the comments can cause a code-comment inconsistency. Note that comments may not detail all expected functional logics. If the information in the comments is insufficient to determine whether the implementation is incorrect, e.g., it is ambiguous or incomplete (such as See \{...\}), such cases should NOT be treated as inconsistencies. If the code includes a check that you believe is valid and necessary, such as more strict access control, it is acceptable for the comment not to explicitly state the check. You should NOT mark the inconsistency as valid.
    2. Whether the inconsistency do lead to any functional differences. If there is no functional difference between the original implementation and the improved_implementation, the inconsistency is NOT valid. Otherwise, the inconsistency is valid.
    
Only consider inconsistencies related to comment-code mismatches. For example, if a function has improper visibility (pure/view) but the comment does not explicitly specify the required visibility, the inconsistency is NOT valid.
You need to carefully examine the function and the functions called by it. If the inconsistency is due to a missing check/operation in this function, verify whether other functions it internally calls have already performed the check/operation. If the internal check is equivalent to the missed check under Any situations, the inconsistency is NOT valid. Otherwise, you should mark it as valid for further analysis.
You should assume all comments are correct and describe the intended behavior of the function. If the functionality of the implementation differs from the comments, it is a valid inconsistency, and you should return true. 
You should make sure that the 'violated_comment' is a comment for the target function itself. For example, if the 'violated_comment' is a comment for another function, you should not consider it as a valid inconsistency.
If the comment is a suggestion/recommendation/gas-related description, do not flag as inconsistent.


Please generate a JSON array as your response. Each item in the array should include three keys: "task", "result", and "explanation".
- "task": The task number.
- "result": Set to True if you agree that the inconsistency is valid. Otherwise, set to False.
- "explanation": Provide a brief reason (up to 50 words) for your decision.

Ensure your response strictly adheres to JSON formatting. Only return a JSON array as the final output.
'''

    for i, task in enumerate(tasks):
        function_name = task['function_name']
        function_comment = json.dumps(task['function_comment'], sort_keys=True)
        
        contract_code = json.dumps(task['contract_code'], sort_keys=True)
        contract_full_code = json.dumps(task['contract_full_code'], sort_keys=True)
        inconsistency_info = json.dumps(task['inconsistency_info'], sort_keys=True)
        
        prompt += f'''
        

=== Function Implementation ===
{contract_code}

=== Contract Implementation ===
{contract_full_code}

=== Comment Related to the Function {function_name} ===
{function_comment}

=== Inconsistency Information Provided by Automated Code Review Agent ===
{inconsistency_info}

'''

    return prompt

