import json
import hashlib
import os
import re
import time
from openai import OpenAI
import threading
import argparse


token_lock = threading.Lock()

chat_client = None
global_model = None
gpt_query_cache = None
def init_prompt_config(api_key, base_url, global_model_name, gpt_query_cache_dir):
    global chat_client, global_model, gpt_query_cache
    chat_client = OpenAI(api_key=api_key, base_url=base_url)
    global_model = global_model_name
    gpt_query_cache = gpt_query_cache_dir

total_tokens = 0


def print_usage_statistics():
    global total_tokens
    print(f"Total tokens used: {total_tokens}")


def unwrap_json(str):
    try:
        if '```' in str:
            match = re.search(r'```json\n(.*?)\n```', str, re.DOTALL)
            if match:
                str = match.group(1)
            test = json.loads(str)
    except:
        return None
    return json.loads(str)


def unwrap_souce_code(str):
    try:
        if '```' in str:
            str = '\n'.join(str.split('\n')[1:-1])
    except:
        pass
    return str

def chat(messages, model=None, cache=True, CACHE_DIR=None, is_json=True, timeout=600):
    global total_tokens, total_input_token, total_output_token
    if model is None:
        model = global_model
    if CACHE_DIR is None:
        CACHE_DIR = gpt_query_cache
    if CACHE_DIR is None:
        raise ValueError("gpt_query_cache (CACHE_DIR) is not initialized. Please call init_prompt_config in main.py before using chat.")
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    request_hash = hashlib.md5(json.dumps(messages, sort_keys=True).encode()).hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"{request_hash}.json")

    assistant_response = None
    if cache and os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
                assistant_response = cached_data.get("response")
                prompt_tokens = cached_data.get("prompt_tokens", 0)
                completion_tokens = cached_data.get("completion_tokens", 0)
                return assistant_response
        except Exception as e:
            pass

    if not assistant_response:  # retry until success
        max_attempts = 2
        attempt = 0
        assistant_response = ''
        while attempt < max_attempts:
            try:
                response = chat_client.chat.completions.create(
                    messages=messages,
                    model=model,
                    temperature=0,
                    stream=False
                )
                tokens_used = response.usage.total_tokens
                prompt_tokens = response.usage.prompt_tokens
                completion_tokens = response.usage.completion_tokens

                with token_lock:
                    total_tokens += tokens_used

                assistant_response = response.choices[0].message.content
                if is_json:
                    assistant_response = unwrap_json(assistant_response)
                    cache_data = {
                        "response": assistant_response,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens
                    }
                    with open(cache_file, 'w') as f:
                        json.dump(cache_data, f)
                else:
                    cache_data = {
                        "response": assistant_response,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens
                    }
                    with open(cache_file, 'w') as f:
                        json.dump(cache_data, f)
                break 
            except Exception as e:
                if "rate_limit_exceeded" in str(e):
                    wait_time = re.search(r'Please try again in (\d+(\.\d+)?)s', str(e))
                    if wait_time:
                        wait_time = float(wait_time.group(1)) * 2
                        time.sleep(wait_time)
                attempt += 1
                if attempt == max_attempts:
                    return None

    return assistant_response
   
def propagate_comments_through_LLM_and_static_analysis(contract, function, comments, comments_to_propagate):
    prompt = f'''Assume you are a senior smart contract developer. You have a Solidity function '{function.name}' with incomplete comments.
    You need to augment comments for the function '{function.name}' in the contract '{contract.name}' by propagating the comments for its related contracts/functions/statements/variables to this functions.
    Specifically, you need to follow the following workflow:
### Stage 1: Coomment Propagation
    You need to propagate the comments from the related contracts/functions/statements/variables to the function '{function.name}'. The intuition is that the comments from the related code entities can provide additional information for the function '{function.name}'
The detailed relations between the code entities and function '{function.name}' and propagation rules could be one of the follows:
- 'Inherit': Funtion {function.name} inherits the functions from the parent contract, so some of the comments from the parent function can be propagated to the function.
- 'Implement': Funtion {function.name} implements an interface, so some of the comments from the interface can be propagated to the function.
- 'Override': Funtion {function.name} overrides a parent function, so some of the comments from the parent function can be propagated to the function.
- 'Overload': Funtion {function.name} overloads a function, so some of the comments from the overloaded function can be propagated to the function.
- 'Call': Funtion {function.name} calls another function, so some of the comments from the callee function can be propagated to the call statement in the caller function. Note that the propagated comments should be in 'statement' level, and the entity should be the 
- 'Def-Use': Funtion {function.name} uses a variable/event/error, so some of the comments from the variable declaration can be propagated to the function.
Note that you can only propagate existing comments from other provided code entities and refine them to suite the function '{function.name}'. You can NOT add any completely new comments that is not any of the provided comments.
If a comment is already covered by the existing comments for the function '{function.name}', you should NOT propagate it.
When propagating comments, you should also consider the source code for function '{function.name}' to ensure the comments are applicable to the function.
### Stage 2: Comment Refinement
    The propagated comments may not be directly applicable to the target function and often require contextual adjustments, such as updating parameter names. Therefore, you need to refine the propagated comments to make them more suitable for the function '{function.name}'.
### Stage 3: Comment Deduplication
    The propagated comments should be de-duplicated based on the semantic of the comments. Any comment that duplicates the meaning of an existing one or whose intent is already encompassed by other comments should be removed
    
    
=== Source Code for function '{function.name}' ===
{function.source_mapping.content}

=== Existing Comments for function '{function.name}' ===
{comments}

=== Comment-Code Entities related to function '{function.name}' ===
{comments_to_propagate}


Each Comment-Code Entity includes the following fields:
- 'type': The type of the relation between the code entity and function '{function.name}'. It can be 'Inherit', 'Implement', 'Override', 'Overload', 'Call', 'Def-Use'.
- 'comment_to_propagate': The comment for the code entity to be propagated from the code entity to function '{function.name}'.
    - "comment": "Original text (exact match)",
    - "level": "contract|function|statement|variable|none",
    - "entity": "contract name|function signature|statement|variable name",
    - "contract": which contract the comment belongs to


=== Output Format ===
You should output the propagated comment for function '{function.name}'. Inlcude both the original comment and the propagated comment.
It should follow the same format as the existing comments for the function.
OUTPUT: Generate JSON array with strict structure:
[
    {{
        "comment": "Original text (exact match)",
        "level": "contract|function|statement|variable|none",
        "entity": "Context identifier per rules in Stage 2",
    }},
...
]
You need to follow strict JSON formatting. No additional text outside JSON.


'''

    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache = True)
    assistant_response = unwrap_json(assistant_response)
    return assistant_response
def fix_compile_error(contract_code, origin_function, rewrite_function, error_message, solc_version):
    contract_code_excerpt = '\n'.join(contract_code.split('\n')[0:3]) + '...' + '\n'.join(contract_code.split('\n')[-3:])
    prompt = f'''
Assume you are a senior smart contract developer. You have a Solidity contract that has a compilation error. Your task is to fix the compilation error by modifying the contract code. 
Please provide the modified contract code. Ensure that the modified code compiles successfully. 
You should only output the modified source code of the modified contract. You should only solve the compilation error, and do NOT modify other parts that are not related to the compilation error. You need to return a string containing the modified contract code. Do not use Markdown format. 

The solc compiler version to be used is {solc_version}.
The compilation error is caused after modifying the following function: {rewrite_function.keys()}\n

=== The origin implementation with no compilation error ===
{origin_function}

=== The modified implementation with compilation error ===
{rewrite_function}

=== The full contract code with the compilation error ===
{contract_code}

=== The error message is===
{error_message} 

You should output a fixed version of the following functions: {rewrite_function.keys()}.
The output should be a json dictionary suggesting corrections. This dictionary includes:
    - The Name (only name, not signature) of the functions that need changes as keys.
    - The new implementation of the functions as values.

    '''

    messages = [
        {"role": "user", "content": prompt}
    ]
    assistant_response = chat(messages, cache = True, is_json = False)
    assistant_response = unwrap_json(assistant_response)
    return assistant_response


def fix_compile_error_source_code_level(contract_code, rewrite_function, error_message, solc_version):
    contract_code_excerpt = '\n'.join(contract_code.split('\n')[0:3]) + '...' + '\n'.join(contract_code.split('\n')[-3:])
    prompt = f'''
Assume you are a senior smart contract developer. You have a Solidity contract that has a compilation error. Your task is to fix the compilation error by modifying the contract code. 
Please provide the modified contract code. Ensure that the modified code compiles successfully. 
You should only output the modified source code of the modified contract. You should only solve the compilation error, and do NOT modify other parts that are not related to the compilation error. You need to return a string containing the modified contract code. Do not use Markdown format. 

The output should be formatted as follows:
{contract_code_excerpt}

The solc compiler version to be used is {solc_version}.
The compilation error is caused after modifying the following function: {rewrite_function}\n

=== The contract code with the compilation error ===
{contract_code}

=== The error message is===
{error_message} 
    '''

    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache = True, is_json = False)
    assistant_response = unwrap_souce_code(assistant_response)
    return assistant_response


def match_comments_to_entities(contract_name, contract_code):
    prompt = f'''
You are a senior smart contract analyzer specializing in comment analysis. Your task is to systematically analyze Solidity contract comments, match them to the corresponding code entities.
Specifically, you need to follow the following workflow:

## Stage 1: Comment Preprocessing
    1.1 Filter valid comments: Extract comments using // or /* */ or * syntax. Do not include strings in the code rather than comments.
    1.2 Comment Sentence segmentation: Split comments at sentence-ending periods. Treat each sentence as independent unit.
    1.3 Filter out comments that are not related to code entities. For example, author information, license information, or version information.

## Stage 2: Matching each comment to its corresponding code 'level' and 'entity'. You need to match the comments to the most proper code entity.
The 'level' of a contract can be 'contract', a 'function', a 'statement', a 'variable'.
(1) 'contract' refers to a contract, interface, or abstract contract. If the comment refers to a contract, the 'entity' should be the contract name. 
(2) 'function' refers to a function, constructor, or modifier. If the comment pertains to a specific function, the 'entity' should be the function signature. Note that a function signature is the function name + '(' + parameter types + ')', such as add(uint256,uint256) .
(3) 'statement' refers to any statement. If the comment pertains to a specific statement, the 'entity' should be the function name followed by a colon and the statement itself. 
(4) 'variable' refers to global/local data structures, including parameters, variables, event, and error definitions. If the comment pertains to a variable/parameter/return value declared by a function, the 'entity' should be the function name followed by a colon and the name of the variable/event/error. If the comment pertains to a variable declared by the contract, the 'entity' should be the contract name followed by a colon and the name of the variable/event/error.

==== Output Requirements ====
OUTPUT: Generate JSON array with strict structure:
[
    {{
        "comment": "Original text (exact match)",
        "level": "contract|function|statement|variable",
        "entity": "Context identifier per rules in Stage 2",
    }},
...
]
You need to follow strict JSON formatting. No additional text outside JSON.

=== Contract Code to be Analyzed ===
{contract_code}
    '''
    
    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache = True)

    return assistant_response

def remove_comments(contract_code):
    comment_pattern = re.compile(r'(//.*?$|/\*.*?\*/)', re.DOTALL | re.MULTILINE)
    return comment_pattern.sub('', contract_code)


def check_function_inconsistency(function_related_code, function_name, function_comment, contract_interface, solc_version):
    contract_code = remove_comments(function_related_code)
    prompt = f'''
Assume you are a senior smart contract analyzer specialized in analyzing code-comment inconsistencies in functions.
Your task is to evaluate whether a function's implementation explicitly contradicts the functional logic described in the comments.
Analyze the Solidity contract function '{function_name}' following this workflow:
## Stage 1: Code-Comment Inconsistency Detection
    Examine all comments one by one and carefully. Assume all comments are correct.
    When you analyze, you should consider all function implementations provided to you, including functions that are called by the target function, and functions that call the target function.
    The common inconsistencies include, but are not limited to:
    (1) Lack of Access controls. For example, the comment says the function should be restricted to the owner, but the function is not restricted.
    (2) Lack of Variable/Parameter checks (require/revert/if statements). For example, the comment says the function should check the range of an input parameter, but the function (and the function it calls) do not have any check.
    (3) Missing Key Operations explictly required by the comments. For example, the comment says the function should emit an event, but the function (and the function it calls) do not emit the event.
    (4) Wrong Key Function Logic. Note that comments may not detail all key functional logics. If the information in the comments is insufficient to determine whether the implementation is incorrect, such cases should not be treated as inconsistencies. An inconsistency should only be flagged when the implementation clearly violates the comments. For example, if the comment states the function should transfer the token to msg.sender, but it transfers to another address, this would be an inconsistency.
    (5) Different Input/Output Interface. For example, the comment says the function should return a value, but the function does not return anything.
    
## Stage 2: Correct Program Variant Generation (Only applicable if there is an inconsistency)
    If there is an inconsistency, you need to provide a corrected version of functions related to the inconsistency.
    (1) 'explanation': A brief reason (up to 50 words) for the inconsistency.
    (2) 'violated_comment': The specific part of the comment that the function contradicts.
    (3) 'improved_implementation': A dictionary suggesting corrections. Include all functions in the analysis:
        If a function needs changes, use its name as the key and the new implementation as the value. 
    The new implementation will be compiled by the Solidity compiler version {solc_version}.
    It should only use the functions and variables that exist in the provided contract interface when modifying the code.


==== Output Requirements ====
OUTPUT: Generate a JSON object with a strict structure:
    (1) If there is no inconsistency, return the JSON object: {{"result": true}}
    (2) If the implementation violates the comments, return the JSON object:
    {{
        "result": false,
        "explanation": "Brief technical reason for mismatch ≤50 words",
        "violated_comment": "Exact contradictory comment fragment", 
        "improved_implementation": {{
            "{function_name}": "Full corrected code of the function",
            // Other functions only if modified
        }}
    }}
You need to follow strict JSON formatting. No additional text outside JSON.


=== Comments to Check ===
{function_comment}

=== Function Implementation ===
{function_related_code}

=== Interface of the Contract ===
{contract_interface}

'''
    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache = True)
    return assistant_response

