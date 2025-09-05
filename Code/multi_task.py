import json
from chat import chat, unwrap_json
from verifier import confirm_function_inconsistency_prompt_v1, confirm_function_inconsistency_prompt_v2, confirm_function_inconsistency_prompt_v3, confirm_function_inconsistency_prompt_v4, confirm_function_inconsistency_prompt_v5
from checker import check_function_inconsistency_prompt_v1, check_function_inconsistency_prompt_v2, check_function_inconsistency_prompt_v3, check_function_inconsistency_prompt_v4, check_function_inconsistency_prompt_v5

def generate_check_prompt_by_agent_number(agent_number, tasks, solc_version):
    """
    Generate the appropriate prompt based on the agent number.
    """
    if agent_number == 1:
        return check_function_inconsistency_prompt_v1(tasks, solc_version)
    elif agent_number == 2:
        return check_function_inconsistency_prompt_v2(tasks, solc_version)
    elif agent_number == 3:
        return check_function_inconsistency_prompt_v3(tasks, solc_version)
    elif agent_number == 4:
        return check_function_inconsistency_prompt_v4(tasks, solc_version)
    elif agent_number == 5:
        return check_function_inconsistency_prompt_v5(tasks, solc_version)
    else:
        raise ValueError(f"Unsupported agent number: {agent_number}")

def check_function_inconsistency_multi_task(tasks, solc_version, agent_number):
    prompt = generate_check_prompt_by_agent_number(agent_number, tasks, solc_version)
    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache=True)
    return assistant_response
































































        



















def propagate_comments_through_LLM_and_static_analysis_with_multiple_task(tasks):
    prompt = '''Assume you are a senior smart contract developer. You have multiple Solidity functions with incomplete comments.
You need to enhance the comments for these functions by propagating the comments for their related contracts/functions/statements/variables to these functions.
Each task is independent and should be handled separately. Specifically, you need to follow this workflow for each task:


You need to propagate comments from the related contracts/functions/statements/variables to the functions. The idea is that comments from related code entities can provide additional information for the functions.
You need to strictly follow the following rules to propagate comments between different code entities:
- 'Inherit': The function inherits the functions from the parent contract, so some of the comments from the parent function can be propagated to the function.
- 'Implement': The function implements an interface, so some of the comments from the interface can be propagated to the function.
- 'Override': The function overrides a parent function, so some of the comments from the parent function can be propagated to the function.
- 'Overload': The function overloads a function, so some of the comments from the overloaded function can be propagated to the function.
- 'Def-Use': The function uses a event/error, so some of the comments from the variable declaration can be propagated to the function. To process a "Def-Use" comment, you should generate a new 'variable'-level comment to describe the variable/event/error used in the function. The generated comment MUST starts with "@variable/@event/@error :"(depending on whether the entity is a variable/event/error) and the 'entity' must be the variable/event/error name.
- 'Call': The function calls another function. To process a "Call" comment, You should generate a new 'statement' level comment to explictly describe what the called function do. The generated 'comment' field MUST starts with "@This is a call statement, the called function has the following comments: " and the 'entity' must be the call statememt for the called function.
Note that you can only transfer existing comments from other provided code entities. You cannot add any completely new comments that are not among the provided comments.
If a comment is already covered by the existing comments for the functions, you should NOT propagate it.
When propagating comments, you should also consider the source code for functions to ensure the comments are applicable to the functions.


The propagated comments may not be directly applicable to the target functions and often require contextual adjustments, such as updating parameter names. Therefore, you need to refine the propagated comments to make them more suitable for the functions.


The propagated comments should be de-duplicated based on the meaning of the comments.
Any propagated comment that duplicates the meaning of an existing comment or other propagated comments should be removed.
The remaining propagatedcomments should be unique and not overlap in meaning with any other comments.

Each Comment Entity to propagate includes the following fields:
- 'type': The type of the relation between the code entity and the target function. It can be 'Inherit', 'Implement', 'Override', 'Overload', 'Call', 'Def-Use'.
- 'comment_to_propagate': The comment for the code entity to be propagated from the code entity to the target function.
    - "comment": "Original text (exact match)",
    - "level": "contract|function|statement|variable|none",
    - "entity": "contract_name|function_signature|function_signature:statement|function_signature:variable_name",
    - "contract": which contract the comment belongs to
    
=== Output Format ===
You should output the propagated comments for each function. Include *ONLY* the newly propagated comment. If no comments are propagated, return [].
It should follow the same format as the existing comments for the function.
OUTPUT: Generate JSON array with strict structure:
[
    {
        "task": Task number,
        "comments": [
            {
                "comment": "Original text (exact match)",
                "level": "contract|function|statement|variable|none",
                "entity": "the entity the comment belongs to",
            },
            ...
        ]
    },
    ...
]
You need to follow strict JSON formatting. No additional text outside JSON.
'''

    for i, task in enumerate(tasks):
        contract = task['contract']
        function = task['function']
        comments = json.dumps(task['comments'], sort_keys=True)
        comments_to_propagate = json.dumps(task['comments_to_propagate'], sort_keys=True)
        
        prompt += f'''
        

=== Source Code for function '{function.name}' ===
{function.source_mapping.content}

=== Existing Comments for function '{function.name}' ===
{comments}

=== Comment-Code Entities related to function '{function.name}' ===
{comments_to_propagate}
'''


    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache=True)
    
    return assistant_response



def generate_confirm_prompt_by_agent_number(agent_number, tasks):
    """
    Generate the appropriate prompt based on the agent number.
    """
    if agent_number == 1:
        return confirm_function_inconsistency_prompt_v1(tasks)
    elif agent_number == 2:
        return confirm_function_inconsistency_prompt_v2(tasks)
    elif agent_number == 3:
        return confirm_function_inconsistency_prompt_v3(tasks)
    elif agent_number == 4:
        return confirm_function_inconsistency_prompt_v4(tasks)
    elif agent_number == 5:
        return confirm_function_inconsistency_prompt_v5(tasks)
    else:
        raise ValueError(f"Unsupported agent number: {agent_number}")

def confirm_function_inconsistency_using_LLM_multi_task(tasks, agent_numer):

    prompt = generate_confirm_prompt_by_agent_number(agent_numer, tasks)
    messages = [
        {"role": "user", "content": prompt}
    ]

    assistant_response = chat(messages, cache=True)
    return assistant_response






































        

        




















