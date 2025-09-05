"""Module containing helper functions used in both path mode and fork mode."""

import os
import time
import difflib
from typing import TYPE_CHECKING, List, Optional, Tuple

# pylint: disable= no-name-in-module
from solc_select.solc_select import get_available_versions
from slither.utils.upgradeability import (
    compare,
    tainted_inheriting_contracts,
    TaintedExternalContract,
)
from slither.core.declarations import Function
from slither.core.variables.state_variable import StateVariable
from slither.analyses.data_dependency.data_dependency import get_dependencies
from slither.core.cfg.node import Node, NodeType
from slither.core.declarations import (
    Contract,
    Function,
)
from slither.core.expressions import (
    Literal,
    Identifier,
    CallExpression,
    AssignmentOperation,
)
from slither.core.solidity_types import (
    ElementaryType,
)
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from slither.slithir.operations import (
    LowLevelCall,
)
from slither.tools.read_storage.read_storage import SlotInfo, SlitherReadStorage


from diffusc.utils.classes import ContractData, Diff
from diffusc.utils.crytic_print import CryticPrint
from slither import Slither

if TYPE_CHECKING:
    from slither import Slither


def is_function_modified(f1: Function, f2: Function) -> bool:
    """
    Compares two versions of a function, and returns True if the function has been modified.
    First checks whether the functions' content hashes are equal to quickly rule out identical functions.
    Walks the CFGs and compares IR operations if hashes differ to rule out false positives, i.e., from changed comments.

    Args:
        f1: Original version of the function
        f2: New version of the function

    Returns:
        True if the functions differ, otherwise False
    """
    def remove_whitespace(s):
        return ''.join(s.split())
    # If the function content hashes are the same, no need to investigate the function further
    content1 = f1.source_mapping.content
    content2 = f2.source_mapping.content
    content1 = '\n'.join(content1.split('\n')[1:])
    content2 = '\n'.join(content2.split('\n')[1:])

    if remove_whitespace(content1) == remove_whitespace(content2):
        return False
    else:
        print("Here Test 2", content1, content2)
        return True


def assign_library_to_address(libraries):
    result = {}
    address = 0x10
    for (lib, placeholder) in libraries:
        address = address + 1
        result[lib] = f"{address:040x}"

    return result

def replace_address_holder(creation_bytecode1, creation_bytecode2, library2address, libraryplaceholder):
    for (lib, place_holder) in libraryplaceholder:
        address = library2address[lib]
        creation_bytecode1 = creation_bytecode1.replace(place_holder, address)
        creation_bytecode2 = creation_bytecode2.replace(place_holder, address)
        print("Replacing place_holder: ", place_holder, " with address: ", address)
    return creation_bytecode1, creation_bytecode2

def library_address_to_bytecode(libraryplaceholder, library2address, v: Slither):
    result = {}
    for (lib, place_holder) in libraryplaceholder:
        for unit in v.crytic_compile.compilation_units.values():
            for (path, source_unit) in unit.source_units.items():
                if lib in source_unit.bytecodes_runtime:
                    result[library2address[lib]] = source_unit.bytecodes_runtime[lib]
                    break
    return result

def get_creation_bytecode(v1: Slither, v2: Slither, contract_info_1, contract_info_2):    
    creation_1, creation_2, libraryplaceholder, library_to_bytecode1, library_to_bytecode2 = None, None, [], {}, {}
    for unit in v1.crytic_compile.compilation_units.values():
        for (path, source_unit) in unit.source_units.items():
            if os.path.basename(contract_info_1['path']) in path.absolute:
                creation_1 = source_unit.bytecodes_init[contract_info_1['name']]
                libraryplaceholder = source_unit.libraries_names_and_patterns(contract_info_1['name'])
                break
            else:
                print ("Path not found in unit", contract_info_1['path'], path.absolute)
    for unit in v2.crytic_compile.compilation_units.values():
        for (path, source_unit) in unit.source_units.items():
            if os.path.basename(contract_info_2['path']) in path.absolute:
                creation_2 = source_unit.bytecodes_init[contract_info_2['name']]
                libraryplaceholder.extend(source_unit.libraries_names_and_patterns(contract_info_2['name']))
                break
    if creation_1 is None or creation_2 is None:
        raise Exception("Creation Bytecode not found")
    if len(libraryplaceholder) > 0:
        print("libraryplaceholder", libraryplaceholder)
        library2address = assign_library_to_address(libraryplaceholder)
        creation_1, creation_2 = replace_address_holder(creation_1, creation_2, library2address, libraryplaceholder)
        library_to_bytecode1 = library_address_to_bytecode(libraryplaceholder, library2address, v1)
        library_to_bytecode2 = library_address_to_bytecode(libraryplaceholder, library2address, v2)
        # print(creation_1)
        print("library_to_address", library2address)
    # print("Getting Creation Bytecode", creation_1)

    return creation_1, creation_2, library_to_bytecode1, library_to_bytecode2


def compare(
    v1: Contract, v2: Contract, include_external: bool = False, extra_functions = None
) -> Tuple[
    List[Variable],
    List[Variable],
    List[Variable],
    List[Function],
    List[Function],
    List[Function],
]:
    """
    Compares two versions of a contract. Most useful for upgradeable (logic) contracts,
    but does not require that Contract.is_upgradeable returns true for either contract.

    Args:
        v1: Original version of (upgradeable) contract
        v2: Updated version of (upgradeable) contract
        include_external: Optional flag to enable cross-contract external taint analysis

    Returns:
        missing-vars-in-v2: list[Variable],
        new-variables: list[Variable],
        tainted-variables: list[Variable],
        new-functions: list[Function],
        modified-functions: list[Function],
        tainted-functions: list[Function]
        tainted-contracts: list[TaintedExternalContract]
    """

    order_vars1 = v1.state_variables_ordered
    order_vars2 = v2.state_variables_ordered
    func_sigs1 = [function.solidity_signature for function in v1.functions]
    func_sigs2 = [function.solidity_signature for function in v2.functions]

    missing_vars_in_v2 = []
    new_variables = []
    tainted_variables = []
    new_functions = []
    modified_functions = []
    tainted_functions = []

    # Since this is not a detector, include any missing variables in the v2 contract
    if len(order_vars2) < len(order_vars1):
        missing_vars_in_v2.extend(get_missing_vars(v1, v2))

    # Find all new and modified functions in the v2 contract
    new_modified_functions = []
    new_modified_function_vars = []
    
    # if tainted_functions:
    #     for func_sig in set(tainted_functions):
    #         for func in v2.functions:
    #             if func.signature_str == func_sig:
    #                 modified_functions.append(func)
                    
    for sig in func_sigs1:
        function = v2.get_function_from_signature(sig)
        orig_function = v1.get_function_from_signature(sig)
        if not function or not orig_function:
            continue
        if function.is_shadowed or orig_function.is_shadowed:
            continue
        if function.signature_str in extra_functions:
            tainted_functions.append(function)
        else:
            modified_functions.append(function)
        # Include all functions in contratc V1 for differential Testing
        # modified_functions.append(function)
        # new_functions.append(function)
        # new_modified_function_vars += function.all_state_variables_written()
        #
        # if sig not in func_sigs1:
        #     new_modified_functions.append(function)
        #     new_functions.append(function)
        #     new_modified_function_vars += function.all_state_variables_written()
        # else: # only mark influenced functions as modified
        #     new_modified_functions.append(function)
            # modified_functions.append(function)
            # new_modified_function_vars += function.all_state_variables_written()
        
    
                    # new_modified_function_vars += func.all_state_variables_written()
                    
    return (
        [],
        [],
        [],
        [],
        modified_functions, # 不需要插入assert的Functions
        tainted_functions,  # 需要插入assert的Functions
        [],
    )               
                    

    # Find all unmodified functions that call a modified function or read/write the
    # same state variable(s) as a new/modified function, i.e., tainted functions
    for function in v2.functions:
        if (
            function in new_modified_functions
            or function.is_constructor
            or function.name.startswith("slither")
        ):
            continue
        modified_calls = [
            func for func in new_modified_functions if func in function.internal_calls
        ]
        tainted_vars = [
            var
            for var in set(new_modified_function_vars)
            if var in function.all_state_variables_read() + function.all_state_variables_written()
            and not var.is_constant
            and not var.is_immutable
        ]
        if len(modified_calls) > 0 or len(tainted_vars) > 0:
            tainted_functions.append(function)
            
    # Find all new or tainted variables, i.e., variables that are written by a new/modified/tainted function
    for var in order_vars2:
        written_by = v2.get_functions_writing_to_variable(var)
        if next((v for v in v1.state_variables_ordered if v.name == var.name), None) is None:
            new_variables.append(var)
        elif any(func in written_by for func in new_modified_functions + tainted_functions):
            tainted_variables.append(var)

    tainted_contracts = []
    if include_external:
        # Find all external contracts and functions called by new/modified/tainted functions
        tainted_contracts = tainted_external_contracts(
            new_functions + modified_functions + tainted_functions
        )

    return (
        missing_vars_in_v2,
        new_variables,
        tainted_variables,
        new_functions,
        modified_functions,
        tainted_functions,
        tainted_contracts,
    )


def get_compilation_unit_name(slither_object: "Slither") -> str:
    """Get the name of the compilation unit from Slither."""

    name = list(slither_object.crytic_compile.compilation_units.keys())[0]
    name = os.path.basename(name)
    if name.endswith(".sol"):
        name = os.path.splitext(name)[0]
    return name


# TODO: remove these disables if possible
# pylint: disable=too-many-locals,too-many-statements,too-many-branches
def get_pragma_versions_from_file(
    filepath: str, seen: Optional[List[str]] = None
) -> Tuple[str, str]:
    """Recursive function to determine minimum and maximum solc versions required by a Solidity file."""

    def is_higher_version(cur_vers: List[str], high_vers: List[str]) -> bool:
        if int(cur_vers[1]) > int(high_vers[1]) or (
            int(cur_vers[1]) == int(high_vers[1]) and int(cur_vers[2]) > int(high_vers[2])
        ):
            return True
        return False

    def is_lower_version(cur_vers: List[str], low_vers: List[str]) -> bool:
        if int(cur_vers[1]) < int(low_vers[1]) or (
            int(cur_vers[1]) == int(low_vers[1]) and int(cur_vers[2]) < int(low_vers[2])
        ):
            return True
        return False

    def next_version(cur_vers: List[str]) -> List[str]:
        ret_vers = ["0", "0", "0"]
        all_versions = list(get_available_versions().keys())
        all_versions.reverse()
        if ".".join(cur_vers) in all_versions:
            cur_index = all_versions.index(".".join(cur_vers))
            if cur_index + 1 != len(all_versions):
                return all_versions[cur_index + 1].split(".")
            return ret_vers
        if cur_vers[2] == "99":
            ret_vers[1] = str(int(cur_vers[1]) + 1)
        else:
            ret_vers[1] = cur_vers[1]
            ret_vers[2] = str(int(cur_vers[2]) + 1)
        return ret_vers

    def prev_version(cur_vers: List[str]) -> List[str]:
        ret_vers = ["0", "0", "0"]
        all_versions = list(get_available_versions().keys())
        all_versions.reverse()
        if ".".join(cur_vers) in all_versions:
            cur_index = all_versions.index(".".join(cur_vers))
            if cur_index - 1 >= 0:
                return all_versions[cur_index - 1].split(".")
            return ret_vers
        ret_vers[1] = cur_vers[1]
        ret_vers[2] = str(int(cur_vers[2]) - 1)
        return ret_vers

    def last_before_breaking(cur_vers: List[str]) -> List[str]:
        all_versions = list(get_available_versions().keys())
        last_vers = next(v for v in all_versions if v.split(".")[1] == cur_vers[1])
        return last_vers.split(".")

    if seen is None:
        seen = []
    # Read from the file and extract pragma solidity version statements
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except FileNotFoundError:
        return "0.0.0", "0.0.0"
    versions = [
        line.split("solidity")[1].split(";")[0] for line in lines if "pragma solidity" in line
    ]
    versions_sublists = [
        v.replace("= ", "=").replace("> ", ">").replace("< ", "<").replace("^ ", "^").split()
        for v in versions
    ]
    versions = [item for sublist in versions_sublists for item in sublist]

    # Extract import statements from the file
    imports = [line for line in lines if "import" in line]
    files = [
        line.split()[1].split(";")[0].replace('"', "").replace("'", "")
        if line.startswith("import")
        else line.split()[1].replace('"', "").replace("'", "")
        for line in imports
    ]
    # Keep track of the version constraints imposed by imports
    max_version = ["0", "9", "99"]
    min_version = ["0", "0", "0"]
    # Recursively call this function for each imported file, and update max and min
    for path in files:
        if path.startswith("./"):
            path = os.path.join(os.path.dirname(filepath), path[2:])
        elif path.startswith("../"):
            path = os.path.join(os.path.dirname(os.path.dirname(filepath)), path[3:])
        if path not in seen:
            seen.append(path)
            file_versions = get_pragma_versions_from_file(path, seen)
            if is_higher_version(file_versions[0].split("."), min_version):
                min_version = file_versions[0].split(".")
            if is_lower_version(file_versions[1].split("."), max_version):
                max_version = file_versions[1].split(".")

    # Iterate over the versions found in this file, and update the version constraints accordingly
    for ver in versions:
        operator = ver.split("0.")[0]
        vers = ver.split(".")
        vers[0] = "0"
        if operator == ">=" and is_higher_version(vers, min_version):
            min_version = vers
        elif operator == ">" and is_higher_version(next_version(vers), min_version):
            min_version = next_version(vers)
        elif operator == "<=" and is_lower_version(vers, max_version):
            max_version = vers
        elif operator == "<" and is_lower_version(prev_version(vers), max_version):
            max_version = prev_version(vers)
        elif operator == "^" and is_higher_version(vers, min_version):
            min_version = vers
            max_version = vers # last_before_breaking(vers)
        elif operator == "":
            min_version = vers
            max_version = vers
    # If one of the constraints has not been defined, pick a reasonable constraint
    if max_version == ["0", "9", "99"]:
        max_version = last_before_breaking(min_version)
    if min_version == ["0", "0", "0"]:
        min_version = [max_version[0], max_version[1], "0"]
    return ".".join(min_version), ".".join(max_version)


# pylint: disable=too-many-locals
def do_diff(
    v_1: ContractData,
    v_2: ContractData,
    additional_targets: Optional[List[ContractData]] = None,
    tainted_functions = None,
    include_external: bool = False,
) -> Diff:
    """Use slither.utils.upgradeability to perform a diff between two contract versions."""
    assert v_1["valid_data"] and v_2["valid_data"]
    start_time = time.time()
    CryticPrint.print_message("* Performing diff of V1 and V2")
    (
        missing_vars,
        new_vars,
        tainted_vars,
        new_funcs,
        modified_funcs,
        tainted_funcs,
        tainted_contracts,
    ) = compare(v_1["contract_object"], v_2["contract_object"], include_external, tainted_functions)
    
    
    if additional_targets:
        tainted_contracts = tainted_inheriting_contracts(
            tainted_contracts,
            [
                t["contract_object"]
                for t in additional_targets
                if t["contract_object"]
                not in [c.contract for c in tainted_contracts]
                + [v_1["contract_object"], v_2["contract_object"]]
            ],
        )
    diff = Diff(
        missing_variables=missing_vars,
        new_variables=new_vars,
        tainted_variables=tainted_vars,
        new_functions=new_funcs,
        modified_functions=modified_funcs,
        tainted_functions=tainted_funcs,
        tainted_contracts=tainted_contracts,
    )
    end_time = time.time()
    CryticPrint.print_message(f"  * Diff analysis completed in {end_time - start_time} seconds")
    for key, lst in diff.items():
        if isinstance(lst, list) and len(lst) > 0:
            CryticPrint.print_warning(f'  * {str(key).replace("-", " ")}:')
            for obj in lst:
                if isinstance(obj, StateVariable):
                    CryticPrint.print_warning(f"      * {obj.full_name}")
                elif isinstance(obj, Function):
                    CryticPrint.print_warning(f"      * {obj.signature_str}")
                elif isinstance(obj, TaintedExternalContract):
                    CryticPrint.print_warning(f"      * {obj.contract.name}")
                    for taint in obj.tainted_functions:
                        CryticPrint.print_warning(f"        * {taint.signature_str}")
                    for taint in obj.tainted_variables:
                        CryticPrint.print_warning(f"        * {taint.signature_str}")
    return diff


def similar(name1: str, name2: str) -> bool:
    """
    Test the name similarity
    Two names are similar if difflib.SequenceMatcher on the lowercase
    version of the name is greater than 0.90
    See: https://docs.python.org/2/library/difflib.html
    Args:
        name1 (str): first name
        name2 (str): second name
    Returns:
        bool: true if names are similar
    """

    val = difflib.SequenceMatcher(a=name1.lower(), b=name2.lower()).ratio()
    ret = val > 0.90
    return ret


def camel_case(name: str) -> str:
    """Convert a string to camel case."""

    parts = name.replace("_", " ").replace("-", " ").split()
    name = parts[0][0].lower() + parts[0][1:]
    if len(parts) > 1:
        for i in range(1, len(parts)):
            name += parts[i][0].upper() + parts[i][1:]
    return name


def write_to_file(filename: str, content: str) -> None:
    """Write content to a file. If the parent directory doesn't exist, create it."""

    base_dir = os.path.dirname(filename)
    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)

    with open(filename, "wt", encoding="utf-8") as out_file:
        out_file.write(content)
