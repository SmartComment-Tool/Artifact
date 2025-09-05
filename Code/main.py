import random
import sys
import time
from get_slither_instance import get_slither_instance_from_crytic_export
from match_comment import analyze
import os
import requests
import json
from chat import print_usage_statistics, init_prompt_config
from slither.slither import Slither
from crytic_compile import CryticCompile
from crytic_compile.platform.standard import Standard
import re
from multiprocessing import Pool, cpu_count
import argparse


def get_contract_code(contract_address, etherscan_api_key='HKA8R3YVMVIT44AZQDN1H5AWZ477Q78KSY'):
    url = "https://api.etherscan.io/api"
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": contract_address,
        "tag": "latest",
        "apikey": etherscan_api_key
    }
    response = requests.get(url, params=params)
    data = response.json()

    if "result" in data:
        contract_code = data["result"]
        return contract_code
    return None


def get_contract_name(api_key: str, contract_address: str) -> str:
    url = f"https://api.etherscan.io/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": api_key
    }
    response = requests.get(url, params=params)
    data = response.json()

    if data["status"] == "1" and data["message"] == "OK":
        contract_name = data["result"][0]["ContractName"]
        return contract_name
    else:
        raise Exception(f"Error fetching contract name: {data['result']}")


def get_creation_tx_hash(contract_address, etherscan_api_key='HKA8R3YVMVIT44AZQDN1H5AWZ477Q78KSY'):
    url = "https://api.etherscan.io/api"
    params = {
        "module": "contract",
        "action": "getcontractcreation",
        "contractaddresses": contract_address,
        "apikey": etherscan_api_key
    }

    response = requests.get(url, params=params)
    data = response.json()

    if data["status"] == "1" and data["message"] == "OK":
        creation_tx_hash = data["result"][0]["txHash"]
        return creation_tx_hash
    return None


def get_source_code_via_forge_cast_and_flattern(contract_address: str, output_dir: str) -> str:
    file_path = os.path.join(output_dir, f"{contract_address}.sol")
    if os.path.exists(file_path):
        return file_path
    command = f"cast etherscan-source {contract_address} --etherscan-api-key HKA8R3YVMVIT44AZQDN1H5AWZ477Q78KSY --flatten -d  {file_path}"
    os.system(command)
    return file_path


def get_tx_input_data(tx_hash, etherscan_api_key='HKA8R3YVMVIT44AZQDN1H5AWZ477Q78KSY'):
    url = "https://api.etherscan.io/api"
    params = {
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
        "apikey": etherscan_api_key
    }

    response = requests.get(url, params=params)
    data = response.json()

    if "result" in data:
        input_data = data["result"]["input"]
        return input_data
    return None


def get_constructor_arguments_via_creation_tx(contract_address, contract_name, local_slither_instance):
    creation_tx_hash = get_creation_tx_hash(contract_address)
    if creation_tx_hash is None:
        return None
    input_data = get_tx_input_data(creation_tx_hash)
    if input_data is None:
        return None
    creation_bytecode = ''
    for unit in local_slither_instance.crytic_compile.compilation_units.values():
        for (path, source_unit) in unit.source_units.items():
            if contract_name + '.sol' in path.absolute:
                creation_bytecode = source_unit.bytecodes_init[contract_name]
                break
    creation_bytecode = creation_bytecode.replace('0x', '')
    for suffix_length in range(10, len(creation_bytecode), 5):
        creation_bytecode_suffix = creation_bytecode[-suffix_length:]
        if len(input_data.split(creation_bytecode_suffix)) > 2:
            continue
        if creation_bytecode_suffix not in input_data:
            return None
        else:
            return input_data.split(creation_bytecode_suffix)[1]
    return None


def get_contract_constructor_arguments_and_solc_version(contract_address, contract_name, etherscan_api_key = 'HKA8R3YVMVIT44AZQDN1H5AWZ477Q78KSY'):
    def extract_solc_version(data):
        pattern = re.compile(r'v(\d+\.\d+\.\d+)')
        match = pattern.search(data)
        if match:
            return match.group(1)
        return None
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": 1,
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": etherscan_api_key
    }

    response = requests.get(url, params=params)
    data = response.json()
    constructor_arguments = ''
    solc_version = None
    if data["status"] == "1" and data["message"] == "OK":
        constructor_arguments = data["result"][0]["ConstructorArguments"]
        solc_version = extract_solc_version(data["result"][0]['CompilerVersion'])
    local_slither_instance = get_slither_instance(contract_address)

    if constructor_arguments is None or constructor_arguments == '':
        constructor_arguments = get_constructor_arguments_via_creation_tx(contract_address, contract_name, local_slither_instance)
    return constructor_arguments, solc_version


def get_slither_instance(contract_address):
    max_attempts = 2
    attempt = 0
    while attempt < max_attempts:
        try:
            contracts_slither_instance = Slither(contract_address, etherscan_api_key='HKA8R3YVMVIT44AZQDN1H5AWZ477Q78KSY')
            return contracts_slither_instance
        except Exception as e:
            attempt += 1
            time.sleep(5)
            if attempt == max_attempts:
                raise e


def process_file_safe(file_info):
    file_address, file_path, contract_name, contract_constructor_arguments, solc_version, result_dir, use_cache_insonsistency_file, need_to_confirm_inconsistency, need_to_propagate_comments, agent_number = file_info
    time.sleep(random.uniform(0.5, 10.5))
    contracts_slither_instance = get_slither_instance(file_address)
    inconsistencies = analyze(
        file_path, file_address, contract_name, contracts_slither_instance,
        contract_constructor_arguments, solc_version, use_cache_insonsistency_file, need_to_confirm_inconsistency, need_to_propagate_comments, agent_number
    )
    if need_to_confirm_inconsistency:
        result_file = os.path.join(result_dir, f"{file_address}.json")
        with open(result_file, 'w') as file:
            file.write(json.dumps(inconsistencies, indent=4))
    return (file_address, "success")


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze a single smart contract.")
    parser.add_argument('--result_dir', type=str, default='./result/', help='Directory to store results')
    parser.add_argument('--check_list', type=str, default='./address.txt', help='File containing contract addresses to analyze')
    parser.add_argument('--etherscan_api_key', type=str, required=True, help='Etherscan API key')
    parser.add_argument('--agent_number', type=int, default=5, help='Number of agents for inconsistency inference and confirmation')
    parser.add_argument('--address', type=str, default=None, help='Single contract address to analyze (overrides check_list)')
    parser.add_argument('--api_key', type=str, required=True, default='52ff3208-d023-4b4c-8267-19de576e3df9', help='API key for LLM')
    parser.add_argument('--base_url', type=str, required=True, default='https://ark.cn-beijing.volces.com/api/v3', help='Base URL for LLM API')
    parser.add_argument('--global_model', type=str, required=True, default='deepseek-r1-250120', help='Model name for LLM')
    parser.add_argument('--gpt_query_cache', type=str, default='./cache/', help='Cache directory for LLM queries')
    return parser.parse_args()


def main():
    args = parse_args()
    init_prompt_config(
        api_key=args.api_key,
        base_url=args.base_url,
        global_model_name=args.global_model,
        gpt_query_cache_dir=args.gpt_query_cache
    )
    result_dir = args.result_dir
    check_list_file = args.check_list
    etherscan_api_key = args.etherscan_api_key
    agent_number = args.agent_number
    single_address = args.address
    if check_list_file and os.path.exists(check_list_file):
        with open(check_list_file, 'r') as f:
            addresses = [x.strip().lower() for x in f.readlines() if x.strip()]
    elif single_address:
        addresses = [single_address.strip().lower()]
    else:
        return
    if not addresses:
        return
    for file_address in addresses:
        file = file_address + '.sol'
        file_result_dir = os.path.join(result_dir, file_address)
        file_path = os.path.join(file_result_dir, file)
        if not os.path.exists(file_result_dir):
            os.makedirs(file_result_dir)
        file_path = get_source_code_via_forge_cast_and_flattern(file_address, file_result_dir)
        contract_name = get_contract_name(etherscan_api_key, file_address)
        contract_constructor_arguments, solc_version = get_contract_constructor_arguments_and_solc_version(file_address, contract_name, etherscan_api_key)
        result = process_file_safe((file_address, file_path, contract_name, contract_constructor_arguments, solc_version, file_result_dir, False, True, True, agent_number))
    print_usage_statistics()


if __name__ == "__main__":
    main()

