# SmartComment

## Description

This directory contains the source code for SmartComment, the first technique that combines Large Language Models (LLMs) with program analysis techniques to detect code-comment inconsistencies in smart contracts.

## Installation

**Environment: SmartComment is tested on Python 3.13 and Ubuntu 22.04.2 LTS.**

**Installation steps for SmartComment:**

```bash
cd Code
python -m venv comment-code
source comment-code/bin/activate
brew install echidna
pip install -r requirements.txt
```

SmartComment is built on Slither and Echidna.

## Usage

Once initialization is complete, SmartComment is ready to analyze smart contracts.

For detailed usage information, execute the help command below:

```bash
cd Code
python3 main.py -h
```

SmartComment will output the following information:

```
usage: main.py [-h] [--result_dir RESULT_DIR] [--check_list CHECK_LIST] [--etherscan_api_key ETHERSCAN_API_KEY] [--agent_number AGENT_NUMBER] [--address ADDRESS]
               [--api_key API_KEY] [--base_url BASE_URL] [--global_model GLOBAL_MODEL] [--gpt_query_cache GPT_QUERY_CACHE]

SmartComment: Analyze code comment inconsistencies in smart contracts.

options:
  -h, --help            show this help message and exit
  --result_dir RESULT_DIR
                        Directory to store results
  --check_list CHECK_LIST
                        File containing contract addresses to analyze
  --etherscan_api_key ETHERSCAN_API_KEY
                        Etherscan API key
  --agent_number AGENT_NUMBER
                        Number of agents for inconsistency inference and confirmation
  --address ADDRESS     Single contract address to analyze (overrides check_list)
  --api_key API_KEY     API key for LLM
  --base_url BASE_URL   Base URL for LLM API
  --global_model GLOBAL_MODEL
                        Model name for LLM
  --gpt_query_cache GPT_QUERY_CACHE
                        Cache directory for LLM queries
```

Specifically, to use SmartComment, you need to provide the API key for the LLM API, the base URL of the LLM API provider, and the name of the model. SmartComment will use the OpenAI library to handle these parameters.

### Analyze Smart Contracts

SmartComment supports analyzing a single contract. For example, using the following command, Slither can analyze a single contract. It will use the `etherscan_api_key` to fetch and download the contract from Etherscan and use the `api_key` to interact with the user-specified LLM.

The analysis results from SmartComment will be stored in the specified `result_dir`.

```bash
python3 main.py --address 0x2de91872cd4de1ed07d51492e55262b278bcbcd8 --api_key LLM-API-KEY --base_url --etherscan_api_key Etherscan-API-Key LLM-API-Base-URL --global_model deepseek-r1-250120  --result_dir Result-Dir
```

SmartComment also supports batch analysis of contracts. For example, using the following command, Slither can analyze each contract listed in `check_list` (the check list should be a text file, with each line containing a contract address).

```bash
python3 main.py --check_list check_list.txt --api_key LLM-API-KEY --etherscan_api_key Etherscan-API-Key --base_url LLM-API-Base-URL --global_model deepseek-r1-250120 --result_dir Result-Dir
```



### Reproduce the Experiment Results

The following commands can be used to reproduce the experiment results from our paper. For each `check_list_file` (`Dataset1/dataset1.txt` and `Dataset2/dataset2.txt`), execute the command below. The results will be stored in `result_dir`. The version of the LLM api used in our experiment is deepseek-r1-250120.

```bash
cd Code
python3 main.py --check_list check_list.txt --api_key LLM-API-KEY --etherscan_api_key Etherscan-API-Key --base_url LLM-API-Base-URL --global_model deepseek-r1-250120 --result_dir Result-Dir
```

The `Experiments/*/RawResult` folder stores the raw results from executing these commands.