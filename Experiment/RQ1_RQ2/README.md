# Experiment

This directory contains the following components:

* `dataset1.txt` includes the address list of the 1,000 smart contracts used in RQ1 and RQ2.
* `./RawResult/` contains the raw output files from SmartComment when analyzing the 1,000 smart contracts.
* `dataset1_label.csv` records the label results for the 1,000 smart contracts. The first three columns in this file are the contract address, contract, and function reported by SmartComment to have code-comment inconsistencies. The fourth column is labeled as "TP" (True Positive) or "FP" (False Positive), representing the manual labeling results that verify whether the inconsistencies reported by SmartComment are true or false positives.



### Reproduce the Experiment Results

The following commands can be used to reproduce the experiment results in RQ1 and RQ2. For `dataset1.txt` , execute the command below. The results will be stored in `result_dir`. The version of the LLM api used in our experiment is deepseek-r1-250120.

```bash
cd Code
python3 main.py --check_list dataset1.txt --api_key LLM-API-KEY --etherscan_api_key Etherscan-API-Key --base_url LLM-API-Base-URL --global_model deepseek-r1-250120 --result_dir Result-Dir
```

The `./RawResult` folder stores the raw results from executing these commands.