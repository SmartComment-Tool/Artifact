# Experiment

This directory contains the following components:

* `dataset2.txt` includes the address list of the 200 smart contracts used in RQ3.
* `./RawResult/` contains the raw output files from SmartComment when analyzing the 1,000 smart contracts.
* `dataset2_label_SmartComment.csv` records SmartComment (and its ablation variants)'s results on the annotated dataset. The first three columns in this file are the contract address, contract, and functions. The fourth column is labeled as "TP" (True Positive), "FP" (False Positive), "TN" (True Negative), or "FN" (False Negative), representing the manual labeling results.
* `dataset2_label_smartcoco.csv` records the results on the annotated dataset obtained using SmartCoco's official code(at [https://github.com/SCCoCo/SmartCoCo](https://github.com/SCCoCo/SmartCoCo)). The first three columns in this file are the contract address, contract, and functions. The fourth column is labeled as "TP" (True Positive), "FP" (False Positive), "TN" (True Negative), or "FN" (False Negative), representing the manual labeling results.

### Reproduce the Experiment Results

The following commands can be used to reproduce the experiment results of SmartComment in RQ3. For `dataset2.txt` , execute the command below. The results will be stored in `result_dir`. The version of the LLM api used in our experiment is deepseek-r1-250120.

```bash
cd Code
python3 main.py --check_list dataset2.txt --api_key LLM-API-KEY --etherscan_api_key Etherscan-API-Key --base_url LLM-API-Base-URL --global_model deepseek-r1-250120 --result_dir Result-Dir
```

The `./RawResult` folder stores the raw results from executing these commands.