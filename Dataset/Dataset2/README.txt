# Dataset2

The second dataset is a manually annotated dataset containing 200 real-world smart contracts, sampled from the same previous dataset. It includes manually annotated labels indicating true/false positives and negatives of code-comment inconsistencies, which are used in RQ3 to enable evaluation metrics such as recall and F1-score for a comprehensive comparison of SmartComment with the prior work SmartCoco.

To our knowledge, this is the first annotated dataset for code-comment inconsistencies in smart contracts, which includes annotated labels for true positives, false positives, and false negatives, thereby enabling the comparison of precision, recall, and F1-score between different tools.

This directory contains the following files:

* `./dataset2.txt` contains the address list of the 200 smart contracts used in RQ3.
* `./SourceCode/` contains the source codes of these files, with filenames named by the contract addresses.
