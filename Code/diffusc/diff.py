import os
import shutil
from diffusc.core.path_mode import PathMode
import argparse
from solc_select.solc_select import switch_global_version
from eth_utils import is_address
from diffusc.core.path_mode import PathMode
from diffusc.core.fork_mode import ForkMode
from diffusc.core.hybrid_mode import HybridMode
from diffusc.core.analysis_mode import AnalysisMode
from diffusc.core.code_generation import CodeGenerator
from diffusc.core.report_generation import ReportGenerator
from diffusc.utils.helpers import write_to_file, get_pragma_versions_from_file
from diffusc.utils.crytic_print import CryticPrint

from diffusc.core.echidna import create_echidna_process, run_timed_campaign, run_echidna_campaign
import diffusc.utils.network_vars as net_vars


def write_diff_test(contract_path1, contract_path2, contract_name, output_dir, influenced_main_contract_funcs, solc_version, construtor_arguments):
    args = argparse.Namespace(
        v1 = contract_path1,
        v2 = contract_path2,
        output_dir = output_dir,
        include_protected = False,
        external_taint = False,
        ignore_diff = False,
        run_duration = 5,
        run_custom = None,
        contract_name = contract_name,
        workers = 4,
        first_failure = True,
        tainted_main_contract_funcs = influenced_main_contract_funcs,
        version = solc_version,
        construtor_arguments = construtor_arguments
        # 添加更多参数
    )
    
        
    if args.output_dir is not None:
        output_dir = args.output_dir
        if not str(output_dir).endswith(os.path.sep):
            output_dir += os.path.sep
            
    # if os.path.exists(os.path.join(args.output_dir, "corpus")):
    #     print("Deleting Existing corpus folder")
    #     shutil.rmtree(os.path.join(args.output_dir, "corpus")) 


    seq_len = 50
    # if args.seq_len:
    #     if str(args.seq_len).isnumeric():
    #         seq_len = int(args.seq_len)
    #     else:  # pragma: no cover
    #         CryticPrint.print_error(
    #             "\n* Sequence length provided is not numeric. Defaulting to 100.",
    #         )

    test_len = 200000
    # if args.campaign_len:
    #     if str(args.campaign_len).isnumeric():
    #         test_len = int(args.campaign_len)
    #     else:  # pragma: no cover
    #         CryticPrint.print_error(
    #             "\n* Campaign length provided is not numeric. Defaulting to 100.",
    #         )

    contract_addr = ""
    # if args.contract_addr and is_address(args.contract_addr):
    #     contract_addr = args.contract_addr
    #     CryticPrint.print_information(
    #         "\n* Exploit contract address specified via command line parameter: "
    #         f"{contract_addr}",
    #     )

    senders = []
    # if args.senders:
    #     for sender in str(args.senders).split(","):
    #         if is_address(sender):
    #             senders.append(sender)
    #         else:
    #             CryticPrint.print_error(
    #                 f"\n* Provided sender {sender} is not an address, skipping...",
    #             )

    # Start the analysis
    analysis: AnalysisMode
    CryticPrint.print_information("* Inspecting V1 and V2 contracts:")
    
    analysis = PathMode(args)
    contract = analysis.write_test_contract()
    write_to_file(f"{output_dir}DiffFuzz.sol", contract)
    CryticPrint.print_success(
        f"  * Fuzzing contract generated and written to {output_dir}DiffFuzz.sol.",
    )


    config_file = CodeGenerator.generate_config_file(
        f"corpus",
        test_len,
        contract_addr,
        seq_len,
        senders=senders,
        output_dir=output_dir,
    )
    
    write_to_file(f"{output_dir}CryticConfig.yaml", config_file)
    CryticPrint.print_success(
        f"  * Echidna configuration file generated and written to {output_dir}CryticConfig.yaml.",
    )
    
    return analysis

def execute_diff_test(contract_path1, contract_path2, contract_name, output_dir, influenced_main_contract_funcs, solc_version, construtor_arguments):

    args = argparse.Namespace(
        v1 = contract_path1,
        v2 = contract_path2,
        output_dir = output_dir,
        include_protected = False,
        external_taint = False,
        ignore_diff = False,
        run_duration = 5,
        run_custom = None,
        contract_name = contract_name,
        workers = 4,
        first_failure = True,
        tainted_main_contract_funcs = influenced_main_contract_funcs,
        version = solc_version,
        construtor_arguments = construtor_arguments
        # 添加更多参数
    )
    
        
    if args.output_dir is not None:
        output_dir = args.output_dir
        if not str(output_dir).endswith(os.path.sep):
            output_dir += os.path.sep
            
    # if os.path.exists(os.path.join(args.output_dir, "corpus")):
    #     print("Deleting Existing corpus folder")
    #     shutil.rmtree(os.path.join(args.output_dir, "corpus")) 


    seq_len = 50
    # # if args.seq_len:
    # #     if str(args.seq_len).isnumeric():
    # #         seq_len = int(args.seq_len)
    # #     else:  # pragma: no cover
    # #         CryticPrint.print_error(
    # #             "\n* Sequence length provided is not numeric. Defaulting to 100.",
    # #         )

    test_len = 200000
    # # if args.campaign_len:
    # #     if str(args.campaign_len).isnumeric():
    # #         test_len = int(args.campaign_len)
    # #     else:  # pragma: no cover
    # #         CryticPrint.print_error(
    # #             "\n* Campaign length provided is not numeric. Defaulting to 100.",
    # #         )

    # contract_addr = ""
    # # if args.contract_addr and is_address(args.contract_addr):
    # #     contract_addr = args.contract_addr
    # #     CryticPrint.print_information(
    # #         "\n* Exploit contract address specified via command line parameter: "
    # #         f"{contract_addr}",
    # #     )

    # senders = []
    # if args.senders:
    #     for sender in str(args.senders).split(","):
    #         if is_address(sender):
    #             senders.append(sender)
    #         else:
    #             CryticPrint.print_error(
    #                 f"\n* Provided sender {sender} is not an address, skipping...",
    #             )

    # Start the analysis
    if args.run_duration or args.run_custom:
        run_duration = 60
        if args.run_duration:
            run_duration = args.run_duration
        workers = args.workers

        # In path mode, we need to run Echidna from a dir with access to dependencies as well as test contract
        contract_file = (
            args.run_custom[0] if args.run_custom else f"{output_dir}DiffFuzz.sol"
        )
        output_dir = os.path.relpath(output_dir, os.path.curdir)
        # prefix = os.path.commonpath([output_dir])
        prefix = os.path.abspath(output_dir)
        config = os.path.relpath(os.path.join(output_dir, "CryticConfig.yaml"), prefix)
        contract_file = os.path.relpath(contract_file, prefix)
            

        CryticPrint.print_information(
            f"* Run mode enabled. Starting Echidna with {run_duration} minute time limit..."
        )
        # if analysis.version:
        # raise Exception("analysis.version is not defined")
        proc = create_echidna_process(
            prefix,
            contract_file,
            args.run_custom[1] if args.run_custom else "DiffFuzz",
            config,
            ["--format", "json", "--workers", str(workers)],
        )
        if args.first_failure:
            max_value, fuzzes, results = run_echidna_campaign(proc, max_len = test_len)
        else:
            max_value, fuzzes, results = run_timed_campaign(proc, run_duration)
        if max_value <= 0:
            CryticPrint.print_error(
                f"* Echidna failed to find a difference after {fuzzes} rounds of fuzzing"
            )
            return False
        if results is not None:
            CryticPrint.print_success(
                f"* Echidna found a difference after {fuzzes} rounds of fuzzing"
            )
            ReportGenerator.report_from_json_results(results, [])
            # ReportGenerator.report_from_json_results(results)
        # if results is not None and analysis.code_generator is not None:
        #     new_funcs = analysis.code_generator.new_func_wrappers
        #     ReportGenerator.report_from_json_results(results, new_funcs)

    CryticPrint.print_message(
        "\n-----------------------------------------------------------",
    )
    CryticPrint.print_message(
        "My work here is done. Thanks for using me, have a nice day!",
    )
    CryticPrint.print_message(
        "-----------------------------------------------------------",
    )
    return True