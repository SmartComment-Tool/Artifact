"""Module with base class for ForkMode and PathMode."""

import time
import argparse
from os.path import commonpath
from typing import List, Optional
from diffusc.utils.classes import ContractData, Diff
from diffusc.utils.crytic_print import CryticPrint
from diffusc.utils.slither_provider import SlitherProvider
from diffusc.utils.network_info_provider import NetworkInfoProvider
from diffusc.core.code_generation import CodeGenerator
from diffusc.utils.helpers import get_creation_bytecode
from slither.core.declarations import Contract
import random 
import string
from eth_abi import encode



def random_address() -> str:
    return "0x" + ''.join(random.choices('0123456789abcdef', k=40))

def random_int(bits: int) -> int:
    return random.randint(0, 2**bits - 1)

def random_string(length: int = 10) -> str:
    letters = string.hexdigits
    return ''.join(random.choices(letters, k=length))


def random_bytes(length: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(length))


def generate_random_constructor_parameter(slither_instance: Contract) -> str:
    constructor_params = []
    param_types = []
    if slither_instance.constructor is None:
        return ''
    for param in slither_instance.constructor.parameters:
        param_types.append(str(param.type))
        if str(param.type) == "address":
            constructor_params.append(random_address())
        elif str(param.type).startswith("uint"):
            byte_num = int(str(param.type).replace("uint", ""))
            constructor_params.append(random_int(byte_num))
        elif str(param.type) == "string":
            constructor_params.append(random_string())
        elif str(param.type).startswith("bytes"):
            print(param.type)
            if str(param.type) == "bytes":
                byte_num = 32
            else:
                byte_num = int(str(param.type).replace("bytes", ""))
            constructor_params.append(random_bytes(byte_num))
        elif str(param.type) == "bool":
            constructor_params.append(random.choice([True, False]))
    
    encoded_params = encode(param_types, constructor_params).hex()
    encoded_params = encoded_params
    print("Randomly Generated and Encoded Constructor Parameters: ", encoded_params)
    return encoded_params

# pylint: disable=too-many-instance-attributes
class AnalysisMode:
    """Base class inherited by PathMode and ForkMode."""

    _mode: str
    _provider: Optional[SlitherProvider]
    net_info: Optional[NetworkInfoProvider]
    _v1: Optional[ContractData]
    _v2: Optional[ContractData]
    _proxy: Optional[ContractData]
    _targets: Optional[List[ContractData]]
    _diff: Optional[Diff]
    code_generator: Optional[CodeGenerator]
    out_dir: str
    version: str
    upgrade: bool
    protected: bool
    external_taint: bool
    ignore_diff: bool

    def __init__(self, args: argparse.Namespace) -> None:
        self._v1 = None
        self._v2 = None
        self._proxy = None
        self._targets = None
        self._diff = None
        self.code_generator = None
        try:
            self.parse_args(args)
        except ValueError as err:
            raise ValueError(str(err)) from err

    def parse_args(self, args: argparse.Namespace) -> None:
        """Parse arguments that are used in both analysis modes."""

        if args.output_dir:
            self.out_dir = args.output_dir
        else:
            self.out_dir = "./"

        if args.version:
            self.version = args.version
        else:
            self.version = "0.8.0"

        # if args.fuzz_upgrade and not args.proxy:
        #     CryticPrint.print_warning(
        #         "  * Upgrade during fuzz sequence specified via command line parameter,"
        #         " but no proxy was specified. Ignoring...",
        #     )
        #     self.upgrade = False
        # else:
        #     self.upgrade = bool(args.fuzz_upgrade)
        self.upgrade = False
        self.protected = bool(args.include_protected)
        self.external_taint = bool(args.external_taint)
        self.ignore_diff = bool(args.ignore_diff)
        self.construtor_arguments = args.construtor_arguments

    def analyze_contracts(self) -> None:
        """
        Must be implemented by subclasses. Should get ContractData for all contracts and
        set self._v1 and self._v2, plus self._proxy and self._targets if necessary.
        """
        raise NotImplementedError()

    def dependencies_common_path(self) -> str:
        assert self._v1 and self._v2
        paths = [self._v1["path"], self._v2["path"]]
        if self._targets:
            paths.extend([target["path"] for target in self._targets])
        if self._proxy:
            paths.append(self._proxy["path"])
        return commonpath(paths)

    def write_test_contract(self) -> str:
        """
        Calls CodeGenerator.generate_test_contract and returns the generated contract code.
        :return: The test contract code as a string.
        """
        if not self._v1 or not self._v2:
            self.analyze_contracts()
        assert self._v1 and self._v2 and self._diff

        creation_bytecode_1, creation_bytecode_2, library_1, library_2 = get_creation_bytecode(self._v1['slither'], self._v2['slither'], self._v1, self._v2)
        if self.construtor_arguments is not None:
            print("Using Constructor Arguments Fetched from Etherscan", self.construtor_arguments)
            creation_params = self.construtor_arguments
        else:
            print("No Constructor Arguments Provided, Using Randomly Generated Arguments")
            creation_params = generate_random_constructor_parameter(self._v1['contract_object'])
        constructor_1 = creation_bytecode_1 + creation_params
        constructor_2 = creation_bytecode_2 + creation_params
        start_time = time.time()
        self.code_generator = CodeGenerator(
            self._v1,
            self._v2,
            self._mode,
            self.version,
            self.upgrade,
            self.protected,
            constructor_1,
            constructor_2,
            library_1,
            library_2,
            self.net_info,
            ignore_diff=self.ignore_diff,
        )
        self.code_generator.proxy = self._proxy
        if self._targets is not None:
            self.code_generator.targets = self._targets

        contract = self.code_generator.generate_test_contract(self._diff, output_dir=self.out_dir)
        end_time = time.time()
        CryticPrint.print_message(
            f"  * Contract generation completed in {end_time - start_time} seconds."
        )
        return contract
