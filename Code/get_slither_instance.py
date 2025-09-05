from slither import Slither
import os
from crytic_compile import CryticCompile
from diffusc.utils.helpers import get_pragma_versions_from_file
from solc_select.solc_select import (
    switch_global_version,
)
def get_slither_instance_from_crytic_export(file_path, contract_name, solc_version):
    switch_global_version(solc_version, True)
    return Slither(file_path)

