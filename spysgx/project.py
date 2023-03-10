import logging
import pickle
import re

import angr
import guardian

from .explorer import PrintSymbolsExplorer

logger = logging.getLogger(__name__)
info, debug = logger.info, logger.debug


class Project:
    """
    The Project class creates a spySGX project from an enclave and a target ecall.

    Parameters
    ----------
    enclave_path : str
        Path to the enclave
    target_ecall : str
        Name of the target ecall
    pickle_path : str
        Path to the pickle file, where the project is cached for later use
    """
    def __init__(self, enclave_path, target_ecall, pickle_path = None, base_addr=0x400000,
    ):
        # Load the project from a pickle file if it exists
        self.proj = angr.Project(
            enclave_path, load_options={"main_opts": {"base_addr": base_addr}}
        )

        # [HACK] TODO Current hack before we have the correct SGX-SDK
        self.proj.hook_symbol("sgx_is_outside_enclave", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
        # [Hack end]

        self.guard = guardian.Project(
            self.proj,
            find_missing_ecalls_or_ocalls=True,
            violation_check=False,
        )
        # Set the correct target ecall
        ecall_id = None
        for ecall in self.guard.ecalls:
            if ecall[1] == target_ecall:
                ecall_id = ecall[0]
                break
        
        assert ecall_id is not None, f"Could not find ecall {target_ecall}"
        self.guard.set_target_ecall(ecall_id)
        
        # Use a custom exploration technique to print out the current symbol for debugging
        self.guard.simgr.use_technique(PrintSymbolsExplorer())

        self.traces = None # Will be set by dump_trace
        ecall_name = re.match(r"^sgx_(.*)", target_ecall).group(1)
        self._reach_symbol(ecall_name)

        # Save the project to a pickle file
        if pickle_path is not None:
            with open(pickle_path, "wb+") as f:
                pickle.dump(self, f)
            info(f"Saved project to {pickle_path}")


    def _reach_symbol(self, find):
        """Try to reach a symbol with guardian."""
        simgr = self.guard.simgr
        # Avoid is a nice way to just call a function if that function is always false
        simgr.explore(find=self.proj.loader.find_symbol(find).rebased_addr)
        simgr.move(from_stash="active", to_stash="discarded")
        simgr.move(from_stash="found", to_stash="active")
        # Clear the history.bbl_addrs
        simgr.active[0].history.trim()

        return simgr
