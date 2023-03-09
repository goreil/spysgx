from angr import ExplorationTechnique
import logging
# Define a custom exploration technique class
logger = logging.getLogger(__name__)

class EnclaveExploration(ExplorationTechnique):
    # Override the step method
    def step(self, simgr, stash='active', **kwargs):
        # Get the current state
        try:
            state = simgr.stashes[stash][0]
            # Find the symbol by address
            symbol = self.project.loader.find_symbol(state.addr)
            # Print out the symbol name if found
            if symbol:
                logger.debug(f"Current state is at {symbol.name}")
            # Call the original step method
        except IndexError:
            pass
        return super().step(simgr, stash=stash, **kwargs)