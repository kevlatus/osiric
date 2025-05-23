from abc import ABC, abstractmethod
import copy
import logging
from typing import (
    Generic,
    Optional,
    AsyncGenerator,
    Tuple,
)

from .common import RecordType, StateType, ExtractionError, ConfigType


# TODO: Use structured logging (e.g., JSON format) for easier parsing.
# TODO: Add more contextual info (e.g., extractor instance ID).


class DataExtractor(Generic[RecordType, StateType, ConfigType], ABC):
    """
    Generic and Abstract Base Class for asynchronous data extractors.

    Supports generic record types and state management for incremental loads
    via two distinct state update methods: one for records, one after processing a batch.

    Type Parameters:
        RecordType: The type of individual records yielded by the extractor.
        StateType: The type of the state tracked by the extractor.
        ConnectionType: The type of the connection managed by the extractor.

    TODO: Add unit tests for this base class and its interactions.
    TODO: Consider adding an ErrorHandler strategy for customizable error handling (retry, skip, abort).
    """

    def __init__(
            self,
            config: ConfigType,
    ):
        """
        Initializes the BaseExtractor.

        Args:
            config: Configuration dictionary for the extractor.

        Raises:
            ValueError: If config is not a dictionary.

        """
        self.config = config
        # TODO: Consider adding a unique instance ID for better logging in concurrent scenarios
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

        self._current_state: Optional[StateType] = None
        self._initial_state_for_run: Optional[StateType] = None

        self.logger.info(f"Initializing {self.__class__.__name__}")

    @property
    def current_state(self) -> Optional[StateType]:
        """
        Returns a copy of the latest state recorded during the extraction process.

        Note: Uses deepcopy by default. If StateType is complex and performance is critical,
              evaluate if copy.copy (shallow) or immutable state objects are sufficient.
        """

        # TODO: If state objects are simple or immutable, copy.copy might be sufficient and faster than copy.deepcopy.
        try:
            return copy.deepcopy(self._current_state)
        except TypeError:
            # deepcopy might fail on complex non-copyable objects (like generators, locks)
            self.logger.warning(
                "Could not deepcopy state, returning direct reference (potential for mutation issues)"
            )
            return self._current_state

    async def _connect(self):
        """
        Establishes an asynchronous connection to the data source.
        Return value depends on the source (e.g., aiohttp session, db connection pool).
        """
        pass

    @abstractmethod
    async def _extract_data(
            self,
            initial_state: Optional[StateType] = None,
    ) -> AsyncGenerator[RecordType, None]:
        """
        Asynchronously extracts data from the source, potentially using initial state.

        Implementations of this method in subclasses are responsible for calling
        `self._update_state_from_batch(batch_context)` after processing each page/batch
        if batch-level state updates are needed.

        Args:
            initial_state: The state provided to the `extract` method for this run.

        Yields:
            AsyncGenerator[RecordType, None]: Records from the source.
        """
        if False:
            yield

    async def _close(self) -> None:
        """Asynchronously closes the connection and cleans up resources."""
        pass

    def _update_state(self, new_state: StateType) -> None:
        """
        (Optional) Updates the internal extractor state based on the context of a
        batch/page/chunk of data processed by `_extract_data`. This is typically
        called after processing a full response from an API page, reading a file chunk, etc.

        Args:
        """
        self._current_state = new_state

    async def extract(
            self,
            initial_state: Optional[StateType] = None,
    ) -> AsyncGenerator[
        Tuple[RecordType, Optional[StateType]],
        None,
    ]:
        """
        Orchestrates the async extraction: connect, extract records, update state, close.

        Calls `_update_state_from_record` with each record before it's yielded along with the state.
        The `_extract_data` implementation is responsible for calling `_update_state_from_batch`
        if needed (e.g., for sync tokens, cursors file offsets).

        Args:
            initial_state: An optional initial state to begin extraction from.
                           For long-running jobs, consider loading this from a persistent store.

        Yields:
            AsyncGenerator[Tuple[RecordType, Optional[StateType]], None]: Tuples of (record, current_state_snapshot)
                                                                        from the source.
        """
        self.logger.info("Starting asynchronous extraction process...")
        # TODO: Use copy.copy if deepcopy is too slow and state allows.
        try:
            self._current_state = copy.deepcopy(initial_state)
            self._initial_state_for_run = copy.deepcopy(initial_state)
        except TypeError:
            self.logger.warning(
                "Could not deepcopy initial state, using direct reference."
            )
            self._current_state = initial_state
            self._initial_state_for_run = initial_state

        self.logger.info(
            f"Extraction starting with initial state: {self._initial_state_for_run}"
        )

        try:
            self.logger.debug("Connecting...")
            await self._connect()
            self.logger.info("Connection established.")

            self.logger.info("Extracting data...")
            async for data in self._extract_data(
                    initial_state=self._initial_state_for_run
            ):
                # Yield the record and a snapshot of the current state
                # self.current_state property returns a copy
                yield data, self.current_state

            self.logger.info(f"Async data extraction complete")

        except NotImplementedError as e:
            self.logger.error(f"Async method not implemented in subclass: {e}")
            raise ExtractionError(
                f"Async method not implemented in subclass: {e}"
            ) from e
        except ExtractionError as e:
            self.logger.error(f"Async extraction failed: {e}")
            raise
        except Exception as e:
            self.logger.error(
                f"An unexpected error occurred during async extraction: {e}",
                exc_info=True,
            )
            raise ExtractionError(
                f"An unexpected async extraction error occurred: {e}"
            ) from e
        finally:
            # Ensure connection is closed even if errors occur
            await self._close_safely()
            # Clear run-specific initial state reference
            self._initial_state_for_run = None
            self.logger.info("Asynchronous extraction process finished.")

    async def __aenter__(self):
        """Allows using the extractor with 'async with'."""

        self.logger.debug("Entering async context manager.")
        # Connection is established within extract()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Ensures resources are cleaned up when exiting 'async with' block."""

        self.logger.debug(f"Exiting async context manager (exception: {exc_type}).")
        # Ensure close is called, even if extract wasn't fully completed
        await self._close_safely()
        # Return False to propagate exceptions that occurred within the 'with' block
        return False

    async def _close_safely(self):
        """Helper async method to safely call the subclass's _close method."""

        self.logger.debug("Attempting safe close via _close()...")
        try:
            await self._close()
        except NotImplementedError:
            self.logger.warning("_close() method not implemented in subclass.")
        except Exception as e:
            # Log error during close but don't prevent cleanup completion
            self.logger.error(f"Error during safe async close: {e}", exc_info=True)
        finally:
            self.logger.debug("Async safe close finished.")
