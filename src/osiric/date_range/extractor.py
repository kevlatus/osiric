import asyncio
from datetime import datetime, timedelta
from typing import (
    Any,
    Optional,
    AsyncGenerator,
    Tuple,
    TypeVar,
    Union,
    Sequence,
    Iterator,
)

import pydantic

from ..common import ExtractionError
from ..extractor import DataExtractor


def generate_time_windows(
    overall_start_time: datetime,
    overall_end_time: datetime,
    window_delta: timedelta,
) -> Iterator[Tuple[datetime, datetime]]:
    """
    Generates a series of time windows (start_time, end_time) for a given overall range and delta.

    Args:
        overall_start_time: The absolute start of the entire date range.
        overall_end_time: The absolute end of the entire date range (exclusive).
        window_delta: The duration of each smaller time window (e.g., timedelta(days=1)).

    Yields:
        Tuple[datetime.datetime, datetime.datetime]: A tuple representing (window_start_time, window_end_time).
                                                     The window_end_time is exclusive.
    """
    if window_delta <= timedelta(0):
        raise ValueError("window_delta must be positive.")
    if overall_start_time >= overall_end_time:
        # Or yield nothing, depending on desired behavior for empty/invalid ranges
        # raise ValueError("overall_start_time must be before overall_end_time.")
        return

    current_window_start = overall_start_time
    while current_window_start < overall_end_time:
        current_window_end = current_window_start + window_delta
        # Ensure the window does not exceed the overall_end_time
        if current_window_end > overall_end_time:
            current_window_end = overall_end_time

        yield current_window_start, current_window_end

        current_window_start = current_window_end
        # Safety break if delta is zero or negative, though validated above
        if current_window_start >= overall_end_time or window_delta <= timedelta(0):
            break


WrappedRecordType = TypeVar("WrappedRecordType")
WrappedConfigType = TypeVar("WrappedConfigType", bound=Optional[pydantic.BaseModel])
DateRangeState = Optional[Tuple[datetime, datetime]]


class DateRangeExtractorWrapper(
    DataExtractor[
        WrappedRecordType,
        Optional[datetime],
        WrappedConfigType,
    ]
):
    """
    A wrapper extractor that iterates over date ranges, breaking them into smaller
    time windows and calling a wrapped extractor for each window.

    The wrapped extractor's pagination strategy must be configured to accept a
    tuple (start_datetime, end_datetime) as its `initial_state` and use it
    to filter API requests accordingly.
    """

    def __init__(
        self,
        wrapped_extractor: DataExtractor[
            WrappedRecordType,
            DateRangeState,
            WrappedConfigType,
        ],
        start_time: datetime,
        end_time: datetime,
        window_delta: timedelta,
    ):
        """
        Initializes the DateRangeExtractorWrapper.

        Args:
            wrapped_extractor: An instance of a BaseExtractor subclass.
            start_time: The absolute start of the entire date range.
            end_time: The absolute end of the entire date range (exclusive).
            window_delta: The duration of each smaller time window.
        """

        super().__init__(wrapped_extractor.config)

        if not isinstance(wrapped_extractor, DataExtractor):
            raise TypeError("wrapped_extractor must be an instance of BaseExtractor.")
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise TypeError(
                "overall_start_time and overall_end_time must be datetime objects."
            )
        if not isinstance(window_delta, timedelta):
            raise TypeError("window_delta must be a timedelta object.")
        if window_delta <= timedelta(0):
            raise ValueError("window_delta must be positive.")

        self.wrapped_extractor = wrapped_extractor
        self.overall_start_time = start_time
        self.overall_end_time = end_time
        self.window_delta = window_delta

        # The wrapper's own state will track the last successfully processed window's start time.
        # This allows for resuming if the overall process is interrupted.
        self._current_state: Optional[datetime] = None
        self.logger.info(
            f"DateRangeExtractorWrapper initialized for range "
            f"{self.overall_start_time} to {self.overall_end_time} with window {self.window_delta}."
        )

    async def _connect(self) -> Optional[Any]:
        """
        Connection management is primarily handled by the wrapped extractor
        when its extract method is called. This wrapper might not need
        its own persistent connection.
        If the wrapped_extractor requires explicit connect/close around multiple
        extract calls, this logic would need to be adapted.
        """
        self.logger.debug(
            f"Wrapper: _connect called. Delegating to wrapped extractor's lifecycle."
        )
        # If wrapped_extractor had a connect method that should be called once:
        # return await self.wrapped_extractor._connect()
        return None  # Or ConnectionType if defined for wrapped_extractor

    async def _close(self) -> None:
        """
        Similar to _connect, resource cleanup is often managed by the
        wrapped extractor's extract method lifecycle or its own _close.
        """
        self.logger.debug(
            f"Wrapper: _close called. Delegating to wrapped extractor's lifecycle."
        )
        # If wrapped_extractor had a close method that should be called once:
        # await self.wrapped_extractor._close()
        pass

    async def _extract_data(
        self,
        initial_state: Optional[datetime] = None,
    ) -> AsyncGenerator[Union[WrappedRecordType, Sequence[WrappedRecordType]], None]:
        """
        Iterates through time windows, calling the wrapped extractor for each.

        Args:
            initial_state: The initial state for this wrapper's run,
                               typically last_completed_window_end
                               to resume from.
        Yields:
            Records from the wrapped extractor.
        """
        start_from_time = self.overall_start_time
        if initial_state is not None:
            start_from_time = (
                initial_state  # Start from the end of the last completed window
            )
            self.logger.info(
                f"Wrapper: Resuming from time {start_from_time} based on initial state."
            )
        else:
            self.logger.info(
                f"Wrapper: Starting new extraction from {self.overall_start_time}."
            )

        if start_from_time >= self.overall_end_time:
            self.logger.info(
                f"Wrapper: Start time {start_from_time} is at or after overall end time {self.overall_end_time}. Nothing to extract."
            )
            return

        time_windows = generate_time_windows(
            start_from_time,  # Start from where we left off or overall_start_time
            self.overall_end_time,
            self.window_delta,
        )

        for window_start, window_end in time_windows:
            self.logger.info(
                f"Wrapper: Processing window: {window_start} to {window_end}"
            )

            # The `initial_state` for the wrapped_extractor is the current time window.
            # The wrapped_extractor's pagination strategy MUST be configured to use this.
            current_window_as_state: Tuple[datetime, datetime] = (
                window_start,
                window_end,
            )

            try:
                # We expect the wrapped_extractor to handle its own connection lifecycle
                # within its extract() method if needed (like RestApiExtractor does).
                # The second item yielded by wrapped_extractor.extract is its own state,
                # which we don't directly use here, but it's part of the signature.
                all_data = []
                async for data, _ in self.wrapped_extractor.extract(
                    initial_state=current_window_as_state
                ):
                    if isinstance(data, list):
                        all_data.extend(data)
                    else:
                        all_data.append(data)
                self._update_state(window_end)
                yield all_data

            except ExtractionError as e:
                self.logger.error(
                    f"Wrapper: ExtractionError in wrapped extractor for window {window_start}-{window_end}: {e}"
                )
                # Decide on error handling: re-raise, skip window, etc.
                # For now, re-raising will stop the whole process.
                raise ExtractionError(
                    f"Error in wrapped extractor for window {window_start}-{window_end}: {e}"
                ) from e
            except Exception as e:
                self.logger.error(
                    f"Wrapper: Unexpected error in wrapped extractor for window {window_start}-{window_end}: {e}",
                    exc_info=True,
                )
                raise ExtractionError(
                    f"Unexpected error in wrapped_extractor for window {window_start}-{window_end}: {e}"
                ) from e

            # Small delay to be polite, configurable if needed
            await asyncio.sleep(0.1)

        self.logger.info(f"Wrapper: Finished processing all time windows.")
