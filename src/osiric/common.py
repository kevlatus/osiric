from typing import TypeVar, Optional

import pydantic

RecordType = TypeVar("RecordType")
"""Represents the type of a single extracted record"""

StateType = TypeVar("StateType")
"""Represents the type of the state managed by the extractor"""

ConfigType = TypeVar("ConfigType", bound=Optional[pydantic.BaseModel])
"""Represents the type of the config by the extractor"""


class ExtractionError(Exception):
    """Custom exception for errors during the extraction process."""

    pass
