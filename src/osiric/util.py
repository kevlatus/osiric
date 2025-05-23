import logging
from typing import Dict, Any, Optional, Union, List


def get_nested_key(
        data: Dict[str, Any],
        keys: Optional[Union[str, List[str]]],
) -> Any:
    """
    Safely retrieves a value from a nested dictionary using a dot-separated string or list of keys.

    Args:
        data: The dictionary to search within.
        keys: A dot-separated string (e.g., 'a.b.c') or a list of keys (e.g., ['a', 'b', 'c']).
              If None, returns the original data.

    Returns:
        The value found at the nested key path, or None if the path doesn't exist or data is invalid.
    """

    if keys is None:
        return data
    if not isinstance(data, dict):
        logging.debug(f"Cannot access keys in non-dict data: {type(data)}")
        return None

    if isinstance(keys, str):
        key_list = keys.split(".")
    elif isinstance(keys, list):
        key_list = keys
    else:
        logging.error(f"Invalid key type for nested access: {type(keys)}")
        return None

    value = data
    try:
        for key in key_list:
            if isinstance(value, dict):
                value = value[key]
            elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
                # Allow accessing list elements by index if key is a digit string
                value = value[int(key)]
            else:
                logging.debug(
                    f"Cannot access key '{key}' in value: {value} (type: {type(value)})"
                )
                return None
        return value
    except (KeyError, IndexError, TypeError) as e:
        logging.debug(
            f"Nested key path '{keys}' not found or invalid access in data. Error: {e}"
        )
        return None
    except Exception as e:
        logging.error(
            f"Unexpected error getting nested key '{keys}'. Error: {e}", exc_info=True
        )
        return None
