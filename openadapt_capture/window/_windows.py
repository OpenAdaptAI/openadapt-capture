"""Windows platform window capture using pywinauto.

Copied from legacy OpenAdapt window/_windows.py. Only import paths changed.
"""

import pickle
import time
from pprint import pprint
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pywinauto

from loguru import logger


def get_active_window_state(read_window_data: bool) -> dict:
    """Get the state of the active window.

    Returns:
        dict: A dictionary containing the state of the active window.
            The dictionary has the following keys:
                - "title": Title of the active window.
                - "left": Left position of the active window.
                - "top": Top position of the active window.
                - "width": Width of the active window.
                - "height": Height of the active window.
                - "meta": Meta information of the active window.
                - "data": None (to be filled with window data).
                - "window_id": ID of the active window.
    """
    # catch specific exceptions, when except happens do log.warning
    try:
        active_window = get_active_window()
    except RuntimeError as e:
        logger.warning(e)
        return {}
    meta = get_active_window_meta(active_window)
    rectangle_dict = dictify_rect(meta["rectangle"])
    if read_window_data:
        data = get_element_properties(active_window)
    else:
        data = {}
    state = {
        "title": meta["texts"][0],
        "left": meta["rectangle"].left,
        "top": meta["rectangle"].top,
        "width": meta["rectangle"].width(),
        "height": meta["rectangle"].height(),
        "meta": {**meta, "rectangle": rectangle_dict},
        "data": data,
        "window_id": meta["control_id"],
    }
    try:
        pickle.dumps(state)
    except Exception as exc:
        logger.warning(f"{exc=}")
        state.pop("data")
    return state


def get_active_window_meta(
    active_window: "pywinauto.application.WindowSpecification",
) -> dict:
    """Get the meta information of the active window.

    Args:
        active_window: The active window object.

    Returns:
        dict: A dictionary containing the meta information of the
              active window.
    """
    if not active_window:
        logger.warning(f"{active_window=}")
        return None
    result = active_window.get_properties()
    return result


def get_active_element_state(x: int, y: int) -> dict:
    """Get the state of the active element at the given coordinates.

    Args:
        x (int): The x-coordinate.
        y (int): The y-coordinate.

    Returns:
        dict: A dictionary containing the properties of the active element.
    """
    active_window = get_active_window()
    active_element = active_window.from_point(x, y)
    properties = get_properties(active_element)
    properties["rectangle"] = dictify_rect(properties["rectangle"])
    return properties


def _safe_text(value: object) -> str:
    """Return a stable textual property without leaking object reprs."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _element_info_value(element: object, name: str) -> object | None:
    info = getattr(element, "element_info", None)
    if info is None:
        return None
    try:
        return getattr(info, name, None)
    except Exception:
        return None


def _safe_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _supported_patterns(element: object) -> list[str]:
    patterns = (
        ("invoke", "iface_invoke"),
        ("value", "iface_value"),
        ("selection_item", "iface_selection_item"),
        ("toggle", "iface_toggle"),
        ("expand_collapse", "iface_expand_collapse"),
    )
    supported = []
    for label, attribute in patterns:
        try:
            if getattr(element, attribute, None) is not None:
                supported.append(label)
        except Exception:
            continue
    return supported


def _structural_node(element: object) -> dict:
    try:
        properties = element.get_properties()
    except Exception:
        try:
            properties = get_properties(element)
        except Exception:
            properties = {}

    rectangle = properties.get("rectangle")
    bounds = dictify_rect(rectangle) if rectangle is not None else None
    texts = properties.get("texts") or []
    name = properties.get("name") or (texts[0] if texts else "")
    role = properties.get("control_type") or _element_info_value(
        element, "control_type"
    )
    return {
        "role": _safe_text(role),
        "name": _safe_text(name),
        "automation_id": _safe_text(
            properties.get("automation_id")
            or _element_info_value(element, "automation_id")
        ),
        "class_name": _safe_text(
            properties.get("class_name")
            or _element_info_value(element, "class_name")
        ),
        "bounds": bounds,
        "supported_patterns": _supported_patterns(element),
    }


def get_active_element_observation(x: int, y: int) -> dict:
    """Capture a versioned, JSON-safe UIA fingerprint at action time."""
    active_window = get_active_window()
    target = active_window.from_point(x, y)

    ancestors = []
    current = target
    for _ in range(5):
        try:
            current = current.parent()
        except Exception:
            break
        if current is None:
            break
        ancestors.append(_structural_node(current))
        if current == active_window:
            break

    window_node = _structural_node(active_window)
    process_id = _element_info_value(target, "process_id")
    if process_id is None:
        process_id = _element_info_value(active_window, "process_id")

    return {
        "schema_version": 1,
        "observer": "windows_uia",
        "target": _structural_node(target),
        "ancestors": ancestors,
        "window_name": window_node["name"],
        "process_id": _safe_int(process_id),
    }


def get_active_window() -> "pywinauto.application.WindowSpecification":
    """Get the active window object.

    Returns:
        pywinauto.application.WindowSpecification: The active window object.
    """
    import pywinauto

    app = pywinauto.application.Application(backend="uia").connect(active_only=True)
    window = app.top_window()
    return window.wrapper_object()


def get_element_properties(
    element: "pywinauto.application.WindowSpecification",
) -> dict:
    """Recursively retrieves the properties of each element and its children.

    Args:
        element: An instance of a custom element class
                 that has the `.get_properties()` and `.children()` methods.

    Returns:
        dict: A nested dictionary containing the properties of each element
          and its children.
        The dictionary includes a "children" key for each element,
        which holds the properties of its children.

    Example:
        element = Element()
        properties = get_element_properties(element)
        print(properties)
        # Output: {'prop1': 'value1', 'prop2': 'value2',
                  'children': [{'prop1': 'child_value1', 'prop2': 'child_value2',
                  'children': []}]}
    """
    properties = get_properties(element)
    children = element.children()

    if children:
        properties["children"] = [get_element_properties(child) for child in children]

    # Dictify the "rectangle" key
    properties["rectangle"] = dictify_rect(properties["rectangle"])

    return properties


def dictify_rect(rect: "pywinauto.win32structures.RECT") -> dict:
    """Convert a rectangle object to a dictionary.

    Args:
        rect: The rectangle object.

    Returns:
        dict: A dictionary representation of the rectangle.
    """
    rect_dict = {
        "left": rect.left,
        "top": rect.top,
        "right": rect.right,
        "bottom": rect.bottom,
    }
    return rect_dict


def get_properties(element: "pywinauto.application.WindowSpecification") -> dict:
    """Retrieves specific writable properties of an element.

    This function retrieves a dictionary of writable properties for a given element.
    It achieves this by temporarily modifying the class of the element object using
    monkey patching.This approach is necessary because in some cases, the original
    class of the element may have a `get_properties()` function that raises errors.

    Args:
        element: The element for which to retrieve writable properties.

    Returns:
        A dictionary containing the writable properties of the element,
        with property names as keys and their corres
        ponding values.

    """
    _element_class = element.__class__
    import pywinauto

    class TempElement(element.__class__):
        writable_props = pywinauto.base_wrapper.BaseWrapper.writable_props

    # Instantiate the subclass
    element.__class__ = TempElement
    # Retrieve properties using get_properties()
    properties = element.get_properties()
    element.__class__ = _element_class
    return properties


def main() -> None:
    """Test function for retrieving and inspecting the state of the active window.

    This function is primarily used for testing and debugging purposes.
    """
    time.sleep(1)

    state = get_active_window_state()
    pprint(state)
    pickle.dumps(state)
    import ipdb

    ipdb.set_trace()  # noqa: E702


if __name__ == "__main__":
    main()
