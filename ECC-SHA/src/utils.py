"""
Utility Helpers
===============
Shared helpers used across all modules.
"""

import time
import functools


def to_bytes(data):
    """Convert string or bytes to bytes."""
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, bytes):
        return data
    raise TypeError(f"Expected str or bytes, got {type(data).__name__}")


def timer(func):
    """Decorator that measures and prints function execution time."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        print(f"  ⏱  {func.__name__} took {elapsed*1000:.2f} ms")
        return result

    return wrapper


def print_header(title: str, width: int = 60):
    """Print a formatted section header."""
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def print_step(step_num: int, description: str):
    """Print a numbered step."""
    print(f"\n[{step_num}] {description}")


def print_result(label: str, value, success: bool = True):
    """Print a labelled result with status icon."""
    icon = "✅" if success else "❌"
    print(f"  {icon} {label}: {value}")


def truncate_hex(hex_str: str, length: int = 40) -> str:
    """Truncate a hex string for display."""
    if len(hex_str) <= length:
        return hex_str
    return hex_str[:length] + "…"
