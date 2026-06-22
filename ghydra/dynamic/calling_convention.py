"""Pure x86-64 calling-convention logic (no unicorn dependency).

Arg-register order, return register, stack-arg layout, and 16-byte stack
alignment for the high-level call() primitive. Unit-tested directly.
"""

SUPPORTED_CONVENTIONS = {"sysv", "ms"}

_ARG_REGISTERS = {
    "sysv": ["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
    "ms": ["RCX", "RDX", "R8", "R9"],
}


def _check(convention: str) -> str:
    if convention not in SUPPORTED_CONVENTIONS:
        raise ValueError(
            f"unsupported calling convention: {convention!r} "
            f"(supported: {sorted(SUPPORTED_CONVENTIONS)})")
    return convention


def arg_registers(convention: str) -> list[str]:
    return list(_ARG_REGISTERS[_check(convention)])


def return_register(convention: str) -> str:
    _check(convention)
    return "RAX"


def validate_args(args: list) -> None:
    """Reject any arg that is not an int or a {"bytes": hex} dict (v1 scope)."""
    for i, arg in enumerate(args):
        if isinstance(arg, bool):
            raise ValueError(f"arg[{i}]: bool is not a valid integer arg")
        if isinstance(arg, int):
            continue
        if isinstance(arg, dict) and set(arg) == {"bytes"} and isinstance(arg["bytes"], str):
            continue
        raise ValueError(
            f"arg[{i}]: only int or {{\"bytes\": hex}} args are supported in v1 "
            f"(float/struct args are out of scope)")
