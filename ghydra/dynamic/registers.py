"""x86-64 register name -> Unicorn constant mapping.

Importing this module does NOT require unicorn unless resolve_register is called.
"""

def _build_map():
    try:
        from unicorn.x86_const import (
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
            UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
            UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
            UC_X86_REG_R15, UC_X86_REG_EFLAGS,
        )
    except ImportError:
        return {}
    return {
        "RAX": UC_X86_REG_RAX, "RBX": UC_X86_REG_RBX, "RCX": UC_X86_REG_RCX,
        "RDX": UC_X86_REG_RDX, "RSI": UC_X86_REG_RSI, "RDI": UC_X86_REG_RDI,
        "RSP": UC_X86_REG_RSP, "RBP": UC_X86_REG_RBP, "RIP": UC_X86_REG_RIP,
        "R8": UC_X86_REG_R8, "R9": UC_X86_REG_R9, "R10": UC_X86_REG_R10,
        "R11": UC_X86_REG_R11, "R12": UC_X86_REG_R12, "R13": UC_X86_REG_R13,
        "R14": UC_X86_REG_R14, "R15": UC_X86_REG_R15, "EFLAGS": UC_X86_REG_EFLAGS,
    }


X86_64_REGISTERS = _build_map()


def resolve_register(name: str) -> int:
    """Resolve a register name (case-insensitive) to a Unicorn constant."""
    if not X86_64_REGISTERS:
        raise KeyError("unicorn not installed; pip install ghydramcp[unicorn]")
    key = name.upper()
    if key not in X86_64_REGISTERS:
        raise KeyError(f"Unknown x86-64 register: {name}")
    return X86_64_REGISTERS[key]
