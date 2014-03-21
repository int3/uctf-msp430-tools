condition_codes = {
    'jne': 0,
    'jnz': 0,
    'jeq': 1,
    'jz': 1,
    'jnc': 2,
    'jlo': 2,
    'jc': 3,
    'jhs': 3,
    'jn': 4,
    'jge': 5,
    'jl': 6,
    'jmp': 7
}

format_one = {
    'rrc': 0,
    'swpb': 1,
    'rra': 2,
    'sxt': 3,
    'push': 4,
    'call': 5,
    'reti': 6
}

format_two = {
    'mov': 4,
    'add': 5,
    'addc': 6,
    'subc': 7,
    'sub': 8,
    'cmp': 9,
    'dadd': 10,
    'bit': 11,
    'bic': 12,
    'bis': 13,
    'xor': 14,
    'and': 15
}
