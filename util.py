def as_signed(n, bits=16):
    mask = 1 << (bits - 1)
    return (n ^ mask) - mask # convert to signed

