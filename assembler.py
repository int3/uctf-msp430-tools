from opcodes import *

def assemble(lines):
    rv = []
    for line in lines:
        line = line.strip()
        if len(line) == 0:
            continue
        op, sep, args = line.partition(' ')
        args = [a.strip() for a in args.split(',')]
        words = assemble_one(op, args)
        for w in words:
            rv.append(w)
    return rv

def assemble_one(op, args):
    rv = []
    byte_op = False
    immed = None
    if op[-2:] == '.b':
        op = op[:-2]
        byte_op = True
    if op[0] == 'j':
        assert len(args) == 1
        arg = args[0]
        assert arg[0] == '$' and arg[1] in ['+', '-'] and arg[2:4] == '0x'
        offset = int(arg[1:], 16)
        assert -2**9 <= offset <= 2**9-1
        rv.append(0x2000 | (condition_codes[op] << 10) | ((offset >> 1) - 1 & 0x3ff))
    elif op in format_one:
        assert len(args) == 1
        mode, addr, immed = parse_address(args[0])
        rv.append(0x1000 | format_one[op] << 7 | int(byte_op) << 6 | mode << 4 | addr)
        if immed:
            rv.append(immed)
    elif op in format_two:
        assert len(args) == 2
        dest_mode, dest_addr, dest_immed = parse_address(args[1])
        assert immed is None or (dest_mode == 1 and dest_addr == 2) # dest cannot be an immediate
        src_mode, src_addr, src_immed = parse_address(args[0])
        rv.append(format_two[op] << 12 | src_addr << 8 | dest_mode << 7 | \
                int(byte_op) << 6 | src_mode << 4 | dest_addr)
        if src_immed: rv.append(src_immed)
        if dest_immed: rv.append(dest_immed)
    else:
        raise Exception('nyi')

    return map(swpb, rv)

def swpb(word):
    return ((word >> 8) & 0xff) | ((word << 8) & 0xff00)

def parse_address(s):
    if s[0] == 'r':
        return (0, int(s[1:]), None)
    elif s[-1] == ')':
        offset, sep, rest = s.partition('(')
        return (1, int(rest[1:-1]), int(offset, 16))
    elif s[0] == '@':
        if s[-1] == '+':
            return (3, int(s[2:-1]), None)
        else:
            return (2, int(s[2:]), None)
    elif s[0] == '#':
        immed = int(s[1:], 16)
        if immed == 4:
            return (2, 2, None)
        elif immed == 8:
            return (3, 2, None)
        elif immed == 0:
            return (0, 3, None)
        elif immed == 1:
            return (1, 3, None)
        elif immed == 2:
            return (2, 3, None)
        elif immed == -1:
            return (3, 3, None)
        else:
            return (3, 0, immed)
    elif s[0] == '&':
        return (1, 2, int(s[1:], 16))
    else:
        raise Exception()

def hex2(n):
    return "%04x" % (n & 0xffff)

if __name__ == '__main__':
    import sys
    if sys.argv[1] == '-i':
        while True:
            try:
                s = raw_input('> ')
                print hex2(assemble([s])[0])
            except EOFError:
                print 'EOF found; exiting.'
                break
            except Exception:
                print 'Failed to assemble.'
    else:
        with open(sys.argv[1]) as f:
            print "".join(hex2(inst) for inst in assemble(f.readlines()))
