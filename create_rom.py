def parse(lines, outfile):
    star_from = None
    for line in lines:
        addr, sep, rest = line.partition('   ')
        addr = int(addr[:-1], 16)
        if star_from is not None:
            for i in xrange(star_from, addr):
                outfile.write(chr(0))
            star_from = None
        if rest[0] == '*':
            star_from = addr
        else:
            mem_values, sep, rest = rest.partition('   ')
            for v in mem_values.split(' '):
                word = int(v, 16)
                outfile.write(chr(word>>8))
                outfile.write(chr(word&0xff))

if __name__ == '__main__':
    import sys
    with open(sys.argv[2], 'wb') as outfile:
        with open(sys.argv[1]) as f:
            parse(f.readlines(), outfile)
