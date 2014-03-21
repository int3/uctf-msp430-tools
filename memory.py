from array import array

class Registers(object):

    def __init__(self):
        self.regs = array('H', [0] * 16)

    def __getitem__(self, no):
        return self.regs[no]

    def __setitem__(self, no, v):
        self.regs[no] = v

class Memory(object):

    def __init__(self, f, size=0x10000):
        self.mem = array('B')
        self.mem.fromfile(f, size)

    def __getitem__(self, addr):
        if isinstance(addr, slice):
            # I am assuming no step value is provided in the slice
            arr = []
            for i in xrange(addr.start, addr.stop, 2):
                arr.append(self.mem[i] | self.mem[i+1] << 8)
            return arr
        else:
            return self.mem[addr] | self.mem[addr+1] << 8

    def __setitem__(self, addr, v):
        self.mem[addr] = v & 0xff
        self.mem[addr+1] = v >> 8 & 0xff

    def __len__(self):
        return len(self.mem)

    def get_byte(self, addr):
        return self.mem[addr]

    def set_byte(self, addr, v):
        self.mem[addr] = v & 0xff

    def tofile(self, f):
        self.mem.tofile(f)
