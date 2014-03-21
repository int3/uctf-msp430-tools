import sys
from decoder import Decoder, Address

class Disassembler(object):

    def __init__(self):
        self.decoder = Decoder(self)

    def __getattr__(self, name):
        if not name.startswith('do_'):
            raise AttributeError("Disassembler has no attribute '%s'" % name)

        return name[3:]

    def disassemble(self, pc, mem, limit_addr=sys.maxint, is_trace=False):
        try:
            while pc < limit_addr and pc < len(mem):
                name, is_byte_insn, args, size = self.decoder.decode(pc, mem)
                is_ret = self.is_ret(name, args)
                name, args = self.try_emulate_insn(name, args)
                full_name = name
                if name[0] == 'j':
                    arg_str = '$%+x' % args[0]
                    if not is_trace:
                        arg_str += ' [%x]' % (args[0] + pc)
                else:
                    if is_byte_insn:
                        full_name += '.b'
                    arg_str = (', '.join(map(self.pretty_addr, args)))
                yield pc, '%s\t' % full_name + arg_str
                pc += size
                if (is_ret or name == 'jmp') and not is_trace:
                    break
        except:
            yield pc, 'Failed to disassemble.'

    reg_names = ['pc', 'sp', 'sr', 'cg']

    @staticmethod
    def is_ret(name, args):
        return name == 'mov' and args[0] == Address(3, 1, None) and \
                args[1] == Address(0, 0, None)

    @staticmethod
    def pretty_reg(n):
        if n < 4:
            return Disassembler.reg_names[n]
        return 'r%d' % n

    @staticmethod
    def pretty_addr(addr):
        if addr.loc == 2:
            if addr.mode == 1:
                return '&%04x' % addr.data
            elif addr.mode in [2, 3]:
                return '#%x' % (1 << addr.mode)
        elif addr.loc == 3:
            if addr.mode == 3:
                return '#-1'
            else:
                return '#%x' % addr.mode
        elif addr.mode == 3 and addr.loc == 0:
            return '#%04x' % addr.data

        if addr.mode == 0:
            return Disassembler.pretty_reg(addr.loc)
        elif addr.mode == 1:
            return '%x(%s)' % (addr.data, Disassembler.pretty_reg(addr.loc))
        elif addr.mode == 2:
            return '@r%d' % addr.loc
        else:
            return '@%s+' % Disassembler.pretty_reg(addr.loc)

    @staticmethod
    def try_emulate_insn(name, args):
        if Disassembler.is_ret(name, args):
            return 'ret', []
        elif name == 'mov' and args[1] == Address(0, 0, None):
            return 'br', [args[0]]
        return name, args

if __name__ == '__main__':
    from emulator import Memory
    import os.path
    disassembler = Disassembler()
    with open(sys.argv[1]) as f:
        mem = Memory(f, os.path.getsize(sys.argv[1]))
        dis = disassembler.disassemble(0, mem, is_trace=True)
        print '\n'.join(line[1] for line in dis)
