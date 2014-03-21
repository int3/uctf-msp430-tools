from disassembler import Disassembler
from collections import deque

class Tracer(object):

    def __init__(self, fname):
        self.tracefile = open(fname, 'w')
        self.circular_buffer = deque(maxlen=0x11)
        self.loop_header = None
        self.loop_end = None
        self.loop_count = 0

    def trace(self, pc, name, is_byte_insn, args, m):
        if self.loop_header is not None:
            if self.loop_header == pc:
                self.loop_count += 1
                return
            elif self.loop_header < pc <= self.loop_end:
                return
            else:
                self.tracefile.write('<loop %d times>\n' % self.loop_count)
                self.loop_header = None
                self.loop_count = 0

        if name[0] == 'j' and name != 'jmp' and -0x20 <= args[0] < 0:
            target = args[0] + pc
            simple_loop = True
            for op_pc, op_name in reversed(self.circular_buffer):
                if op_pc == target:
                    break
                if op_name[0] == 'j':
                    simple_loop = False
                    break
            if simple_loop:
                self.loop_header = target
                self.loop_end = pc

        if name[0] != 'j':
            emulated_name, emulated_args = \
                    Disassembler.try_emulate_insn(name, args)
            if is_byte_insn:
                emulated_name += '.b'
            arg_strs = map(Disassembler.pretty_addr, emulated_args)
            values = []
            for i, s in enumerate(arg_strs):
                if s[0] != '#':
                    values.append('%04x (%04x)' %
                            (m.get_addr(args[i], inc=False), m.registers[args[i].loc]))
            arg_str = ", ".join(arg_strs)
            if len(values) > 0:
                arg_str += ' [%s]' % ", ".join(values)
        else:
            emulated_name = name
            arg_str = '$%+x [%04x]' % (args[0], args[0] + pc)

        self.circular_buffer.append((pc, name))

        self.tracefile.write("%04x %s\t%s\n" % (pc,
            emulated_name, arg_str))
