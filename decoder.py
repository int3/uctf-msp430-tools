from collections import namedtuple
from util import as_signed
from opcodes import condition_codes, format_one, format_two

Address = namedtuple('Address', ['mode', 'loc', 'data'])

class Decoder(object):

    def __init__(self, handlers):
        self.condition_handlers = [None] * 8
        self.format_one_handlers = [None] * 7
        self.format_two_handlers = [None] * 16
        self.register_handlers(self.condition_handlers, condition_codes, handlers)
        self.register_handlers(self.format_one_handlers, format_one, handlers)
        self.register_handlers(self.format_two_handlers, format_two, handlers)

    @staticmethod
    def register_handlers(handler_table, mapping, handlers):
        for k, v in mapping.iteritems():
            if handler_table[v] is not None:
                continue
            if hasattr(handlers, 'do_' + k):
                handler_table[v] = getattr(handlers, 'do_' + k)

        def make_nyi(insn_name):
            def nyi(*args):
                print "Insn NYI: %s" % insn_name
            return nyi

        for k, v in mapping.iteritems():
            if handler_table[v] is None:
                handler_table[v] = make_nyi(k)

    @staticmethod
    def is_byte_insn(insn):
        return insn & (1 << 6)

    def decode(self, pc, mem):
        if pc & 1:
            raise Exception('insn unaligned. pc: %x' % pc)
        insn = mem[pc]
        if insn >> 12 == 1: # format 1
            mode = insn >> 4 & 0x3
            loc = insn & 0xf
            size = 2
            if (mode == 1 and loc != 3) or (mode == 3 and loc == 0):
                data = as_signed(mem[pc+2])
                size += 2
            else:
                data = None
            return (self.format_one_handlers[insn >> 7 & 0x7],
                    self.is_byte_insn(insn),
                    [Address(mode, loc, data)], size)
        elif insn >> 13 == 1: # jump
            mask = 1 << 10
            offset = (((insn & 0x3ff) + 1 << 1) ^ mask) - mask # convert to signed
            return (self.condition_handlers[insn >> 10 & 0x7],
                    self.is_byte_insn(insn),
                    [offset], 2)
        else: # format 2
            src_mode = insn >> 4 & 0x3
            src_loc = insn >> 8 & 0xf
            size = 2
            if (src_mode == 1 and src_loc != 3) or (src_mode == 3 and src_loc == 0):
                src_data = as_signed(mem[pc+2])
                size += 2
            else:
                src_data = None
            dest_mode = insn >> 7 & 0x1
            dest_loc = insn & 0xf
            dest_data = None
            if dest_mode == 1 and dest_loc != 3:
                dest_data = as_signed(mem[pc+size])
                size += 2
            return (self.format_two_handlers[insn >> 12 & 0xf],
                    self.is_byte_insn(insn),
                    [Address(src_mode, src_loc, src_data),
                     Address(dest_mode, dest_loc, dest_data)], size)

