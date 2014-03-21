#! /usr/bin/env python

import sys
from termcolor import colored
from util import as_signed
from decoder import Decoder, Address
from disassembler import Disassembler
from memory import Registers, Memory

PC, SP, SR, CG = range(4)

disassembler = Disassembler()

class Machine(object):

    def __init__(self, fname):
        self.fname = fname
        self.decoder = Decoder(self)
        self.breakpoints = {}
        self.breakpoint_conditions = {}
        self.prev_input = None
        self.hex_input_mode = False
        self.tracked_registers = set([SP])
        self.reset()

    def reset(self):
        with open(self.fname) as f:
            self.mem = Memory(f)
        self.door_unlocked = False
        self.step_count = 1
        self.break_at_finish = -1
        self.registers = Registers()
        self.registers[PC] = self.mem[0xfffe]
        self.call_targets = [self.registers[PC]]
        self.callsites = []
        self.current_block_start = self.registers[PC]
        self.insn_count = 0

    def debug(self, prog_input=raw_input, debug_input=raw_input,
            prog_output=sys.stdout, debug_output=sys.stdout,
            trace=None):
        self.prog_input = prog_input
        self.debug_input = debug_input
        self.prog_output = prog_output
        self.debug_output = debug_output
        self.trace = trace
        try:
            while self.execute_next():
                pass
        except EOFError:
            self.display('EOF received. Bye!')

    def display(self, v):
        self.debug_output.write(str(v) + '\n')

    def display_state(self):
        lines = disassembler.disassemble(self.current_block_start, self.mem,
                self.registers[PC] + 10)
        for line in lines:
            addr, insn = line
            text = "%x: %s" % line
            if addr == self.registers[PC]:
                self.display(colored(text, 'green'))
            else:
                self.display(text)
        self.display('')
        for i, r in enumerate(self.registers):
            self.debug_output.write('%s: %04x' % (Disassembler.pretty_reg(i), r))
            if (i + 1) % 4 == 0:
                self.debug_output.write('\n')
            else:
                self.debug_output.write('\t')
        self.display('')
        for reg in self.tracked_registers:
            self.debug_output.write(colored('%s >> ' % Disassembler.pretty_reg(reg), 'blue'))
            self.display_mem(self.registers[reg])

    def display_mem(self, addr):
        start = max(0, addr - 16)
        end = min(0xffff, addr + 16)
        self.debug_output.write('%x:' % start)
        for i in xrange(start, end):
            if (i - start) % 2 == 0:
                self.debug_output.write(' ')
            text = '%02x' % self.mem.get_byte(i)
            if i == addr:
                text = colored(text, 'red')
            self.debug_output.write(text)
        self.display('')

    def handle_cmds(self):
        while True:
            self.display_state()
            s = self.debug_input('> ')
            if s == '':
                if self.prev_input is not None:
                    s = self.prev_input
            self.prev_input = s
            cmd, sep, rest = s.partition(' ')
            rest = rest.strip()

            if cmd == 'break':
                target, sep, cond = rest.partition(' if ')
                self.breakpoints[int(target, 16)] = -1
                if cond != '':
                    self.breakpoint_conditions[int(target, 16)] = \
                            lambda: eval(cond, globals(), self.__dict__)
            elif cmd == 'unbreak':
                if rest == 'all':
                    self.breakpoints = set()
                else:
                    try:
                        del self.breakpoints[int(rest, 16)]
                        del self.breakpoint_conditions[int(rest, 16)]
                    except:
                        pass
            elif cmd == 'breakpoints':
                self.display('List of breakpoints currently set:')
                for b in self.breakpoints.keys():
                    self.display('\t%x' % b)
            elif cmd == 'track':
                self.tracked_registers.add(int(rest))
            elif cmd == 'untrack':
                self.tracked_registers.discard(int(rest))
            elif cmd == 'reset':
                self.reset()
                break
            elif cmd == 'print':
                try:
                    self.display(eval(rest, globals(), self.__dict__))
                except:
                    self.display("Error while evaluating expression")
            elif cmd == 'exec':
                try:
                    exec rest in globals(), self.__dict__
                except:
                    self.display("Error while evaluating statements")
            elif cmd == 'hex':
                self.hex_input_mode = True
                self.display('Program input will now be treated as hexadecimal.')
            elif cmd == 'text':
                self.hex_input_mode = False
                self.display('Program input will now be treated as text.')
            elif cmd == 'dump':
                with open(rest, 'wb') as f:
                    self.mem.tofile(f)
            elif cmd == 'mem':
                self.display_mem(int(rest, 16))
                print ''
            elif cmd == 's':
                if rest != '':
                    self.step_count = int(rest)
                else:
                    self.step_count = 1
                break
            elif cmd == 'insncount':
                self.display(self.insn_count)
            elif cmd == 'c':
                break
            elif cmd == 'f':
                self.break_at_finish = 0
                break
            elif cmd == 'tbreak':
                self.breakpoints[int(rest, 16)] = 1
            elif cmd == 'bt':
                self.print_backtrace()
            elif cmd == 'trace':
                self.trace = Tracer(rest).trace
            elif cmd == 'disas':
                addr = int(rest, 16)
                lines = disassembler.disassemble(addr, self.mem,
                        addr + 10)
                for line in lines:
                    print "%x: %s" % line
            else:
                self.display('Unrecognized command')

    def print_backtrace(self):
        pc = self.registers[PC]
        i = 0
        self.display('Backtrace:')
        for callsite, call_target in \
                reversed(zip(self.callsites + [pc], self.call_targets)):
            self.display('#%d\t%x in %x' % (i, callsite, call_target))
            i += 1
        self.display('')

    def should_break(self, pc):
        if pc not in self.breakpoints:
            return False
        if pc in self.breakpoint_conditions:
            return self.breakpoint_conditions[pc]()
        return True

    def execute_next(self):
        cpuoff = self.registers[SR] & (1 << 4)
        if cpuoff:
            self.display('<CPUOFF bit set. Exiting.>')
        if cpuoff or self.door_unlocked:
            self.display('<Executed %d instructions.>' % self.insn_count)
            return False
        pc = self.registers[PC]

        self.insn_count += 1
        step_count = self.step_count
        if self.step_count > 0:
            self.step_count -= 1

        should_break = self.should_break(pc)
        if should_break:
            if self.breakpoints[pc] == 1: # -1 is a permanent breakpoint
                del self.breakpoints[pc]
                if pc in self.breakpoint_conditions:
                    del self.breakpoint_conditions[pc]
            elif self.breakpoints > 1:
                self.breakpoints[pc] -= 1

        if should_break or step_count == 1:
            self.handle_cmds()
        pc = self.registers[PC] # in case of reset

        is_ret = False
        is_call = False
        if pc == 0x10:
            self.handle_callgate(self.registers[SR])
            self.mem[0x10] = 0x4130 # ret

        handler, is_byte_insn, args, size = self.decoder.decode(pc, self.mem)
        self.operand_bytes = 1 if is_byte_insn else 2

        if handler is None:
            raise Exception('Failed to decode instruction at pc %x.' % pc)

        name = handler.__name__[3:]
        self.next_pc = pc + size
        self.registers[PC] += 2

        if not self.peephole_execute(name, is_byte_insn, args, size):
            if self.trace is not None:
                self.trace(pc, name, is_byte_insn, args, self)

            handler(*args)

        is_ret = Disassembler.is_ret(name, args)
        is_call = name == 'call'

        if self.registers[PC] == pc + 2:
            self.registers[PC] = self.next_pc
        else:
            self.current_block_start = self.registers[PC]
            if self.break_at_finish >= 0:
                if is_ret:
                    self.break_at_finish -= 1
                    if self.break_at_finish == -1:
                        self.step_count = 1
                elif is_call:
                    self.break_at_finish += 1

            if is_call:
                self.callsites.append(pc)
                self.call_targets.append(self.registers[PC])
            elif is_ret:
                self.callsites.pop()
                self.call_targets.pop()

        return True

    def peephole_execute(self, name, is_byte_insn, args, size):
        if not (name == 'jnz' and args[0] == -2):
            return False

        prev_insn_data = self.decoder.decode(self.registers[PC] - 4, self.mem)
        prev_handler, prev_is_byte_insn, prev_args, prev_size = prev_insn_data
        if not (prev_handler.__name__[3:] == 'add' and \
                prev_args[0] == Address(3, 3, None) and \
                isinstance(prev_args[1], Address) and not prev_args[1].loc == 0):
            return False

        self.operand_bytes = 1 if prev_is_byte_insn else 2

        if self.trace is not None:
            v = self.get_addr(prev_args[1], 0)
            self.trace(self.registers[PC],
                    '%s_peephole_%d' % (name, v), is_byte_insn, args, self)

        self.set_addr(prev_args[1], 0)
        self.registers[PC] = self.next_pc
        self.zero = 1
        self.negative = 0
        self.carry = 1

        return True

    def get_addr(self, addr, operand_bytes=None, inc=True):
        if operand_bytes is None:
            operand_bytes = self.operand_bytes

        if addr.loc == 2:
            if addr.mode == 1:
                return self._get_addr(addr.data, operand_bytes)
            elif addr.mode >= 2:
                return 1 << addr.mode
        elif addr.loc == 3:
            if addr.mode == 3:
                return (1 << self.operand_bytes * 8) - 1 # -1
            else:
                return addr.mode
        elif addr.loc == 0 and addr.mode == 3:
            return addr.data

        if addr.mode == 0:
            mask = (1 << (8 * self.operand_bytes)) - 1
            return self.registers[addr.loc] & mask
        else:
            if addr.mode == 1:
                index = addr.data
            else:
                index = 0
            rv = self._get_addr(self.registers[addr.loc] + index, operand_bytes)
            if addr.mode == 3 and inc:
                self.registers[addr.loc] += 2
            return rv

    def _get_addr(self, addr, operand_bytes):
        if operand_bytes == 1:
            return self.mem.get_byte(addr)
        else:
            return self.mem[addr]

    def set_addr(self, addr, v, operand_bytes=None):
        if operand_bytes is None:
            operand_bytes = self.operand_bytes

        if addr.mode == 0:
            mask = (1 << (8 * self.operand_bytes)) - 1
            self.registers[addr.loc] = v & mask
        else:
            if addr.loc == 2 and addr.mode == 1:
                dest = addr.data
            elif addr.mode == 1:
                dest = self.registers[addr.loc] + addr.data
            else:
                dest = self.registers[addr.loc]

            if operand_bytes == 1:
                self.mem.set_byte(dest, v)
            else:
                self.mem[dest] = v

    @property
    def carry(self):
        return self.registers[SR] & 1

    @carry.setter
    def carry(self, v):
        self.registers[SR] &= 0xfffe # clear bit
        self.registers[SR] |= v

    @property
    def zero(self):
        return self.registers[SR] >> 1 & 1

    @zero.setter
    def zero(self, v):
        self.registers[SR] &= ~(1 << 1) & 0xffff
        self.registers[SR] |= v << 1

    @property
    def negative(self):
        return self.registers[SR] >> 2 & 1

    @negative.setter
    def negative(self, v):
        self.registers[SR] &= ~(1 << 2) & 0xffff
        self.registers[SR] |= v << 2

    @property
    def overflow(self):
        return self.registers[SR] >> 8 & 1

    @overflow.setter
    def overflow(self, v):
        self.registers[SR] &= ~(1 << 8) & 0xffff
        self.registers[SR] |= v

    def set_status_result_bits(self, v):
        self.registers[SR] = 0
        bit_count = self.operand_bytes * 8
        mask = (1 << bit_count) - 1
        self.negative = (v & mask) >> 15 & 1
        self.zero = int((v & mask) == 0)
        self.carry = v >> 16 & 1

    def do_mov(self, src, dest):
        self.set_addr(dest, self.get_addr(src))

    def do_add(self, src, dest):
        v = self.get_addr(dest) + self.get_addr(src)
        self.set_status_result_bits(v)
        self.set_addr(dest, v)

    def do_addc(self, src, dest):
        v = self.get_addr(dest) + self.get_addr(src) + self.carry
        self.set_status_result_bits(v)
        self.set_addr(dest, v)

    def do_sub(self, src, dest):
        v = self.get_addr(dest) + (~self.get_addr(src) & 0xffff) + 1
        self.set_status_result_bits(v)
        self.set_addr(dest, v)

    def do_cmp(self, src, dest):
        v = self.get_addr(dest) + (~self.get_addr(src) & 0xffff) + 1
        self.set_status_result_bits(v)

    def do_bit(self, src, dest):
        v = self.get_addr(dest) & self.get_addr(src)
        self.set_status_result_bits(v)

    def do_bic(self, src, dest):
        v = self.get_addr(dest) & ~self.get_addr(src)
        self.set_addr(dest, v)

    def do_bis(self, src, dest):
        v = self.get_addr(dest) | self.get_addr(src)
        self.set_addr(dest, v)

    def do_xor(self, src, dest):
        v = self.get_addr(dest) ^ self.get_addr(src)
        self.set_status_result_bits(v)
        self.carry = 1 - self.zero
        self.set_addr(dest, v)

    def do_and(self, src, dest):
        v = self.get_addr(dest) & self.get_addr(src)
        self.set_status_result_bits(v)
        self.carry = 1 - self.zero
        self.set_addr(dest, v)

    def do_push(self, src):
        self.registers[SP] -= 2
        self.mem[self.registers[SP]] = self.get_addr(src)

    def do_call(self, dest):
        self.registers[SP] -= 2
        self.mem[self.registers[SP]] = self.next_pc
        self.registers[PC] = self.get_addr(dest)

    def do_jeq(self, offset):
        if self.zero:
            self.registers[PC] += offset - 2

    def do_jnz(self, offset):
        if not self.zero:
            self.registers[PC] += offset - 2

    def do_jc(self, offset):
        if self.carry:
            self.registers[PC] += offset - 2

    def do_jnc(self, offset):
        if not self.carry:
            self.registers[PC] += offset - 2

    def do_jge(self, offset):
        if self.negative ^ self.overflow == 0:
            self.registers[PC] += offset - 2

    def do_jl(self, offset):
        if self.negative ^ self.overflow:
            self.registers[PC] += offset -2
    
    def do_jmp(self, offset):
        self.registers[PC] += offset - 2

    def do_swpb(self, dest):
        v = self.get_addr(dest)
        v = v >> 8 | (v << 8 & 0xff00)
        self.set_addr(dest, v)

    def do_sxt(self, dest):
        v = as_signed(self.get_addr(dest), 8)
        self.set_status_result_bits(v)
        self.carry = 1 - self.zero
        self.set_addr(dest, v)

    def do_rrc(self, dest):
        v = self.get_addr(dest)
        new_carry = v & 1
        bit_count = self.operand_bytes * 8
        mask = (1 << bit_count) - 1
        v = ((v >> 1) | (self.carry << bit_count - 1)) & mask
        # what happens to high order bits?
        if v & mask & 0x8000:
            self.negative = 1
        if v != 0:
            self.zero = 0
        self.carry = new_carry
        self.set_addr(dest, v)

    def do_rra(self, dest):
        bit_count = self.operand_bytes * 8
        mask = (1 << bit_count) - 1
        v = self.get_addr(dest)
        v = (as_signed(v, bit_count) >> 1) & mask
        self.zero = 0
        if v & 0x8000:
            self.negative = 1
        self.set_addr(dest, v)

    def do_dadd(self, src, dest):
        s = self.get_addr(src)
        d = self.get_addr(dest)
        carry = 0
        negative = 0
        v = 0
        for i in xrange(0, self.operand_bytes * 2):
            src_nibble = (s >> i * 4) & 0xf
            dest_nibble = (d >> i * 4) & 0xf
            n = src_nibble + dest_nibble + carry
            negative = (n >> 3) & 1
            if n >= 10:
                n -= 10
                carry = 1
            else:
                carry = 0
            v |= (n & 0xf) << i * 4
        self.carry = carry
        if negative == 1:
            self.negative = negative
        self.set_addr(dest, v)

    def handle_callgate(self, sr):
        if not sr >> 15 & 1:
            return
        interrupt = sr >> 8 & 0x7f
        if interrupt == 0:
            self.prog_output.write(chr(self.mem.get_byte(self.registers[SP] + 8)))
        elif interrupt == 2:
            while True:
                addr = self.mem[self.registers[SP] + 8]
                max_len = self.mem[self.registers[SP] + 10]
                try:
                    s = self.prog_input('(max: %d; mode: %s)> ' %
                            (max_len, 'hex' if self.hex_input_mode else 'char'))
                except KeyboardInterrupt:
                    self.handle_cmds()
                    continue
                if self.hex_input_mode:
                    s = s.replace(' ', '')
                    if len(s) % 2 != 0:
                        self.display('Hex input should have an even length.')
                        continue
                    try:
                        for i in xrange(0, min(len(s) / 2, max_len)):
                            self.mem.set_byte(addr + i, int(s[i*2:(i+1)*2], 16))
                    except Exception as e:
                        self.display('Error parsing hex input: ' + e.message)
                        continue
                else:
                    s = s[:max_len]
                    for i, c in enumerate(s):
                        self.mem.set_byte(addr + i, ord(c))
                    self.mem.set_byte(addr + len(s), 0)
                break
            self.step_count = 1
        elif interrupt == 0x20: # rand
            self.registers[15] = 0 # not actually random
        elif interrupt == 0x7d: # is password correct?
            flag_location = self.mem[self.registers[SP] + 10]
            self.mem[flag_location] = 0 # always false
        elif interrupt == 0x7e:
            self.mem[15] = 0 # always false
        elif interrupt == 0x7f:
            self.door_unlocked = True
            self.display('<Door unlocked!>')
        else:
            raise Exception('NYI: Interrupt %x' % interrupt)


if __name__ == '__main__':
    import sys
    import argparse
    from tracer import Tracer
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', help='trace')
    args, rest = parser.parse_known_args()
    if args.t is not None:
        trace = Tracer(args.t).trace
    else:
        trace = None
    machine = Machine(rest[0])
    machine.debug(trace=trace)
