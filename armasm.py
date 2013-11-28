"""ARM inline assembler.

This module allows creation of new functions in ARM assembler
(machine language) which can be directly called from Python.

The assembler syntax parsed by this module follows as closely as practical
the offical ARM syntax
"""

from functools import partial as _partial
import re as _re
import ctypes as _ctypes
from ctypes.util import find_library as _find_library

class AssemblerError(Exception):
    """Exception thrown when a syntax error is encountered in the assembler code."""
    pass

_registers = dict(("r%d" % _i, _i) for _i in range(16))

# register name synonyms
for _i in range(4):
    _registers["a%d" % (_i + 1)] = _registers["r%d" % _i]

for _i in range(8):
    _registers["v%d" % (_i + 1)] = _registers["r%d" % (_i + 4)]

_registers["sb"] = _registers["r9"]
_registers["ip"] = _registers["r12"]
_registers["sp"] = _registers["r13"]
_registers["lr"] = _registers["r14"]
_registers["pc"] = _registers["r15"]

_status_registers = {"cpsr" : 0, "spsr" : 1}

_conditions = [
 "eq", "ne", "cs", "cc",
 "mi", "pl", "vs", "vc",
 "hi", "ls", "ge", "lt",
 "gt", "le", "", "nv"]

class _InstructionFormat:
    format_fields = {
        "0" : 1,
        "1" : 1,
        "A" : 1,
        "B" : 1,
        "CPNum" : 4,
        "CRd" : 4,
        "CRm" : 4,
        "CRn" : 4,
        "Cond" : 4,
        "H" : 1,
        "I" : 1,
        "Imm24" : 24,
        "L" : 1,
        "N" : 1,
        "Offset" : 0,
        "Offset1" : 4,
        "Offset2" : 4,
        "Op1" : 0,
        "Op2" : 3,
        "Opcode" : 4,
        "Operand2" : 12,
        "P" : 1,
        "Rd" : 4,
        "RdHi" : 4,
        "RdLo" : 4,
        "RegisterList" : 16,
        "R" : 1,
        "Rm" : 4,
        "Rn" : 4,
        "Rs" : 4,
        "S" : 1,
        "Shift" : 3,
        "U" : 1,
        "W" : 1,
    }

    def __init__(self, format, length=32):
        self.format = format
        self.length = length
        format = format.split()[::-1]
        leftover = length - sum(self.format_fields[f] for f in format)
        bit = 0
        base = 0
        mask = 0
        offset = 0
        fields = {}
        for f in format:
            bits = self.format_fields[f]
            if bits == 0:
                bits = leftover
            if f == "1":
                base = base + (1 << offset)
            if f in "01":
                mask = mask + (1 << offset)
            else:
                fields[f] = (offset, bits)
            offset = offset + bits
        assert offset == length
        self.base = base
        self.mask = mask
        self.fields = fields
        self.signature = " ".join(sorted(fields.keys()))

    def match(self, n):
        return (n & self.mask) == self.base

    def encode(self, fields):
        if len(fields) != len(self.fields):
            missing = set(self.fields.keys()) - set(fields.keys())
            if missing:
                raise ValueError("Missing fields: " + " ".join(missing))
            spurious = set(fields.keys()) - set(self.fields.keys())
            raise ValueError("Spurious fields: " + " ".join(spurious))
        base = self.base
        for f in fields:
            offset, bits = self.fields[f]
            value = fields[f]
            mask = (1 << bits) - 1
            base = base | ((value & mask) << offset)
        return base


class _ShiftSpec:
    allowed_immediates = dict([(i, i % 32) for i in range(1, 33)])
    def __init__(self, number, allowed_immediates=None, register_allowed=True):
        self.number = number
        if allowed_immediates is not None:
            self.allowed_immediates = allowed_immediates
        self.register_allowed = register_allowed

_shifts = {
    "lsl" : _ShiftSpec(0, allowed_immediates=dict([(_i,_i) for _i in range(32)])), 
    "lsr" : _ShiftSpec(2), 
    "asr" : _ShiftSpec(4), 
    "ror" : _ShiftSpec(6, allowed_immediates=dict([(_i,_i) for _i in range(1, 32)])),
    "rrx" : _ShiftSpec(6, allowed_immediates={1:0}, register_allowed=False)
}
_shifts["asl"] = _shifts["lsl"]

_comma_split_re = _re.compile(r"(?:(?:\[[^\]]*\])|(?:{[^}]*})|(?:\$.)|[^,])+|.")

def _comma_split(str):
    return [item.strip() for item in _comma_split_re.findall(str) if item != ',']


class _OperandParser:
    pc = 0
    labels = {}
    constant_pool_offset = 0
    instruction = None

    operand2_format = _InstructionFormat("Offset Shift Rm", 12)
    library_cache = {}

    memory_re = _re.compile(r"^\[(.*)\]\s*(!?)$")
    regset_re = _re.compile(r"^{(.*)}$")

    special_chars = {"space" : ord(' '), "newline" : ord('\n'), "tab" : ord('\t')}

    def __init__(self, libraries):
        self.constant_pool = []
        self.constant_pool_dict = {}
        self.libraries = [self.convert_library(lib) for lib in libraries]

    def error(self, message):
        instruction = self.instruction
        full_message = "%s\nLine %d: %s" % (message, instruction.linenumber, instruction.code)
        error = AssemblerError(full_message)
        error.linenumber = instruction.linenumber
        error.code = instruction.code
        error.message = message
        raise error


    def convert_library(self, lib):
        library_cache = self.library_cache
        if isinstance(lib, str):
            if lib not in library_cache:
                library_cache[lib] = _ctypes.CDLL(_find_library(lib))
            return library_cache[lib]
        else:
            return lib

    def get_constant_pool_address(self, constant):
        if constant in self.constant_pool_dict:
            return self.constant_pool_dict[constant]
        address = self.constant_pool_offset
        self.constant_pool_offset = self.constant_pool_offset + 1
        self.constant_pool.append(constant)
        self.constant_pool_dict[constant] = address
        return address


    def lookup_symbol(self, str):
        for lib in self.libraries:
            try:
                return _ctypes.cast(getattr(lib, str), _ctypes.c_void_p).value
            except AttributeError:
                pass
        return None

    def encode_immediate(self, n, checked=True):
        r = 0
        b = n & 0xFFFFFFFF
        while r < 16:
            if b < 256:
                return (r << 8) | b
            r = r + 1
            b = ((b << 2) | (b >> 30)) & 0xFFFFFFFF  # rotate left by two bits
        if checked:
            self.error("Immediate value cannot be assembled: %d" % n)
        else:
            return None

    def encode_ldr_immediate(self, n, checked=True):
        if n >= 0 and n < (1 << 12):
            return n
        elif checked:
            self.error("Immediate offset cannot be assembled: %d" % n)
        else:
            return None


    def parse_immediate(self, str, checked=False, prefix="#"):
        if str and str[0] == prefix:
            str = str[1:].strip()
        try:
            return int(str, base=0)
        except ValueError:
            pass
        if str and str[0] == '$':
            ch = str[1:]
            if len(ch) == 1:
                return ord(ch)
            elif ch in self.special_chars:
                return self.special_chars[ch]
        result = self.lookup_symbol(str)
        if checked and result is None:
            self.error("Expected immediate value, got: %s" % str)
        else:
            return result

    def parse_memory(self, str):
        mo = self.memory_re.match(str)
        if mo is None:
            self.error("Expected memory location, got: %s" % str)
        return [s.strip() for s in _comma_split(mo.group(1))], mo.group(2)

    def parse_register(self, str, checked=False):
        reg = _registers.get(str.lower(), None)
        if reg is None and checked:
            self.error("Expected register, got: %s" % str)
        else:
            return reg

    def parse_status_register(self, str):
        reg = _status_registers.get(str.lower(), None)
        if reg is None:
            self.error("Expected CPSR or SPSR, got: %s" % str)
        else:
            return reg


    def parse_regset(self, str):
        mo = self.regset_re.match(str)
        if mo is not None:
            str = mo.group(1)
        result = set()
        for r in _comma_split(str):
            r = r.strip()
            r = r.split("-", 1)
            if len(r) == 1:
                result.add(self.parse_register(r[0].strip()))
            else:
                r1, r2 = r
                r1 = self.parse_register(r1.strip(), checked=True)
                r2 = self.parse_register(r2.strip(), checked=True)
                result.update(range(min(r1, r2), max(r1, r2) + 1))
        return result

    def parse_signed_register(self, str, checked=False):
        U = 1
        if str and str[0] == "-":
            U = 0
            str = str[1:].strip()
        return self.parse_register(str, checked), U

    def parse_shift(self, str, allow_registers=True):
        shift = str[:3]
        shift_field = str[3:].strip()
        try:
            shift_spec = _shifts[shift.lower()]
        except KeyError:
            self.error("Expected shift, got: %s" % str)

        if allow_registers and shift_spec.register_allowed:
            shift_value = self.parse_register(shift_field)
            if shift_value is not None:
                return (shift_spec.number + 1, shift_value << 1)

        shift_value = self.parse_immediate(shift_field, checked=True)
        if shift_value in shift_spec.allowed_immediates:
            return (shift_spec.number, shift_spec.allowed_immediates[shift_value])
        else:
            self.error("Shift with value of %d is not allowed" % shift_value)

        self.error("Expected shift, got: %s" % str)


    def parse_operand2(self, operands, encode_imm, allow_shift_register=True):
        if len(operands) == 0:
            return {"I":1, "Operand2": 0, "U": 1}
        elif len(operands) == 1:
            Rm, U = self.parse_signed_register(operands[0])
            if Rm is not None:
                return {"I":0, "Operand2": Rm, "U": U}
            imm = self.parse_immediate(operands[0])
            if imm is not None:
                U = 1
                encoded_imm = encode_imm(imm, checked=False)
                if encoded_imm is None:
                    U = 0
                    encoded_imm = encode_imm(-imm, checked=False)
                    if encoded_imm is None:
                        encode_imm(imm, checked=True) # cause error
                return {"I":1, "Operand2": encoded_imm, "U": U}
            self.error("Expected register or immediate, got: %s" % operands[0])
        elif len(operands) == 2:
            Rm, U = self.parse_signed_register(operands[0], checked=True)
            t, c = self.parse_shift(operands[1], allow_shift_register)
            operand2 = self.operand2_format.encode({"Shift" : t, "Offset" : c, "Rm" : Rm})
            return {"I":0, "Operand2": operand2, "U": U}


    def parse_dpi_operand2(self, operands):
        fields = self.parse_operand2(operands, self.encode_immediate)
        if fields["U"] == 0:
            self.error("Minus sign (-) not allowed in this instruction")
        del fields["U"]
        return fields

    def parse_load_store(self, operands):
        W = 0
        if len(operands) == 1:
            pre_indexed = 1
            operands, bang = self.parse_memory(operands[0])
            if bang:
                W = 1
        else:
            pre_indexed = 0
            operands0, bang = self.parse_memory(operands[0])
            if len(operands0) != 1:
                self.error("Expected [register], got: %s" % operands[0])
            if bang:
                self.error("In post-indexed _mode, ! is not allowed")
            operands = operands0 + operands[1:]
        fields = self.parse_operand2(operands[1:], self.encode_ldr_immediate, allow_shift_register=False)
        fields["P"] = pre_indexed
        fields["W"] = W
        fields["I"] = 1 - fields["I"]
        fields["Rn"] = self.parse_register(operands[0], checked=True)
        return fields


_instructions = {}

class _Instruction:
    code = ""
    label = ""
    opcode = ""
    operands = []
    linenumber = 0
    pc = 0

    def __init__(self, code):
        self.code = code
        code = code.split(";", 1)[0]
        code = code.split(":", 1)
        if len(code) == 1:
            code = code[0]
        else:
            self.label = code[0].strip()
            code = code[1]
        code = code.strip()
        if code:
            code = code.split(None, 1)
            self.opcode = code[0].strip().lower()
            if len(code) > 1:
                self.operands = _comma_split(code[1])

    def parse(self, parser):
        parser.instruction = self
        parser.pc = self.pc
        if self.opcode not in _instructions:
            parser.error("Invalid opcode: %s" % self.opcode)
        return _instructions[self.opcode](parser, self.operands)


_dpi_format = _InstructionFormat("Cond 0 0 I Opcode S Rn Rd Operand2")
_branch_format = _InstructionFormat("Cond 1 0 1 L Offset")
_bx_format = _InstructionFormat("Cond 0 0 0 1 0 0 1 0 1 1 1 1 1 1 1 1 1 1 1 1 0 0 L 1 Rm")
_load_store_format = _InstructionFormat("Cond 0 1 I P U B W L Rn Rd Operand2")
_load_store_multi_format = _InstructionFormat("Cond 1 0 0 P U S W L Rn RegisterList")
_mul_format = _InstructionFormat("Cond 0 0 0 0 0 0 0 S Rd 0 0 0 0 Rs 1 0 0 1 Rm")
_mla_format = _InstructionFormat("Cond 0 0 0 0 0 0 1 S Rd Rn Rs 1 0 0 1 Rm")
_clz_format = _InstructionFormat("Cond 0 0 0 1 0 1 1 0 1 1 1 1 Rd 1 1 1 1 0 0 0 1 Rm")
_mrs_format = _InstructionFormat("Cond 0 0 0 1 0 R 0 0 1 1 1 1 Rd 0 0 0 0 0 0 0 0 0 0 0 0")
_swi_format = _InstructionFormat("Cond 1 1 1 1 Imm24")

def _parse_dpi(opcode, condition, s, parser, operands):
    if len(operands) not in (3, 4):
        parser.error("Expected 3 or 4 arguments, got %d" % len(operands))
    fields = parser.parse_dpi_operand2(operands[2:])
    Rd = parser.parse_register(operands[0], checked=True)
    Rn = parser.parse_register(operands[1], checked=True)
    fields["Rd"] = Rd
    fields["Rn"] = Rn
    fields["Opcode"] = opcode
    fields["Cond"] = condition
    fields["S"] = s
    return _dpi_format.encode(fields)

def _parse_move(opcode, condition, s, parser, operands):
    if len(operands) not in (2, 3):
        parser.error("Expected 2 or 3 arguments, got %d" % len(operands))
    fields = parser.parse_dpi_operand2(operands[1:])
    Rd = parser.parse_register(operands[0], checked=True)
    fields["Rd"] = Rd
    fields["Rn"] = 0 
    fields["Opcode"] = opcode
    fields["Cond"] = condition
    fields["S"] = s
    return _dpi_format.encode(fields)

def _parse_cond(opcode, condition, s, parser, operands):
    if len(operands) not in (2, 3):
        parser.error("Expected 2 or 3 arguments, got %d" % len(operands))
    fields = parser.parse_dpi_operand2(operands[1:])
    Rn = parser.parse_register(operands[0], checked=True)
    fields["Rd"] = 0
    fields["Rn"] = Rn
    fields["Opcode"] = opcode
    fields["Cond"] = condition
    fields["S"] = s
    return _dpi_format.encode(fields)

def _parse_branch(condition, link, parser, operands):
    if len(operands) != 1:
        parser.error("Expected 1 argument, got %d" % len(operands))
    label = operands[0]
    if label not in parser.labels:
        parser.error("Undefined label: %s" % label)
    target = parser.labels[label]
    offset = target - parser.pc - 2
    return _branch_format.encode({"L" : link, "Cond" : condition, "Offset" : offset})

def _parse_bx(condition, link, parser, operands):
    if len(operands) != 1:
        parser.error("Expected 1 argument, got %d" % len(operands))
    Rm = parser.parse_register(operands[0], checked=True)
    return _bx_format.encode({"L" : link, "Cond" : condition, "Rm" : Rm})

def _parse_load_store(condition, load, B, parser, operands):
    if len(operands) not in (2, 3, 4):
        parser.error("Expected 2, 3 or 4 arguments, got %d" % len(operands))
    Rd = parser.parse_register(operands[0], checked=True)
    fields = parser.parse_load_store(operands[1:])
    fields["Rd"] = Rd
    fields["L"] = load
    fields["B"] = B
    fields["Cond"] = condition
    return _load_store_format.encode(fields)

def _parse_load_store_multi(condition, load, before, increment, parser, operands):
    if len(operands) != 2:
        parser.error("Expected 2 arguments, got %d" % len(operands))
    W = 0
    S = 0
    operand0 = operands[0]
    if operand0 and operand0[-1] == '!':
        W = 1
        operand0 = operand0[:-1].strip()
    operand1 = operands[1]
    if operand1 and operand1[-1] == '^':
        S = 1
        operand1 = operand1[:-1].strip()
    Rn = parser.parse_register(operand0, checked=True)
    RegisterList = sum(1<<r for r in parser.parse_regset(operand1))
    fields = {"P": before, "U": increment, "Cond" : condition, "L" : load, "W" : W, "S" : S, "Rn" : Rn, "RegisterList" : RegisterList}
    return _load_store_multi_format.encode(fields)


def _parse_push_pop(condition, load, parser, operands):
    if len(operands) != 1:
        parser.error("Expected 1 argument, got %d" % len(operands))
    Rn = 13 # stack pointer
    before = 1 - load
    increment = load
    RegisterList = sum(1<<r for r in parser.parse_regset(operands[0]))
    fields = {"P": before, "U": increment, "Cond" : condition, "L" : load, "W" : 1, "S" : 0, "Rn" : Rn, "RegisterList" : RegisterList}
    return _load_store_multi_format.encode(fields)

def _parse_mul(condition, S, parser, operands):
    if len(operands) != 3:
        parser.error("Expected 3 arguments, got %d" % len(operands))
    Rd = parser.parse_register(operands[0], checked=True)
    Rm = parser.parse_register(operands[1], checked=True)
    Rs = parser.parse_register(operands[2], checked=True)
    if Rd == Rm:
        Rm, Rs = Rs, Rm
    return _mul_format.encode({"Rd" : Rd, "Rm" : Rm, "Rs" : Rs, "Cond" : condition, "S" : S})

def _parse_mla(condition, S, parser, operands):
    if len(operands) != 4:
        parser.error("Expected 4 arguments, got %d" % len(operands))
    Rd = parser.parse_register(operands[0], checked=True)
    Rm = parser.parse_register(operands[1], checked=True)
    Rs = parser.parse_register(operands[2], checked=True)
    Rn = parser.parse_register(operands[3], checked=True)
    if Rd == Rm:
        Rm, Rs = Rs, Rm
    return _mla_format.encode({"Rd" : Rd, "Rm" : Rm, "Rs" : Rs, "Rn" : Rn, "Cond" : condition, "S" : S})

def _parse_clz(condition, parser, operands):
    if len(operands) != 2:
        parser.error("Expected 2 arguments, got %d" % len(operands))
    Rd = parser.parse_register(operands[0], checked=True)
    Rm = parser.parse_register(operands[1], checked=True)
    return _clz_format.encode({"Rd" : Rd, "Rm" : Rm, "Cond" : condition})

def _parse_mrs(condition, parser, operands):
    if len(operands) != 2:
        parser.error("Expected 2 arguments, got %d" % len(operands))
    Rd = parser.parse_register(operands[0], checked=True)
    R = parser.parse_status_register(operands[1])
    return _mrs_format.encode({"Rd" : Rd, "R" : R, "Cond" : condition})

def _parse_swi(condition, parser, operands):
    if len(operands) != 1:
        parser.error("Expected 1 argument, got %d" % len(operands))
    imm24 = parser.parse_immediate(operands[0], checked=True)
    limit = 1<<24
    if imm24 < 0 or imm24 >= limit:
        parser.error("Immediate value should be between 0 and %d, got: %d" % (limit - 1, imm24))
    return _swi_format.encode({"Cond": condition, "Imm24" : imm24})


# Install data-processing instructions
_dpi_instructions = [("and", 0), ("eor", 1), ("sub", 2), ("rsb", 3), ("add", 4),
  ("adc", 5), ("sbc", 6), ("rsc", 7), ("orr", 12), ("bic", 14)]

for (_name, _opcode) in _dpi_instructions:
    for _i in range(len(_conditions)):
        _fullname = _name + _conditions[_i] 
        _instructions[_fullname] = _partial(_parse_dpi, _opcode, _i, 0)
        _instructions[_fullname + "s"] = _partial(_parse_dpi, _opcode, _i, 1)

# Install move instructions
_move_instructions = [("mov", 13), ("mvn", 15)]

for (_name, _opcode) in _move_instructions:
    for _i in range(len(_conditions)):
        _fullname = _name + _conditions[_i] 
        _instructions[_fullname] = _partial(_parse_move, _opcode, _i, 0)
        _instructions[_fullname + "s"] = _partial(_parse_move, _opcode, _i, 1)

# Install test instructions
_cond_instructions = [("tst", 8), ("teq", 9), ("cmp", 10), ("cmn", 11)]
for (_name, _opcode) in _cond_instructions:
    for _i in range(len(_conditions)):
        _fullname = _name + _conditions[_i] 
        _instructions[_fullname] = _partial(_parse_cond, _opcode, _i, 1)

# Install branch instructions
for _i in range(len(_conditions)):
    _fullname = "b" + _conditions[_i] 
    _instructions[_fullname] = _partial(_parse_branch, _i, 0)
    _fullname = "bl" + _conditions[_i] 
    _instructions[_fullname] = _partial(_parse_branch, _i, 1)
    _fullname = "bx" + _conditions[_i] 
    _instructions[_fullname] = _partial(_parse_bx, _i, 0)
    _fullname = "blx" + _conditions[_i] 
    _instructions[_fullname] = _partial(_parse_bx, _i, 1)

# Install load/store instructions
for _i in range(len(_conditions)):
    _fullname = "ldr" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_load_store, _i, 1, 0)
    _fullname = "str" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_load_store, _i, 0, 0)
    _fullname = "ldr" + _conditions[_i] + "b"
    _instructions[_fullname] = _partial(_parse_load_store, _i, 1, 1)
    _fullname = "str" + _conditions[_i] + "b"
    _instructions[_fullname] = _partial(_parse_load_store, _i, 0, 1)

# Install load/store instructions
for _i in range(len(_conditions)):
    _fullname = "ldr" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_load_store, _i, 1, 0)
    _fullname = "str" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_load_store, _i, 0, 0)
    _fullname = "ldr" + _conditions[_i] + "b"
    _instructions[_fullname] = _partial(_parse_load_store, _i, 1, 1)
    _fullname = "str" + _conditions[_i] + "b"
    _instructions[_fullname] = _partial(_parse_load_store, _i, 0, 1)

# Install load/store multi instructions
for _i in range(len(_conditions)):
    _fullname = "push" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_push_pop, _i, 0)
    _fullname = "pop" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_push_pop, _i, 1)

    for _increment in range(2):
        for _before in range(2):
            _mode = "di"[_increment] + "ab"[_before]
            _fullname = "ldm" + _conditions[_i] + _mode
            _instructions[_fullname] = _partial(_parse_load_store_multi, _i, 1, _before, _increment)
            _fullname = "stm" + _conditions[_i] + _mode
            _instructions[_fullname] = _partial(_parse_load_store_multi, _i, 0, _before, _increment)

# Install MULtiply instructions
for _i in range(len(_conditions)):
    _fullname = "mul" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_mul, _i, 0)
    _fullname = _fullname + "s"
    _instructions[_fullname] = _partial(_parse_mul, _i, 1)

    _fullname = "mla" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_mla, _i, 0)
    _fullname = _fullname + "s"
    _instructions[_fullname] = _partial(_parse_mla, _i, 1)

# Install Count Leading Zero instructions
for _i in range(len(_conditions)):
    _fullname = "clz" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_clz, _i)

# Install Move Register from Status instructions
for _i in range(len(_conditions)):
    _fullname = "mrs" + _conditions[_i]
    _instructions[_fullname] = _partial(_parse_mrs, _i)

# Install SoftWare Interrupt instructions
for _i in range(len(_conditions)):
    for _name in ("swi", "svc"):
        _fullname = _name + _conditions[_i]
        _instructions[_fullname] = _partial(_parse_swi, _i)


# support for LDR pseudo-instruction
def _wrap_ldr(ldr, mov, mvn, parser, operands):
    if len(operands) == 2:
        imm = parser.parse_immediate(operands[1], checked=False, prefix="=")
        if imm is not None:
            parser.parse_register(operands[0], checked=True)
            if parser.encode_immediate(imm, checked=False) is not None:
                operands = [operands[0], "#%d" % imm]
                return mov(parser, operands)
            elif parser.encode_immediate(~imm, checked=False) is not None:
                operands = [operands[0], "#%d" % ~imm]
                return mvn(parser, operands)
            else:
                address = parser.get_constant_pool_address(imm)
                address = 4 * (address - parser.pc - 2)
                return ldr(parser, [operands[0], "[pc, #%d]" % address])
    return ldr(parser, operands)

for _cond in _conditions:
    _name = "ldr" + _cond
    _instructions[_name] = _partial(_wrap_ldr, _instructions[_name], 
           _instructions["mov" + _cond], _instructions["mvn" + _cond])


def _make_executable_array(opcodes):
    import mmap
    n = len(opcodes)
    m = mmap.mmap(-1, 4*n,  prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
    result = (_ctypes.c_uint32 * n).from_buffer(m)
    for i in range(n):
        result[i] = opcodes[i]
    return result

_type_flags = {
    "b" : _ctypes.c_int8,
    "B" : _ctypes.c_uint8,
    "h" : _ctypes.c_int16,
    "H" : _ctypes.c_uint16,
    "i" : _ctypes.c_int32,
    "I" : _ctypes.c_uint32,
    "l" : _ctypes.c_int64,
    "L" : _ctypes.c_uint64,

    "str" : _ctypes.c_char_p,
    "ch" : _ctypes.c_char,
    "bool" : _ctypes.c_bool,
    "p" : _ctypes.c_void_p,
    "" : None
}

def prototype(proto):
    if not isinstance(proto, str):
        return proto
    args, result = proto.split("->")
    result = _type_flags[result.strip()]
    args = [_type_flags[a.strip()] for a in args.split()]
    return _ctypes.CFUNCTYPE(result, *args)

def _make_function(exec_array, proto):
    proto = prototype(proto)
    f = proto(_ctypes.addressof(exec_array))
    f.__armasm_code__ = exec_array
    return f


def asm(prototype, code, libraries=()):
    """Convert ARM assembler into a callable object.

    Required arguments:
    prototype -- either a `ctypes.CFUNCTYPE' object or a string acceptable to `armasm.prototype'
    code      -- the actual assembler code, as a string

    Optional arguments:
    libraries -- a sequence of either `ctypes.CDLL' objects or strings acceptable to `ctypes.util.find_library'

    Examples:
      asm("i i -> i", "mul r0, r1, r0")   -- returns a callable object which takes two integers and returns their product

    """

    linenumber = 0
    pc = 0
    _instructions = []
    labels = {}
    for line in code.split("\n"):
        linenumber = linenumber + 1
        instruction = _Instruction(line)
        instruction.linenumber = linenumber
        instruction.pc = pc
        if instruction.label:
            labels[instruction.label] = pc
        if instruction.opcode:
            pc = pc + 1
        _instructions.append(instruction)

    opcodes = []
    parser = _OperandParser(libraries)
    parser.labels = labels
    parser.constant_pool_offset = pc + 1

    for instruction in _instructions:
        if instruction.opcode:
            v = instruction.parse(parser)
            opcodes.append(v)
    opcodes.append(0xe12fff1e) # bx lr
    opcodes.extend(parser.constant_pool)
    result = _make_executable_array(opcodes)
    return _make_function(result, prototype)


def dis(asm_function):
    """Disassemble assembled function object.

    Given a callable object created with `armasm.asm', this function
    prints its disassembled listing.

    This functions uses the external `objdump' tool.
    It first tries the ARM-specific `arm-linux-gnueabihf-objdump', then tries
    the generic `objdump'.

    If neither exist or their invocation produces an error, this function will error out.
    """
    import tempfile
    import os
    import subprocess
    f = tempfile.NamedTemporaryFile(delete=False)

    try:
        executable = subprocess.check_output(("which", "arm-linux-gnueabihf-objdump")).decode().strip()
    except subprocess.CalledProcessError:
        executable = "objdump"
    try:
        f.write(bytearray(asm_function.__armasm_code__))
        f.close()
        output = subprocess.check_output((executable, "-D", f.name, "-m", "arm", "-b", "binary")).decode()
    finally:
        os.unlink(f.name)
    # try to skip useless headers
    start = "   0:"
    loc = output.find(start)
    if loc >= 0:
        output = output[loc:]
    print(output)
