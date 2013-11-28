import unittest
from armasm import asm, dis

code = """
mov r1, 0
loop:
ldrb r2, [a1], 1
cmp r2, 0
beq done
add r1, r1, 1
b loop

done:
mov a1, r1
"""


class TestAsm(unittest.TestCase):

    def test_asm(self):
        f = asm("str -> i", code)
        s = b"Hello, world"
        n = f(s)
        self.assertEqual(n, len(s))


if __name__ == "__main__":
    unittest.main()
