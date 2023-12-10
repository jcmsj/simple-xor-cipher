from xor_cipher import xor_bytes, xor_str
import unittest

class TestXOR(unittest.TestCase):
    def test_xor_bytes(self):
        # Test case 1: XOR of two empty bytes should return an empty byte string
        self.assertEqual(xor_bytes(b'', b''), b'')

        # Test case 2: XOR of two equal bytes should return a byte with all zeros
        self.assertEqual(xor_bytes(b'\x01\x02\x03', b'\x01\x02\x03'), b'\x00\x00\x00')

        # Test case 3: XOR of two different bytes should return the XOR result
        self.assertEqual(xor_bytes(b'\x01\x02\x03', b'\x04\x05\x06'), b'\x05\x07\x05')

    def test_xor_str(self):
        # Test case 1: XOR of two empty strings should return an empty byte string
        self.assertEqual(xor_str('', ''), b'')

        # Test case 2: XOR of two equal strings should return a byte with all zeros
        self.assertEqual(xor_str('abc', 'abc'), b'\x00\x00\x00')

        # Test case 3: XOR of two different strings should return the XOR result
        self.assertEqual(xor_str('abc', 'def'), b'\x05\x07\x05')

if __name__ == '__main__':
    unittest.main()
