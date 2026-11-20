"""Regression cases for the 16 KiB ELF gate, using minimal in-memory ELF files."""
import struct
import unittest

from audit_bridge import inspect_elf


def elf(machine=183, offset=0, vaddr=0, alignment=16384):
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 3, machine)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, offset, vaddr, 0, 1, 1, alignment)
    return data


class ElfGateTest(unittest.TestCase):
    def test_both_machines_and_nonzero_congruent_offset(self):
        for abi, machine in (("arm64-v8a", 183), ("x86_64", 62)):
            self.assertEqual(16384, inspect_elf(elf(machine, 64, 16448), abi)[0]["alignment"])

    def test_rejects_four_kib_alignment(self):
        with self.assertRaisesRegex(ValueError, "16 KiB"):
            inspect_elf(elf(alignment=4096), "arm64-v8a")

    def test_rejects_incongruent_virtual_address(self):
        with self.assertRaisesRegex(ValueError, "16 KiB"):
            inspect_elf(elf(vaddr=4096), "arm64-v8a")

    def test_rejects_wrong_architecture(self):
        with self.assertRaisesRegex(ValueError, "machine"):
            inspect_elf(elf(machine=62), "arm64-v8a")

    def test_rejects_truncated_program_headers(self):
        with self.assertRaisesRegex(ValueError, "bounds"):
            inspect_elf(elf()[:-1], "arm64-v8a")

    def test_rejects_load_outside_file(self):
        with self.assertRaisesRegex(ValueError, "bounds"):
            inspect_elf(elf(offset=16384, vaddr=16384), "arm64-v8a")

    def test_rejects_no_load_segments(self):
        data = elf()
        struct.pack_into("<I", data, 64, 0)
        with self.assertRaisesRegex(ValueError, "no LOAD"):
            inspect_elf(data, "arm64-v8a")


if __name__ == "__main__":
    unittest.main()
