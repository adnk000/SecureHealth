import hashlib
import unittest

from security import can_user_read, hash_password, mask_name, verify_password


class SecurityTests(unittest.TestCase):
    def test_new_password_hash_is_not_plaintext(self):
        stored = hash_password("correct-horse-battery")
        self.assertNotEqual(stored, "correct-horse-battery")
        self.assertTrue(stored.startswith("scrypt:"))

    def test_modern_password_verification(self):
        stored = hash_password("correct-horse-battery")
        valid, needs_upgrade = verify_password(stored, "correct-horse-battery")
        self.assertTrue(valid)
        self.assertFalse(needs_upgrade)

    def test_legacy_sha256_hash_is_accepted_for_migration(self):
        password = "legacy-demo-password"
        old_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        valid, needs_upgrade = verify_password(old_hash, password)
        self.assertTrue(valid)
        self.assertTrue(needs_upgrade)

    def test_wrong_password_is_rejected(self):
        stored = hash_password("correct-password")
        valid, _ = verify_password(stored, "wrong-password")
        self.assertFalse(valid)

    def test_bell_lapadula_no_read_up(self):
        self.assertTrue(can_user_read(1, 1))
        self.assertFalse(can_user_read(1, 2))
        self.assertFalse(can_user_read(1, 3))
        self.assertTrue(can_user_read(2, 1))
        self.assertTrue(can_user_read(2, 2))
        self.assertFalse(can_user_read(2, 3))
        self.assertTrue(can_user_read(3, 3))

    def test_invalid_clearance_is_denied(self):
        self.assertFalse(can_user_read(None, 1))
        self.assertFalse(can_user_read("invalid", 1))

    def test_patient_name_masking(self):
        self.assertEqual(mask_name("Adnan Khan"), "A**** K****")
        self.assertEqual(mask_name(""), "")


if __name__ == "__main__":
    unittest.main()
