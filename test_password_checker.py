import unittest
from password_checker import (
    check_password,
    contains_dictionary_pattern,
    has_repeated_pattern,
    has_sequential_pattern,
)


class PasswordCheckerTests(unittest.TestCase):

    def test_common_password_detected(self):
        self.assertTrue(contains_dictionary_pattern("password123"))

    def test_sequence_detected(self):
        self.assertTrue(has_sequential_pattern("Abcd1234!"))

    def test_repetition_detected(self):
        self.assertTrue(has_repeated_pattern("AAAabc!"))

    def test_weak_password(self):
        result = check_password("123456")
        self.assertEqual(result.label, "Very Weak")
        self.assertLess(result.score, 40)

    def test_strong_password(self):
        result = check_password("R7!mQ2#vL9@xT4$z")
        self.assertGreaterEqual(result.score, 80)

    def test_recommendations_exist(self):
        result = check_password("hello")
        self.assertGreater(len(result.recommendations), 0)


if __name__ == "__main__":
    unittest.main()
