import unittest

from my_library import TargetValidator


class TargetValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = TargetValidator(default_scheme="https")

    def test_validate_domain_without_scheme(self) -> None:
        result = self.validator.validate("example.com/login")
        self.assertTrue(result.valid)
        self.assertEqual(result.normalized_target, "https://example.com/login")
        self.assertEqual(result.host, "example.com")
        self.assertEqual(result.scheme, "https")

    def test_validate_ip_with_port(self) -> None:
        result = self.validator.validate("http://127.0.0.1:8080/admin")
        self.assertTrue(result.valid)
        self.assertEqual(result.host, "127.0.0.1")
        self.assertEqual(result.port, 8080)
        self.assertEqual(result.normalized_target, "http://127.0.0.1:8080/admin")

    def test_invalid_target(self) -> None:
        result = self.validator.validate("%%%")
        self.assertFalse(result.valid)
        self.assertTrue(result.errors)

    def test_parse_ports_with_ranges(self) -> None:
        ports = self.validator.parse_ports("22,80,8000-8002")
        self.assertEqual(ports, [22, 80, 8000, 8001, 8002])

    def test_parse_ports_rejects_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            self.validator.parse_ports("0,80")


if __name__ == "__main__":
    unittest.main()

