import unittest
from scanner import RULES, mask_line, risk_level

class ScannerTests(unittest.TestCase):
    def test_email_pattern(self):
        self.assertIsNotNone(RULES["Email address"][0].search("a@example.com"))

    def test_masks_email(self):
        result = mask_line("Contact a@example.com")
        self.assertNotIn("a@example.com", result)
        self.assertIn("[EMAIL REDACTED]", result)

    def test_masks_password(self):
        result = mask_line("password=DemoPass123!")
        self.assertNotIn("DemoPass123!", result)
        self.assertIn("[SECRET REDACTED]", result)

    def test_risk_levels(self):
        self.assertEqual(risk_level(0), "NO FINDINGS")
        self.assertEqual(risk_level(8), "MEDIUM")
        self.assertEqual(risk_level(40), "CRITICAL")

if __name__ == "__main__":
    unittest.main()
