"""Basic checks that V5 remains wired into the Streamlit entry point."""
import ast
import pathlib
import unittest

class DashboardTests(unittest.TestCase):
    def test_app_syntax_and_v5_entry(self):
        source = pathlib.Path("app.py").read_text(encoding="utf-8")
        ast.parse(source, filename="app.py")
        self.assertIn("Version 5 — context-aware detection", source)
        self.assertIn("extract_unlabeled_windows(uploaded.getvalue())", source)
        self.assertIn('if imported:', source)
        self.assertIn('st.stop()', source)
        self.assertIn('v5_report["held_out"]', source)

if __name__ == "__main__":
    unittest.main()
