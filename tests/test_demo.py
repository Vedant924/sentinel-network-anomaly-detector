import unittest


class TestDemoFile(unittest.TestCase):
    def test_demo_module_imports(self):
        from src import demo

        self.assertTrue(callable(demo.main))


if __name__ == "__main__":
    unittest.main()