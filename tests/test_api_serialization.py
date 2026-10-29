"""Exercise the API's pure serializer without loading GPU/model dependencies."""

import ast
from datetime import datetime
from pathlib import Path
import unittest


def load_serializer():
    source = Path(__file__).resolve().parents[1] / "src/api/server.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name == "clean_datetime")
    namespace = {"datetime": datetime}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    return namespace["clean_datetime"]


class ApiSerializationTests(unittest.TestCase):
    def setUp(self):
        self.clean = load_serializer()

    def test_preserves_json_scalar_types_and_repeated_values(self):
        source = {"success": True, "again": True, "count": 1, "score": 5.0,
                  "missing": None, "other_missing": None, "text": "ok"}
        result = self.clean(source)
        self.assertEqual(result, source)
        for key, value in source.items():
            self.assertIs(type(result[key]), type(value))

    def test_shared_non_cyclic_containers_are_serialized_each_time(self):
        shared = {"score": 3}
        source = [shared, shared]
        self.assertEqual(self.clean(source), [{"score": 3}, {"score": 3}])

    def test_actual_container_cycle_is_stopped(self):
        source = {"score": 3}
        source["self"] = source
        self.assertEqual(self.clean(source), {"score": 3, "self": "[Circular Reference: dict]"})

    def test_datetime_is_iso_string_and_tuple_becomes_json_array(self):
        moment = datetime(2026, 10, 29, 12, 30)
        self.assertEqual(self.clean((moment, False)), ["2026-10-29T12:30:00", False])


if __name__ == "__main__":
    unittest.main()
