import json
import unittest

from logsanitizer import (
    Action,
    DupDict,
    FieldSemantics,
    PathRule,
    Sanitizer,
    SanitizerConfig,
    Semantic,
    sanitize_json,
)
from logsanitizer.dupdict import dumps, loads


def make_config(**overrides):
    base = dict(
        path_rules=[
            PathRule("**.password", Action.REDACT, reason="credential"),
            PathRule("**.token", Action.REDACT),
            PathRule("users[*].phone", Action.PARTIAL, keep_prefix=3, keep_suffix=4),
            PathRule("order.id", Action.KEEP),
            PathRule("message", Action.SCAN),
        ],
        field_semantics=FieldSemantics(
            {
                "secret": Semantic.CREDENTIAL,
                "session": Semantic.TOKEN,
                "email": Semantic.PII,
                "user_id": Semantic.CORRELATION,
                "note": Semantic.FREE_TEXT,
            }
        ),
        correlation_key=b"test-key",
        audit_salt="test-salt",
    )
    base.update(overrides)
    return SanitizerConfig(**base)


class NestedArrayTest(unittest.TestCase):
    def test_nested_arrays_and_objects(self):
        log = {
            "users": [
                {"name": "alice", "password": "p1", "phone": "13812345678"},
                {"name": "bob", "password": "p2", "phone": "13900001111"},
            ],
            "meta": {"deep": [{"token": "abc123"}]},
        }
        out, report = Sanitizer(make_config()).sanitize(log)
        self.assertEqual(out["users"][0]["password"], "[REDACTED]")
        self.assertEqual(out["users"][1]["password"], "[REDACTED]")
        self.assertEqual(out["meta"]["deep"][0]["token"], "[REDACTED]")
        self.assertEqual(out["users"][0]["phone"], "138****5678")
        self.assertEqual(out["users"][0]["name"], "alice")
        self.assertEqual(report.action_counts[Action.REDACT.name], 3)
        self.assertEqual(report.action_counts[Action.PARTIAL.name], 2)

    def test_json_string_round_trip(self):
        text = json.dumps(
            {"users": [{"password": "p", "phone": "13812345678"}], "ok": 1}
        )
        sanitized_text, report = sanitize_json(text, make_config())
        parsed = json.loads(sanitized_text)
        self.assertNotIn("p\"", sanitized_text)
        self.assertEqual(parsed["users"][0]["password"], "[REDACTED]")
        self.assertEqual(parsed["ok"], 1)


class SameNameDifferentSemanticsTest(unittest.TestCase):
    def test_path_rule_overrides_same_name(self):
        log = {
            "order": {"id": "order-42", "note": "call 13812345678"},
            "user": {"id": "u-9", "user_id": "u-9"},
        }
        config = make_config(
            path_rules=make_config().path_rules
            + [PathRule("user.id", Action.HASH)]
        )
        out, report = Sanitizer(config).sanitize(log)
        self.assertEqual(out["order"]["id"], "order-42")
        self.assertTrue(out["user"]["id"].startswith("corr:"))
        self.assertEqual(out["user"]["user_id"], out["user"]["id"])

    def test_semantic_fallback_by_field_name(self):
        log = {"outer": {"inner": {"secret": "s3cr3t", "email": "a@b.com"}}}
        out, _ = Sanitizer(make_config()).sanitize(log)
        self.assertEqual(out["outer"]["inner"]["secret"], "[REDACTED]")
        self.assertEqual(out["outer"]["inner"]["email"], "[REDACTED]")


class CorrelationTest(unittest.TestCase):
    def test_correlation_field_pseudonymized_not_cleared(self):
        log1 = {"user_id": "u-100", "event": "login"}
        log2 = {"user_id": "u-100", "event": "purchase"}
        sanitizer = Sanitizer(make_config())
        out1, _ = sanitizer.sanitize(log1)
        out2, _ = sanitizer.sanitize(log2)
        self.assertNotEqual(out1["user_id"], "u-100")
        self.assertEqual(out1["user_id"], out2["user_id"])
        self.assertEqual(out1["event"], "login")

    def test_different_ids_get_different_pseudonyms(self):
        sanitizer = Sanitizer(make_config())
        out1, _ = sanitizer.sanitize({"user_id": "u-1"})
        out2, _ = sanitizer.sanitize({"user_id": "u-2"})
        self.assertNotEqual(out1["user_id"], out2["user_id"])


class FreeTextTest(unittest.TestCase):
    def test_free_text_entities_redacted(self):
        log = {"note": "contact me at alice@example.com or 13812345678"}
        out, report = Sanitizer(make_config()).sanitize(log)
        self.assertNotIn("alice@example.com", out["note"])
        self.assertNotIn("13812345678", out["note"])
        self.assertTrue(report.manual_review)

    def test_combined_info_requires_manual_review(self):
        log = {"note": "id 110101199003077777, card 6222020200112233445"}
        _, report = Sanitizer(make_config()).sanitize(log)
        reasons = report.manual_review[0]["reasons"][0]
        self.assertIn("combined_info", reasons)

    def test_single_entity_no_manual_review(self):
        log = {"note": "mail alice@example.com"}
        _, report = Sanitizer(make_config()).sanitize(log)
        self.assertEqual(report.manual_review, [])

    def test_credential_assignment_in_text(self):
        log = {"note": "debug: password=Hunter2! failed"}
        out, _ = Sanitizer(make_config()).sanitize(log)
        self.assertNotIn("Hunter2!", out["note"])
        self.assertIn("password=[REDACTED]", out["note"])

    def test_sensitive_context_without_pattern_flagged(self):
        log = {"note": "用户提供了身份证信息但格式无法识别"}
        _, report = Sanitizer(make_config()).sanitize(log)
        self.assertTrue(report.manual_review)
        self.assertIn(
            "sensitive_context_without_pattern",
            report.manual_review[0]["reasons"],
        )


class TypePreservationTest(unittest.TestCase):
    def test_redaction_preserves_types(self):
        config = make_config(
            path_rules=[
                PathRule("a", Action.REDACT),
                PathRule("b", Action.REDACT),
                PathRule("c", Action.REDACT),
                PathRule("d", Action.REDACT),
                PathRule("e", Action.REDACT),
                PathRule("f", Action.REDACT),
            ]
        )
        log = {"a": 1, "b": 1.5, "c": True, "d": None, "e": [1], "f": {"x": 1}}
        out, _ = Sanitizer(config).sanitize(log)
        self.assertEqual(out, {"a": 0, "b": 0.0, "c": False, "d": None, "e": [], "f": {}})
        self.assertIs(type(out["a"]), int)
        self.assertIs(type(out["b"]), float)
        self.assertIs(type(out["c"]), bool)


class DuplicateKeyTest(unittest.TestCase):
    def test_all_duplicate_values_sanitized(self):
        text = '{"password": "first-secret", "password": "second-secret", "ok": 1}'
        sanitized_text, report = sanitize_json(text, make_config())
        self.assertNotIn("first-secret", sanitized_text)
        self.assertNotIn("second-secret", sanitized_text)
        self.assertEqual(sanitized_text.count("[REDACTED]"), 2)
        self.assertEqual(report.action_counts[Action.REDACT.name], 2)

    def test_dupdict_round_trip(self):
        obj = loads('{"k": 1, "k": 2}')
        self.assertIsInstance(obj, DupDict)
        self.assertEqual(dumps(obj), '{"k":1,"k":2}')


class CircularTest(unittest.TestCase):
    def test_circular_object_does_not_hang(self):
        log = {"a": 1}
        log["self"] = log
        out, report = Sanitizer(make_config()).sanitize(log)
        self.assertEqual(out["self"], "[CircularReference]")
        self.assertEqual(report.circular_references, ["self"])

    def test_shared_reference_is_not_circular(self):
        shared = {"x": 1}
        log = {"p": shared, "q": shared}
        out, report = Sanitizer(make_config()).sanitize(log)
        self.assertEqual(out["p"], {"x": 1})
        self.assertEqual(out["q"], {"x": 1})
        self.assertEqual(report.circular_references, [])


class OversizedTest(unittest.TestCase):
    def test_long_string_truncated(self):
        config = make_config(max_string_length=10)
        out, report = Sanitizer(config).sanitize({"big": "x" * 100})
        self.assertEqual(out["big"], "x" * 10 + "...[truncated]")
        self.assertEqual(report.truncations[0]["reason"], "string_too_long")

    def test_deep_nesting_truncated(self):
        config = make_config(max_depth=3)
        log = {"l1": {"l2": {"l3": {"l4": {"l5": 1}}}}}
        out, report = Sanitizer(config).sanitize(log)
        self.assertEqual(out["l1"]["l2"]["l3"]["l4"], "[Truncated:max_depth]")
        self.assertTrue(report.truncations)

    def test_node_budget(self):
        config = make_config(max_nodes=5)
        log = {"arr": list(range(100))}
        out, report = Sanitizer(config).sanitize(log)
        self.assertIn("[Truncated:node_budget]", json.dumps(out))
        self.assertTrue(report.truncations)


class RuleConflictTest(unittest.TestCase):
    def test_stricter_action_wins_and_is_reported(self):
        config = make_config(
            path_rules=[
                PathRule("a.b", Action.KEEP),
                PathRule("a.b", Action.REDACT),
            ]
        )
        out, report = Sanitizer(config).sanitize({"a": {"b": "secret"}})
        self.assertEqual(out["a"]["b"], "[REDACTED]")
        self.assertEqual(len(report.conflicts), 1)
        self.assertEqual(report.conflicts[0]["chosen"], "REDACT")

    def test_more_specific_path_wins(self):
        config = make_config(
            path_rules=[
                PathRule("**.token", Action.REDACT),
                PathRule("public.token", Action.KEEP),
            ]
        )
        log = {"public": {"token": "visible"}, "private": {"token": "hidden"}}
        out, _ = Sanitizer(config).sanitize(log)
        self.assertEqual(out["public"]["token"], "visible")
        self.assertEqual(out["private"]["token"], "[REDACTED]")

    def test_semantic_beats_weaker_path_rule(self):
        config = make_config(path_rules=[PathRule("data", Action.KEEP)])
        out, report = Sanitizer(config).sanitize({"data": {"secret": "s"}})
        self.assertEqual(out["data"]["secret"], "[REDACTED]")


class PartialRetentionTest(unittest.TestCase):
    def test_partial_keeps_prefix_and_suffix(self):
        config = make_config(
            path_rules=[PathRule("phone", Action.PARTIAL, keep_prefix=3, keep_suffix=4)]
        )
        out, _ = Sanitizer(config).sanitize({"phone": "13812345678"})
        self.assertEqual(out["phone"], "138****5678")

    def test_partial_on_non_string_falls_back_to_redact(self):
        config = make_config(
            path_rules=[PathRule("phone", Action.PARTIAL, keep_prefix=3, keep_suffix=4)]
        )
        out, _ = Sanitizer(config).sanitize({"phone": 13812345678})
        self.assertEqual(out["phone"], 0)


class RoundTripTest(unittest.TestCase):
    def test_sanitize_is_idempotent(self):
        text = json.dumps(
            {
                "user_id": "u-1",
                "password": "pw",
                "note": "email alice@example.com",
                "users": [{"phone": "13812345678"}],
            }
        )
        sanitizer = Sanitizer(make_config())
        once, report1 = sanitizer.sanitize_json(text)
        twice, _ = sanitizer.sanitize_json(once)
        self.assertEqual(once, twice)
        self.assertNotIn("alice@example.com", once)
        self.assertNotIn("13812345678", once)

    def test_audit_digest_irreversible_and_deterministic(self):
        text = json.dumps({"password": "top-secret", "user_id": "u-1"})
        sanitizer = Sanitizer(make_config())
        _, report1 = sanitizer.sanitize_json(text)
        _, report2 = sanitizer.sanitize_json(text)
        self.assertEqual(report1.log_digest, report2.log_digest)
        self.assertNotIn("top-secret", json.dumps(report1.to_dict()))
        self.assertTrue(all(len(e.value_digest) == 16 for e in report1.entries))


if __name__ == "__main__":
    unittest.main()
