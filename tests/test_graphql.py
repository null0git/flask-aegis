from flask import Flask, jsonify

from flask_aegis.graphql import GraphQLBlocked, GraphQLGuard, analyze_query


def test_analyze_simple_query_depth():
    a = analyze_query("query { user { name email } }")
    assert a.depth == 2
    assert a.field_count == 3


def test_analyze_nested_query_depth():
    nested = "query { a { b { c { d { e } } } } }"
    a = analyze_query(nested)
    assert a.depth == 5


def test_analyze_detects_introspection():
    a = analyze_query("query { __schema { types { name } } }")
    assert a.uses_introspection is True


def test_analyze_detects_aliases():
    a = analyze_query("query { x: field1 y: field2 }")
    assert a.alias_count == 2


def test_guard_allows_shallow_query():
    guard = GraphQLGuard(max_depth=10, max_complexity=200)
    assert guard.check("query { user { name } }") is None


def test_guard_blocks_deep_query():
    guard = GraphQLGuard(max_depth=5)
    deep = "query { a { b { c { d { e { f } } } } } }"
    blocked = guard.check(deep)
    assert blocked is not None
    assert blocked.reason == "depth_exceeded"


def test_guard_blocks_wide_query():
    guard = GraphQLGuard(max_complexity=10)
    wide = "query { " + " ".join(f"field{i}" for i in range(20)) + " }"
    blocked = guard.check(wide)
    assert blocked is not None
    assert blocked.reason == "complexity_exceeded"


def test_guard_blocks_alias_bomb():
    guard = GraphQLGuard(max_complexity=1000, max_aliases=5)
    bomb = "query { " + " ".join(f"a{i}: expensiveField" for i in range(20)) + " }"
    blocked = guard.check(bomb)
    assert blocked is not None
    assert blocked.reason == "alias_limit_exceeded"


def test_guard_blocks_introspection_when_disabled():
    guard = GraphQLGuard(allow_introspection=False)
    blocked = guard.check("query { __schema { types { name } } }")
    assert blocked is not None
    assert blocked.reason == "introspection_disabled"


def test_guard_allows_introspection_when_enabled():
    guard = GraphQLGuard(allow_introspection=True)
    assert guard.check("query { __schema { types { name } } }") is None


def test_guard_blocks_oversized_batch():
    guard = GraphQLGuard(max_batch_size=2)
    blocked = guard.check_batch(["query { a }", "query { b }", "query { c }"])
    assert blocked is not None
    assert blocked.reason == "batch_size_exceeded"


def test_guard_allows_batch_within_limit():
    guard = GraphQLGuard(max_batch_size=2)
    assert guard.check_batch(["query { a }", "query { b }"]) is None


def test_flask_decorator_blocks_deep_query():
    guard = GraphQLGuard(max_depth=3, allow_introspection=False)
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)

    @app.errorhandler(GraphQLBlocked)
    def handle(e):
        return jsonify(error=e.reason), 400

    @app.post("/graphql")
    @guard.protect()
    def graphql_endpoint():
        return jsonify(data={"ok": True})

    client = app.test_client()
    good = client.post("/graphql", json={"query": "query { user { name } }"})
    assert good.status_code == 200

    deep = "query { a { b { c { d { e } } } } }"
    bad = client.post("/graphql", json={"query": deep})
    assert bad.status_code == 400
    assert bad.get_json()["error"] == "depth_exceeded"
