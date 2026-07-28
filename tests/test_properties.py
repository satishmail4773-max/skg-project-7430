import copy
import random
import string

from specsentinel.diff import compare_schemas
from specsentinel.schema import canonical_fingerprint, validate_openapi


def test_fingerprint_property_key_order_never_changes_result(openapi_schema):
    randomizer = random.Random(7430)
    baseline = canonical_fingerprint(openapi_schema)
    for _ in range(100):
        candidate = copy.deepcopy(openapi_schema)
        items = list(candidate["info"].items())
        randomizer.shuffle(items)
        candidate["info"] = dict(items)
        assert canonical_fingerprint(candidate) == baseline


def test_diff_property_added_operations_never_increase_risk(openapi_schema):
    randomizer = random.Random(7430)
    for _ in range(50):
        current = copy.deepcopy(openapi_schema)
        path = "/" + "".join(randomizer.choices(string.ascii_lowercase, k=12))
        current["paths"][path] = {"get": {"responses": {"200": {"description": "OK"}}}}
        score, _, changes = compare_schemas(openapi_schema, current)
        assert score == 0
        assert all(change.points == 0 for change in changes)


def test_validation_property_operation_bound_is_enforced(openapi_schema):
    for count in range(1, 25):
        document = copy.deepcopy(openapi_schema)
        document["paths"] = {f"/{index}": {"get": {"responses": {"200": {"description": "OK"}}}} for index in range(count)}
        assert len(validate_openapi(document, count)) == count

