import pytest

from policy_engine import canonical_json, generate_keypair, sign, verify


def test_canonical_json_is_order_independent_and_rejects_floats():
    assert canonical_json({"b": 1, "a": [2, {"d": 1, "c": 2}]}) == canonical_json({"a": [2, {"c": 2, "d": 1}], "b": 1})
    with pytest.raises(TypeError):
        canonical_json({"x": 0.9})


def test_signature_round_trip_and_one_byte_change():
    priv, pub = generate_keypair()
    data = canonical_json({"amount_minor": 90000})
    sig = sign(priv, data)
    assert verify(pub, data, sig)
    assert not verify(pub, canonical_json({"amount_minor": 90001}), sig)
    assert not verify(generate_keypair()[1], data, sig)
    assert not verify(pub, data, "not-base64!!")
