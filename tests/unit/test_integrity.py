"""Plans and manifests carry an integrity block; apply and revert refuse edited ones."""

import json
import logging

import pytest

from sg_tightener import SIGNING_KEY_ENV, check_integrity, sign, verify


def _doc():
    return {"schema": "sg-tightener.manifest/v1", "region": "eu-west-1",
            "groups": [{"group_id": "sg-1", "revoked": [{"IpProtocol": "tcp", "FromPort": 22}]}]}


def _roundtrip(doc):
    return json.loads(json.dumps(doc, indent=2))


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)


def test_signed_document_survives_a_json_round_trip():
    doc = _roundtrip(sign(_doc(), "arn:aws:iam::111:user/alice"))
    assert doc["integrity"]["by"] == "arn:aws:iam::111:user/alice"
    assert "hmac_sha256" not in doc["integrity"]
    assert verify(doc)[0] == "ok"


def test_any_edit_is_detected_and_refused_unless_allowed(caplog):
    doc = _roundtrip(sign(_doc()))
    doc["groups"][0]["group_id"] = "sg-2"
    assert verify(doc)[0] == "modified"
    with pytest.raises(SystemExit, match="allow-modified"):
        check_integrity(doc, "manifest", "m.json")
    with caplog.at_level(logging.WARNING):
        check_integrity(doc, "manifest", "m.json", allow_modified=True)
    assert "continuing" in caplog.text


def test_unsigned_files_from_older_versions_still_work(caplog):
    with caplog.at_level(logging.WARNING):
        check_integrity(_doc(), "plan", "p.json")
    assert "no integrity block" in caplog.text


def test_hmac_catches_a_recomputed_sha256(monkeypatch):
    monkeypatch.setenv(SIGNING_KEY_ENV, "s3cret")
    doc = _roundtrip(sign(_doc()))
    assert doc["integrity"]["hmac_sha256"] and verify(doc)[0] == "ok"
    # Someone edits the file and recomputes the plain hash, without the key.
    monkeypatch.delenv(SIGNING_KEY_ENV)
    doc["region"] = "us-east-1"
    sign(doc)
    doc["integrity"]["hmac_sha256"] = "0" * 64
    monkeypatch.setenv(SIGNING_KEY_ENV, "s3cret")
    status, msg = verify(doc)
    assert status == "modified" and SIGNING_KEY_ENV in msg


def test_signature_that_cannot_be_checked_is_a_warning_not_a_refusal(monkeypatch):
    monkeypatch.setenv(SIGNING_KEY_ENV, "s3cret")
    doc = _roundtrip(sign(_doc()))
    monkeypatch.delenv(SIGNING_KEY_ENV)
    assert verify(doc)[0] == "unverified"
    check_integrity(doc, "manifest", "m.json")  # no SystemExit
    monkeypatch.setenv(SIGNING_KEY_ENV, "other")
    assert verify(doc)[0] == "modified"
