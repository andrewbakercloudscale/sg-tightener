"""--profile and SSO: every script takes --profile, and "not logged in" is one line with the fix."""

import logging

import pytest
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)

import sg_compact
import sg_diagnose
import sg_extend
import sg_ou_report
import sg_tightener
import sg_transfer_audit
import sg_viz
from sg_tightener import friendly_login_errors, login_hint


@pytest.fixture(autouse=True)
def _no_profile(monkeypatch):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setattr(sg_tightener, "_PROFILE", [None])


def test_expired_sso_says_log_in_again_with_the_profile():
    hint = login_hint(UnauthorizedSSOTokenError(), "prod-admin")
    assert "aws sso login --profile prod-admin" in hint
    assert "expired" in hint
    assert "aws sso login --profile dev" in login_hint(TokenRetrievalError(provider="sso", error_msg="x"), "dev")
    assert "aws sso login" in login_hint(SSOTokenLoadError(error_msg="no token"))


def test_profile_from_environment_is_used_in_the_hint(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "from-env")
    assert "--profile from-env" in login_hint(UnauthorizedSSOTokenError())


def test_no_credentials_and_unknown_profile():
    assert "aws sso login" in login_hint(NoCredentialsError())
    hint = login_hint(ProfileNotFound(profile="nope"))
    assert "aws configure list-profiles" in hint and "aws configure sso" in hint


def test_expired_token_from_aws_and_wrapped_errors():
    err = ClientError({"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "DescribeSecurityGroups")
    assert "ExpiredToken" in login_hint(err, "p") and "aws sso login --profile p" in login_hint(err, "p")
    try:
        try:
            raise UnauthorizedSSOTokenError()
        except Exception as inner:
            raise RuntimeError("scan failed") from inner
    except RuntimeError as outer:
        assert "aws sso login" in login_hint(outer)


def test_access_denied_is_not_a_login_problem():
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "DescribeVpcs")
    assert login_hint(denied) is None
    assert login_hint(ValueError("x")) is None


def test_wrapper_turns_login_errors_into_exit_1_and_passes_others(caplog):
    @friendly_login_errors
    def expired():
        raise UnauthorizedSSOTokenError()

    @friendly_login_errors
    def broken():
        raise ValueError("a real bug")

    with caplog.at_level(logging.ERROR):
        assert expired() == 1
    assert "aws sso login" in caplog.text
    with pytest.raises(ValueError):
        broken()


@pytest.mark.parametrize("argv,mod", [
    (["analyse", "--region", "eu-west-1", "--log-group", "g", "--profile", "x"], sg_tightener),
    (["plan", "--region", "eu-west-1", "--approved", "a.json", "--profile", "x"], sg_tightener),
    (["apply", "--plan", "p.json", "--profile", "x"], sg_tightener),
    (["revert", "--manifest", "m.json", "--profile", "x"], sg_tightener),
    (["plan", "--region", "eu-west-1", "--profile", "x"], sg_compact),
    (["export", "--region", "eu-west-1", "--log-group", "g", "--profile", "x"], sg_viz),
])
def test_subcommand_scripts_take_profile(argv, mod):
    assert mod._build_parser().parse_args(argv).profile == "x"


@pytest.mark.parametrize("mod,argv", [
    (sg_extend, ["--region", "eu-west-1", "--log-group", "g"]),
    (sg_diagnose, ["--region", "eu-west-1", "--log-group", "g"]),
    (sg_ou_report, ["--regions", "eu-west-1"]),
    (sg_transfer_audit, ["--regions", "eu-west-1"]),
])
def test_unknown_profile_is_one_line_not_a_traceback(mod, argv, caplog):
    with caplog.at_level(logging.ERROR):
        assert mod.main([*argv, "--profile", "no-such-profile-sg-tightener"]) == 1
    assert "aws configure list-profiles" in caplog.text
