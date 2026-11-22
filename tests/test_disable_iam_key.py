import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from disable_iam_key import decide, handle  # noqa: E402

ACCOUNT = "111122223333"


class Fake:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda **kw: self.calls.append((name, kw))


def finding(user_type="IAMUser", key="AKIAEXAMPLEKEY000001", user="ci-bot", account=ACCOUNT,
            ftype="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"):
    return {"detail": {"id": "f-1", "type": ftype, "severity": 8, "accountId": account,
                       "resource": {"accessKeyDetails": {"accessKeyId": key, "userName": user, "userType": user_type}}}}


@pytest.mark.parametrize("kwargs, action, why", [
    ({}, "deactivate", "UnauthorizedAccess"),
    ({"user_type": "Root"}, "skip", "Root"),
    ({"user_type": "AssumedRole", "key": "ASIAEXAMPLE"}, "skip", "AssumedRole"),
    ({"key": "ASIATEMPORARY000001"}, "skip", "not a long-lived"),
    ({"key": ""}, "skip", "missing"),
    ({"user": ""}, "skip", "no user name"),
    ({"account": "999988887777"}, "skip", "deactivate it there"),
])
def test_decide(kwargs, action, why):
    got_action, reason = decide(finding(**kwargs)["detail"], ACCOUNT)
    assert got_action == action and why in reason


def test_live_run_deactivates_and_notifies():
    iam, sns = Fake(), Fake()
    r = handle(finding(), iam, sns, "arn:topic", ACCOUNT, dry_run=False)
    assert r["done"] is True
    assert iam.calls == [("update_access_key", {"UserName": "ci-bot", "AccessKeyId": "AKIAEXAMPLEKEY000001",
                                                "Status": "Inactive"})]
    (name, msg), = sns.calls
    assert name == "publish" and msg["Subject"].startswith("[security] DEACTIVATED")
    assert json.loads(msg["Message"])["user"] == "ci-bot"


def test_dry_run_never_touches_iam():
    iam, sns = Fake(), Fake()
    r = handle(finding(), iam, sns, "arn:topic", ACCOUNT, dry_run=True)
    assert iam.calls == [] and r["done"] is False
    assert "WOULD DEACTIVATE" in sns.calls[0][1]["Subject"]


def test_skips_are_reported_too():
    iam, sns = Fake(), Fake()
    r = handle(finding(user_type="Root"), iam, sns, "arn:topic", ACCOUNT, dry_run=False)
    assert iam.calls == [] and r["action"] == "skip"
    assert "SKIPPED" in sns.calls[0][1]["Subject"]


def test_malformed_event_does_not_crash():
    iam, sns = Fake(), Fake()
    r = handle({}, iam, sns, "arn:topic", ACCOUNT, dry_run=False)
    assert r["action"] == "skip" and iam.calls == []
