import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from nistcheck import check_plan


def plan(*res):
    return {"planned_values": {"root_module": {"resources": [
        {"address": f"{t}.x", "type": t, "values": v} for t, v in res]}}}


def test_open_ssh_flagged():
    p = plan(("aws_security_group", {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}))
    assert [f.control for f in check_plan(p)] == ["SC-7"]


def test_open_https_not_flagged():
    p = plan(("aws_security_group", {"ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}))
    assert check_plan(p) == []


def test_oci_public_bucket():
    p = plan(("oci_objectstorage_bucket", {"access_type": "ObjectRead"}))
    assert check_plan(p)[0].control == "AC-3"


def test_unencrypted_db_and_public():
    p = plan(("aws_db_instance", {"storage_encrypted": False, "publicly_accessible": True}))
    assert sorted(f.control for f in check_plan(p)) == ["SC-28", "SC-7"]


def test_wildcard_iam():
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert check_plan(plan(("aws_iam_policy", {"policy": pol})))[0].control == "AC-6"


def test_scoped_iam_ok():
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]})
    assert check_plan(plan(("aws_iam_policy", {"policy": pol}))) == []
