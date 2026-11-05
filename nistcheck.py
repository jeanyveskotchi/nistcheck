"""nistcheck: check a Terraform plan (JSON) against a few NIST SP 800-53 controls.

Usage: terraform show -json plan.out > plan.json && python nistcheck.py plan.json [--json]
Exit code is 1 if any HIGH finding exists, so it can gate a CI pipeline.
"""
import json
import sys
from dataclasses import dataclass, asdict

ANY = ("0.0.0.0/0", "::/0")
ADMIN_PORTS = {22, 3389}


@dataclass
class Finding:
    control: str      # NIST 800-53 control id
    severity: str     # HIGH / MEDIUM
    resource: str
    message: str


def _resources(plan):
    """Yield (address, type, values) for every resource that will exist after apply."""
    for r in plan.get("planned_values", {}).get("root_module", {}).get("resources", []):
        yield r["address"], r["type"], r.get("values") or {}
    for m in plan.get("planned_values", {}).get("root_module", {}).get("child_modules", []):
        for r in m.get("resources", []):
            yield r["address"], r["type"], r.get("values") or {}


def _covers_admin(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if rule.get("protocol") in ("-1", -1):
        return True
    if lo is None or hi is None:
        return False
    return any(lo <= p <= hi for p in ADMIN_PORTS)


def check_resource(addr, rtype, v):
    out = []
    if rtype == "aws_security_group":
        for rule in v.get("ingress") or []:
            cidrs = (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or [])
            if any(c in ANY for c in cidrs) and _covers_admin(rule):
                out.append(Finding("SC-7", "HIGH", addr, "Admin port (SSH/RDP) open to the whole internet"))
    elif rtype == "oci_core_security_list":
        for rule in v.get("ingress_security_rules") or []:
            if rule.get("source") in ANY:
                opts = (rule.get("tcp_options") or [{}])[0]
                lo, hi = opts.get("min"), opts.get("max")
                if rule.get("protocol") in ("all", "-1") or (
                        lo is not None and hi is not None and any(lo <= p <= hi for p in ADMIN_PORTS)):
                    out.append(Finding("SC-7", "HIGH", addr, "Admin port (SSH/RDP) open to the whole internet"))
    elif rtype == "aws_s3_bucket" and v.get("acl") in ("public-read", "public-read-write"):
        out.append(Finding("AC-3", "HIGH", addr, "Bucket ACL allows public access"))
    elif rtype == "oci_objectstorage_bucket" and v.get("access_type") not in (None, "NoPublicAccess"):
        out.append(Finding("AC-3", "HIGH", addr, "Object Storage bucket allows public access"))
    elif rtype == "aws_ebs_volume" and not v.get("encrypted"):
        out.append(Finding("SC-28", "HIGH", addr, "Volume is not encrypted at rest"))
    elif rtype == "aws_db_instance":
        if not v.get("storage_encrypted"):
            out.append(Finding("SC-28", "HIGH", addr, "Database storage is not encrypted at rest"))
        if v.get("publicly_accessible"):
            out.append(Finding("SC-7", "HIGH", addr, "Database is publicly accessible"))
    elif rtype in ("aws_iam_policy", "aws_iam_role_policy"):
        try:
            doc = json.loads(v.get("policy") or "{}")
        except ValueError:
            doc = {}
        stmts = doc.get("Statement", [])
        for s in stmts if isinstance(stmts, list) else [stmts]:
            acts = s.get("Action", [])
            acts = [acts] if isinstance(acts, str) else acts
            res = s.get("Resource", [])
            res = [res] if isinstance(res, str) else res
            if s.get("Effect") == "Allow" and "*" in acts and "*" in res:
                out.append(Finding("AC-6", "HIGH", addr, "Policy allows every action on every resource (least privilege)"))
    elif rtype == "aws_cloudtrail" and not v.get("enable_logging", True):
        out.append(Finding("AU-2", "MEDIUM", addr, "CloudTrail logging is switched off"))
    return out


def check_plan(plan):
    findings = []
    for addr, rtype, v in _resources(plan):
        findings.extend(check_resource(addr, rtype, v))
    return findings


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    with open(argv[0]) as f:
        findings = check_plan(json.load(f))
    if "--json" in argv:
        print(json.dumps([asdict(x) for x in findings], indent=2))
    else:
        for x in findings:
            print(f"[{x.severity}] {x.control} {x.resource}: {x.message}")
        print(f"{len(findings)} finding(s)")
    return 1 if any(x.severity == "HIGH" for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
