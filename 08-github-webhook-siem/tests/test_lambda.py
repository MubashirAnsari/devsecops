"""
Offline unit tests for lambda/lambda_function.py.
No AWS or GitHub access needed: boto3 and the GitHub meta call are stubbed.

    python3 -m unittest tests/test_lambda.py -v
"""
import base64
import hashlib
import hmac
import importlib
import ipaddress
import json
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lambda"))

SECRET = "test-secret-not-real"
GITHUB_IP = "192.30.252.10"      # inside 192.30.252.0/22 (a published GitHub hooks range)
OTHER_IP = "203.0.113.10"        # documentation range, never GitHub


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, ContentType):
        self.objects[Key] = Body


class FakeSM:
    def get_secret_value(self, SecretId):
        return {"SecretString": SECRET}


def load_module():
    fake_s3, fake_sm = FakeS3(), FakeSM()
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda name, config=None: fake_s3 if name == "s3" else fake_sm
    botocore = types.ModuleType("botocore")
    cfg = types.ModuleType("botocore.config")
    cfg.Config = lambda **kw: kw
    sys.modules.update({"boto3": boto3, "botocore": botocore, "botocore.config": cfg})
    os.environ.update(BUCKET="test-bucket", SECRET_ID="test-secret-id")
    mod = importlib.import_module("lambda_function")
    mod = importlib.reload(mod)
    mod._fetch_hook_ranges = lambda: [ipaddress.ip_network("192.30.252.0/22"),
                                      ipaddress.ip_network("2a0a:a440::/29")]
    return mod, fake_s3


def request(body, ip=GITHUB_IP, method="POST", secret=SECRET, event="push",
            delivery="72d3162e-cc78-11e3-81ab-4c9367dc0958", ctype="application/json"):
    raw = json.dumps(body).encode()
    sig = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return {
        "requestContext": {"http": {"method": method, "sourceIp": ip}},
        "headers": {"Content-Type": ctype, "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": event, "X-GitHub-Delivery": delivery},
        "body": base64.b64encode(raw).decode(),
        "isBase64Encoded": True,
    }


PUSH = {
    "ref": "refs/heads/main", "forced": False, "created": False, "deleted": False,
    "commits": [{}], "pusher": {"name": "alice"},
    "head_commit": {"message": "fix typo", "committer": {"username": "alice"}},
    "repository": {"full_name": "example/app", "visibility": "private", "default_branch": "main"},
    "sender": {"login": "alice", "type": "User"},
}


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.m, self.s3 = load_module()

    def test_get_is_405(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH, method="GET"), None)["statusCode"], 405)

    def test_non_github_ip_is_403_and_nothing_stored(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH, ip=OTHER_IP), None)["statusCode"], 403)
        self.assertEqual(self.s3.objects, {})

    def test_bad_signature_is_401(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH, secret="wrong"), None)["statusCode"], 401)
        self.assertEqual(self.s3.objects, {})

    def test_wrong_content_type_is_415(self):
        r = self.m.lambda_handler(request(PUSH, ctype="application/x-www-form-urlencoded"), None)
        self.assertEqual(r["statusCode"], 415)

    def test_bad_delivery_id_is_400(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH, delivery="../../etc"), None)["statusCode"], 400)

    def test_allowlist_unavailable_fails_closed_503(self):
        def boom():
            raise OSError("network down")
        self.m._fetch_hook_ranges = boom
        self.assertEqual(self.m.lambda_handler(request(PUSH), None)["statusCode"], 503)

    def test_stale_list_reused_when_refresh_fails(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH), None)["statusCode"], 202)
        self.m._meta["fetched"] -= 7200          # older than TTL, younger than MAX_STALE
        self.m._fetch_hook_ranges = lambda: (_ for _ in ()).throw(OSError("down"))
        self.assertEqual(self.m.lambda_handler(request(PUSH), None)["statusCode"], 202)

    def test_ipv6_github_range_allowed(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH, ip="2a0a:a440::1"), None)["statusCode"], 202)

    def test_valid_push_is_stored_and_flattened(self):
        self.assertEqual(self.m.lambda_handler(request(PUSH), None)["statusCode"], 202)
        keys = sorted(self.s3.objects)
        self.assertTrue(keys[0].startswith("events/") and keys[1].startswith("raw/"))
        rec = json.loads(self.s3.objects[keys[0]])
        g = rec["github"]
        self.assertEqual(rec["integration"], "github-webhook")
        self.assertEqual((g["event"], g["repo"], g["is_default_branch"], g["via_pr_merge"]),
                         ("push", "example/app", True, False))
        self.assertNotIn("action", g)            # null fields are dropped

    def test_ui_pr_merge_detected(self):
        body = dict(PUSH, head_commit={"message": "Merge pull request #12 from example/feature",
                                       "committer": {"username": "web-flow"}})
        self.m.lambda_handler(request(body), None)
        rec = json.loads(next(v for k, v in self.s3.objects.items() if k.startswith("events/")))
        self.assertTrue(rec["github"]["via_pr_merge"])

    def test_deploy_key_public_key_not_in_flat_record(self):
        body = {"action": "created", "key": {"id": 1, "title": "ci", "read_only": False, "key": "ssh-ed25519 AAAA"},
                "repository": PUSH["repository"], "sender": PUSH["sender"]}
        self.m.lambda_handler(request(body, event="deploy_key"), None)
        flat = next(v for k, v in self.s3.objects.items() if k.startswith("events/"))
        self.assertNotIn(b"ssh-ed25519", flat)
        self.assertFalse(json.loads(flat)["github"]["deploy_key_read_only"])


if __name__ == "__main__":
    unittest.main()
