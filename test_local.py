"""Local fake grader. Starts the server with a stub planner (FAKE_MODEL=1), plays the grader,
and checks the contract: state machine, replay, conflicts, trace invariants, redaction.

    python test_local.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import httpx

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
CANARY = "CANARY-secret-token-9f3a1c"
fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)
        print("  FAIL:", msg)


def incident(run_id, title, marker="mk-public-123"):
    obj = {"type": "object", "properties": {"service": {"type": "string"}, "window": {"type": "string"}}}
    return {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": marker,
        "sensitive": {"accessToken": CANARY, "privateNote": "note-" + CANARY},
        "incident": {
            "incidentId": "INC-1", "title": title, "service": "checkout", "severity": "SEV-1",
            "transcript": "\n".join(f"[ev_{i:03d}] line {i} about checkout" for i in range(1, 30)),
            "allowedRootCauses": ["bad_deploy", "traffic_spike", "db_saturation"],
        },
        "toolCatalog": [
            {"name": "query_metrics", "description": "metrics", "inputSchema": obj},
            {"name": "fetch_logs", "description": "logs", "inputSchema": obj},
            {"name": "scale_service", "description": "scale", "inputSchema": obj},
            {"name": "page_owner", "description": "page", "inputSchema": obj},
            {"name": "rollback_deployment", "description": "rollback", "inputSchema": obj},
            {"name": "disable_feature", "description": "flag", "inputSchema": obj},
        ],
        "policy": {
            "maximumDiagnostics": 3,
            "effectTools": ["scale_service", "page_owner", "rollback_deployment", "disable_feature"],
            "approvalRequiredFor": ["rollback_deployment", "disable_feature"],
            "doNotExport": ["accessToken", "privateNote"],
        },
    }


c = httpx.Client(base_url=BASE, timeout=20)
n = [0]


def rid():
    n[0] += 1
    return f"rcpt-{n[0]:04d}-{os.urandom(3).hex()}"


def outcome(d, status=200, **kw):
    o = {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": status,
         "resultClass": "diagnosis_confirmed" if status == 200 else "transient", "nonce": os.urandom(8).hex() + "-uuid"}
    o.update(kw)
    return o


def receipt(run_id, outcomes=None, approvals=None, receipt_id=None):
    body = {"receiptId": receipt_id or rid()}
    if outcomes is not None:
        body["outcomes"] = outcomes
    if approvals is not None:
        body["approvals"] = approvals
    return body, c.post(f"/v2/incidents/{run_id}/receipts", json=body)


def attr(span, key):
    for a in span["attributes"]:
        if a["key"] == key:
            v = a["value"]
            return next(iter(v.values()))
    return None


def check_trace(final, ctx_trace=None):
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    by_id = {s["spanId"]: s for s in spans}
    check(len(by_id) == len(spans), "span ids unique")
    check(len({s["traceId"] for s in spans}) == 1, "single trace id")
    check(re.fullmatch(r"[0-9a-f]{32}", spans[0]["traceId"]) is not None, "trace id format")
    if ctx_trace:
        check(spans[0]["traceId"] == ctx_trace, "continued incoming trace")
    names = [s["name"] for s in spans]
    check(names.count("POST /v2/incidents") == 1, "one server span")
    check(names.count("chat incident-plan") == 1, "exactly one chat span")
    check(names.count("invoke_agent incident-response") == 1, "one agent span")
    check(all(attr(s, "ga5.run.id") == final["runId"] and attr(s, "ga5.public.marker") for s in spans), "run id + marker everywhere")
    check(not any("arguments" in a["key"] or "result" in a["key"] for s in spans for a in s["attributes"]), "no args/result attrs")
    log = final["actionLog"]
    exec_spans = [s for s in spans if s["name"].startswith("execute_tool ")]
    clients = [s for s in spans if s["name"].startswith("POST tool/")]
    check(len(exec_spans) == len({d["actionId"] for d in log}), "one execute_tool per logical action")
    check(len(clients) == len(log), "one CLIENT span per attempt")
    for d in log:
        sid = d["traceparent"].split("-")[2]
        s = by_id.get(sid)
        check(s is not None and s["kind"] == 3, "dispatch span id matches CLIENT span")
        if s:
            check(attr(s, "ga5.attempt") == d["attempt"], "attempt attr")
            check(attr(s, "http.request.resend_count") == d["attempt"] - 1, "resend_count")
            rl = [r for r in final["receiptLog"] if r.get("actionId") == d["actionId"] and r.get("attempt") == d["attempt"]]
            check(len(rl) == 1 and attr(s, "ga5.receipt.nonce") == rl[0]["nonce"] and attr(s, "ga5.receipt.id") == rl[0]["receiptId"], "receipt correlation")
            if rl[0]["status"] == 503:
                check(s["status"]["code"] == 2 and attr(s, "error.type") == "503", "503 span error")
            elif rl[0]["status"] == 0:
                check(s["status"]["code"] == 2 and attr(s, "error.type") == "timeout", "timeout span error")
            else:
                check(s["status"]["code"] != 2 and attr(s, "error.type") is None, "success span clean")
    for s in spans:
        p = by_id.get(s.get("parentSpanId"))
        if p and p["kind"] != 2:
            check(int(s["startTimeUnixNano"]) >= int(p["startTimeUnixNano"]) and int(s["endTimeUnixNano"]) <= int(p["endTimeUnixNano"]),
                  f"time containment {s['name']}")
    for s in spans:
        if s["name"] != "POST /v2/incidents":
            check(s.get("parentSpanId") in by_id, f"parent exists for {s['name']}")
    diag_exec = [s for s in exec_spans if any(d["actionId"] == attr(s, "ga5.action.id") and d["phase"] == "diagnostic" for d in log)]
    joins = [s for s in spans if s["name"] == "incident.join"]
    if len(diag_exec) > 1:
        check(len(joins) == 1 and {l["spanId"] for l in joins[0]["links"]} == {s["spanId"] for s in diag_exec}, "join links all diagnostics")
    else:
        check(not joins, "no join for single diagnostic")
    return names


def no_leak(*objs):
    blob = json.dumps(objs)
    check(CANARY not in blob, "sensitive canary leaked")


def scenario_safe_with_retry():
    print("scenario A: 2 diagnostics, 503 retry, safe effect")
    run = "run-A-" + os.urandom(3).hex()
    req = incident(run, "FAKE:effect=page_owner;diags=2")
    r = c.post("/v2/incidents", json=req)
    check(r.status_code == 200, "create 200")
    first = r.json()
    check(first["status"] == "waiting" and len(first["dispatches"]) == 2 and first["approvals"] == [], "first response shape")
    d1, d2 = first["dispatches"]
    check(all(d["phase"] == "diagnostic" and set(d["evidence"]) <= set(first["diagnosis"]["evidence"]) for d in first["dispatches"]), "diag evidence subset")
    _, r1 = receipt(run, [outcome(d1)])
    check(r1.status_code == 200 and r1.json()["dispatches"] == [] and r1.json()["status"] == "waiting", "partial receipt waits")
    _, r2 = receipt(run, [outcome(d2, 503, resultClass="unavailable")])
    j = r2.json()
    check(len(j["dispatches"]) == 1 and j["dispatches"][0]["attempt"] == 2 and j["approvals"] == [], "retry dispatch, no approval")
    retry = j["dispatches"][0]
    check(retry["actionId"] == d2["actionId"] and retry["callId"] == d2["callId"], "retry keeps ids")
    check(retry["traceparent"] != d2["traceparent"], "retry has new span id")
    _, stale = receipt(run, [outcome(d2, 503)])
    check(stale.status_code in (400, 422), "stale attempt rejected")
    _, r3 = receipt(run, [outcome(retry)])
    eff = r3.json()["dispatches"]
    check(len(eff) == 1 and eff[0]["phase"] == "effect" and eff[0]["toolName"] == "page_owner" and "approvalId" not in eff[0], "safe effect dispatched")
    body4, r4 = receipt(run, [outcome(eff[0])])
    final = r4.json()
    check(final["status"] == "completed" and final["chosenEffect"] == "page_owner" and "dispatches" not in final, "completed final")
    check(len(final["actionLog"]) == 4 and len(final["receiptLog"]) == 4, "logs complete")
    check_trace(final)
    # replay / conflicts
    check(c.post("/v2/incidents", json=req).json() == final, "repeat POST returns same JSON")
    check(c.post(f"/v2/incidents/{run}/receipts", json=body4).json() == final, "identical receipt replay same JSON")
    check(c.get(f"/v2/incidents/{run}").json() == final, "GET equals final")
    changed = json.loads(json.dumps(req)); changed["incident"]["title"] += " x"
    check(c.post("/v2/incidents", json=changed).status_code == 409, "changed runId content -> 409")
    body4b = json.loads(json.dumps(body4)); body4b["outcomes"][0]["nonce"] = "other-nonce-123"
    check(c.post(f"/v2/incidents/{run}/receipts", json=body4b).status_code == 409, "changed receipt -> 409")
    check(receipt(run, [outcome(eff[0])])[1].status_code in (400, 422), "new receipt after completion rejected")
    check(c.get(f"/v2/incidents/{run}").json() == final, "state unchanged after conflicts")
    no_leak(first, r1.json(), r2.json(), r3.json(), final)


def scenario_approval():
    print("scenario B: approval gate")
    run = "run-B-" + os.urandom(3).hex()
    req = incident(run, "FAKE:effect=rollback_deployment;diags=1")
    first = c.post("/v2/incidents", json=req).json()
    d = first["dispatches"][0]
    _, premature = receipt(run, [{"actionId": "act_unknown000", "callId": "call_unknown0", "attempt": 1, "status": 200, "nonce": "n" * 10}])
    check(premature.status_code in (400, 422), "unknown action rejected")
    _, r = receipt(run, [outcome(d)])
    j = r.json()
    check(j["dispatches"] == [] and len(j["approvals"]) == 1, "approval requested, zero dispatches")
    ap = j["approvals"][0]
    check(ap["toolName"] == "rollback_deployment" and re.fullmatch(r"[0-9a-f]{64}", ap["argumentsDigest"]) is not None, "approval shape")
    check(c.get(f"/v2/incidents/{run}").json()["approvals"] == j["approvals"], "GET shows pending approval")
    _, bad_ap = receipt(run, approvals=[{"approvalId": "apr_wrongwrong", "decision": "approved", "nonce": "z" * 10}])
    check(bad_ap.status_code in (400, 422), "wrong approval id rejected")
    nonce = "approval-nonce-" + os.urandom(4).hex()
    _, ra = receipt(run, approvals=[{"approvalId": ap["approvalId"], "decision": "approved", "nonce": nonce}])
    eff = ra.json()["dispatches"]
    check(len(eff) == 1 and eff[0]["actionId"] == ap["actionId"] and eff[0]["approvalId"] == ap["approvalId"] and eff[0]["approvalNonce"] == nonce, "effect carries approval")
    _, rf = receipt(run, [outcome(eff[0])])
    final = rf.json()
    check(final["status"] == "completed" and any("approvalId" in x for x in final["receiptLog"]), "final has approval receipt")
    names = check_trace(final)
    check(names.count("approval_gate") == 1, "approval_gate span")
    gate = next(s for s in final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"] if s["name"] == "approval_gate")
    check(attr(gate, "ga5.approval.id") == ap["approvalId"] and attr(gate, "ga5.approval.receipt.nonce") == nonce, "approval gate attrs")
    no_leak(first, j, ra.json(), final)


def scenario_timeout():
    print("scenario C: diagnostic timeout suppresses effect")
    run = "run-C-" + os.urandom(3).hex()
    first = c.post("/v2/incidents", json=incident(run, "FAKE:effect=scale_service;diags=2")).json()
    d1, d2 = first["dispatches"]
    receipt(run, [outcome(d1)])
    _, r = receipt(run, [outcome(d2, 0, errorType="timeout")])
    final = r.json()
    check(final["status"] == "failed" and final["suppressed"] == ["scale_service"], "failed + suppressed")
    check(all(d["phase"] == "diagnostic" for d in final["actionLog"]) and len(final["actionLog"]) == 2, "no effect dispatched")
    check_trace(final)
    no_leak(first, final)


def scenario_misc():
    print("scenario D/E: bad profile, incoming trace context")
    bad = incident("run-D-" + os.urandom(3).hex(), "FAKE:effect=page_owner;diags=1")
    bad["profile"] = "something/else"
    check(c.post("/v2/incidents", json=bad).status_code in (400, 422), "bad profile rejected")
    check(c.get(f"/v2/incidents/{bad['runId']}").status_code == 404, "nothing created for bad profile")
    tid, sid = "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"
    run = "run-E-" + os.urandom(3).hex()
    r = c.post("/v2/incidents", json=incident(run, "FAKE:effect=page_owner;diags=1"),
               headers={"traceparent": f"00-{tid}-{sid}-01", "tracestate": "vendor=abc"})
    d = r.json()["dispatches"][0]
    check(d["traceparent"].split("-")[1] == tid and d.get("tracestate") == "vendor=abc", "incoming trace continued, tracestate kept")
    _, r1 = receipt(run, [outcome(d)])
    _, r2 = receipt(run, [outcome(r1.json()["dispatches"][0])])
    final = r2.json()
    check_trace(final, ctx_trace=tid)
    server = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    check(server.get("parentSpanId") == sid, "server span parented to incoming span")


def main():
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, FAKE_MODEL="1", DB_PATH=os.path.join(tmp, "t.db"), DATABASE_URL="")
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(PORT), "--log-level", "warning"],
                           cwd=os.path.dirname(os.path.abspath(__file__)), env=env)
    try:
        for _ in range(50):
            try:
                if httpx.get(BASE + "/").status_code == 200:
                    break
            except Exception:
                time.sleep(0.2)
        scenario_safe_with_retry()
        scenario_approval()
        scenario_timeout()
        scenario_misc()
    finally:
        srv.terminate()
    print("\nALL PASSED" if not fails else f"\n{len(fails)} FAILURE(S)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
