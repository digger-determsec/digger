#!/usr/bin/env bash
# DIGGER MCP Quickstart Smoke
# Mirrors the dogfood handshake: scan-live → emit context → digger_mcp → 4 tools.
# Exits non-zero on any failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Locate binaries — prefer workspace target, fall back to PATH
DIGGER="${REPO_ROOT}/target/debug/digger"
DIGGER_MCP="${REPO_ROOT}/target/debug/digger_mcp"
if [ ! -x "$DIGGER" ]; then DIGGER="$(command -v digger 2>/dev/null || true)"; fi
if [ ! -x "$DIGGER_MCP" ]; then DIGGER_MCP="$(command -v digger_mcp 2>/dev/null || true)"; fi

if [ -z "$DIGGER" ] || [ ! -x "$DIGGER" ]; then
    echo "FAIL: digger binary not found" >&2; exit 1
fi
if [ -z "$DIGGER_MCP" ] || [ ! -x "$DIGGER_MCP" ]; then
    echo "FAIL: digger_mcp binary not found" >&2; exit 1
fi

FIXTURE="${REPO_ROOT}/corpus/price-manipulation/bzx-2020/source.sol"
if [ ! -f "$FIXTURE" ]; then
    echo "FAIL: corpus fixture not found: $FIXTURE" >&2; exit 1
fi

CTX="$(mktemp digger-ctx-XXXXXX.json)"
trap 'rm -f "$CTX"' EXIT

echo "=== Phase 1: scan-live → emit ScanContext ==="
"$DIGGER" scan-live --source-file "$FIXTURE" --emit-scan-context "$CTX" > /dev/null 2>&1

if [ ! -f "$CTX" ]; then
    echo "FAIL: scan-live did not emit ScanContext file" >&2; exit 1
fi

FINDING_COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('findings',[])))" "$CTX")
if [ "$FINDING_COUNT" -lt 1 ]; then
    echo "FAIL: ScanContext has $FINDING_COUNT findings (expected >= 1)" >&2; exit 1
fi
echo "  Emitted $FINDING_COUNT finding(s) from bzx-2020"

echo ""
echo "=== Phase 2: MCP handshake → 4 tools ==="
# Build all JSON-RPC requests
REQ_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"quickstart","version":"1.0"}}}'
REQ_NOTIF='{"jsonrpc":"2.0","method":"notifications/initialized"}'
REQ_LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
REQ_FIND='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"scan_id":"x"}}}'

# Get first finding_id for validate test
FINDING_ID=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['findings'][0]['finding_id'])" "$CTX")
RULE_ID=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['findings'][0]['rule_id'])" "$CTX")
SEVERITY=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['findings'][0]['severity'])" "$CTX")
CONFIDENCE=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['findings'][0]['confidence'])" "$CTX")
STAGE=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['findings'][0]['stage'])" "$CTX")

TRUE_CLAIM="{\"scan_id\":\"qs\",\"claimed_findings\":[{\"finding_id\":\"$FINDING_ID\",\"rule_id\":\"$RULE_ID\",\"severity\":\"$SEVERITY\",\"confidence\":\"$CONFIDENCE\",\"stage\":\"$STAGE\",\"locations\":[],\"exploit_status\":\"none\",\"claim_text\":\"benign\"}],\"prose\":\"benign\"}"
LIE_CLAIM="{\"scan_id\":\"qs\",\"claimed_findings\":[{\"finding_id\":\"$FINDING_ID\",\"rule_id\":\"$RULE_ID\",\"severity\":\"critical\",\"confidence\":\"$CONFIDENCE\",\"stage\":\"$STAGE\",\"locations\":[],\"exploit_status\":\"none\",\"claim_text\":\"promoted\"}],\"prose\":\"promoted\"}"

REQ_TRUE="{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"validate_assistant_output\",\"arguments\":$TRUE_CLAIM}}"
REQ_LIE="{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"validate_assistant_output\",\"arguments\":$LIE_CLAIM}}"

# Pipe all requests and capture all responses
ALL_REQUESTS="$REQ_INIT"$'\n'"$REQ_NOTIF"$'\n'"$REQ_LIST"$'\n'"$REQ_FIND"$'\n'"$REQ_TRUE"$'\n'"$REQ_LIE"
RESPONSES=$(echo "$ALL_REQUESTS" | "$DIGGER_MCP" "$CTX" 2>/dev/null)

# Assert initialize
echo "$RESPONSES" | python3 -c "
import json,sys
lines = [l.strip() for l in sys.stdin if l.strip()]
r = [json.loads(l) for l in lines if l.strip()]
init = [x for x in r if x.get('id')==1]
assert len(init)==1, 'missing initialize response'
assert init[0]['result']['protocolVersion']=='2024-11-05', f'bad protocol version: {init[0]}'
print('  initialize: OK')
"

# Assert tools/list returns 4 readonly tools
echo "$RESPONSES" | python3 -c "
import json,sys
lines = [l.strip() for l in sys.stdin if l.strip()]
r = [json.loads(l) for l in lines if l.strip()]
tl = [x for x in r if x.get('id')==2]
assert len(tl)==1, 'missing tools/list response'
tools = tl[0]['result']['tools']
assert len(tools)==4, f'expected 4 tools, got {len(tools)}'
names = {t['name'] for t in tools}
assert names == {'list_findings','get_evidence','get_explanation_context','validate_assistant_output'}, f'unexpected tools: {names}'
for t in tools:
    assert t['annotations']['readOnlyHint']==True, f'{t[\"name\"]} not readOnlyHint'
print('  tools/list: 4 tools, all readOnlyHint')
"

# Assert list_findings echoes engine labels
echo "$RESPONSES" | python3 -c "
import json,sys
lines = [l.strip() for l in sys.stdin if l.strip()]
r = [json.loads(l) for l in lines if l.strip()]
lf = [x for x in r if x.get('id')==3]
assert len(lf)==1, 'missing list_findings response'
findings = json.loads(lf[0]['result']['content'][0]['text'])
assert len(findings)>=1, 'list_findings returned empty'
f = findings[0]
assert f['rule_id']=='$RULE_ID', f'rule_id mismatch: {f[\"rule_id\"]}'
assert f['severity']=='$SEVERITY', f'severity mismatch: {f[\"severity\"]}'
assert f['confidence']=='$CONFIDENCE', f'confidence mismatch: {f[\"confidence\"]}'
print(f'  list_findings: OK ({len(findings)} findings, rule={f[\"rule_id\"]})')
"

# Assert validate passes on engine-true claim
echo "$RESPONSES" | python3 -c "
import json,sys
lines = [l.strip() for l in sys.stdin if l.strip()]
r = [json.loads(l) for l in lines if l.strip()]
vr = [x for x in r if x.get('id')==6]
assert len(vr)==1, 'missing validate response'
report = json.loads(vr[0]['result']['content'][0]['text'])
assert report['pass']==True, f'engine-true claim must pass, got: {report}'
print('  validate (engine-true): pass=True')
"

# Assert validate rejects promoted severity
echo "$RESPONSES" | python3 -c "
import json,sys
lines = [l.strip() for l in sys.stdin if l.strip()]
r = [json.loads(l) for l in lines if l.strip()]
lr = [x for x in r if x.get('id')==7]
assert len(lr)==1, 'missing lie response'
report = json.loads(lr[0]['result']['content'][0]['text'])
assert report['pass']==False, f'promoted severity must fail, got: {report}'
codes = {v['code'] for v in report['violations']}
assert 'SEVERITY_UPGRADED' in codes, f'missing SEVERITY_UPGRADED, got: {codes}'
print('  validate (promoted): pass=False, SEVERITY_UPGRADED')
"

echo ""
echo "=== ALL SMOKE CHECKS PASSED ==="
