// tools/live-check — the loopback front for a real IdP login against the
// standalone template. One process on LIVE_CHECK_PORT does three things:
//
//   1. serves the test page at `/`, its record at `/__live-check/state` and
//      the same record as an issue-ready markdown at `/__live-check/report`;
//   2. is the user Store the template's HttpUserRepository asks — every
//      `<federation>:<sub>` token is a user here, so a login never fails for
//      want of a local account (this is what makes the Store unfit for
//      anything but a loopback check);
//   3. proxies everything else to the provider and records what the
//      federation callback carried (`iss` in full; `code` and `state` as
//      lengths only — never their values, never the `sub`) and how the
//      provider answered it.
//
// Nothing here is the thing under test. The provider's own handling of the
// callback — the RFC 9207 `iss` check in particular — is.
import http from "node:http";
import { URL } from "node:url";

const PORT = Number(process.env.LIVE_CHECK_PORT ?? 3210);
const PROVIDER_PORT = Number(process.env.LIVE_CHECK_PROVIDER_PORT ?? 3000);
const FEDERATION = process.env.LIVE_CHECK_FEDERATION ?? "google";
const EXPECTED_ISS = process.env.LIVE_CHECK_EXPECTED_ISS || null;
const SESSION_COOKIE = process.env.SESSION_NAME ?? "auth.session";
const START_PATH = `/session/oauth/federation/${FEDERATION}`;
const CALLBACK_PATH = `${START_PATH}/callback`;

const state = {
	federation: FEDERATION,
	expectedIss: EXPECTED_ISS,
	startedAt: new Date().toISOString(),
	start: null, // the redirect to the IdP
	callback: null, // what the IdP sent back and how the provider answered
	store: null, // the identity the provider asked the Store about
};

/** The last four characters, the rest as bullets — enough to match, never enough to replay. */
function mask(value) {
	if (typeof value !== "string") return null;
	if (value.length <= 4) return "••••";
	return `${"•".repeat(Math.min(value.length - 4, 12))}${value.slice(-4)}`;
}

function readBody(req) {
	return new Promise((resolve) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => resolve(Buffer.concat(chunks)));
	});
}

function json(res, status, body) {
	res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
	res.end(JSON.stringify(body));
}

// ---- the Store -------------------------------------------------------------
async function store(req, res, url) {
	if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed" });
	let body;
	try {
		body = JSON.parse((await readBody(req)).toString("utf8"));
	} catch {
		return json(res, 400, { error: "bad_json" });
	}
	if (url.pathname === "/__store/authenticate-by-token") {
		const token = typeof body?.token === "string" ? body.token : "";
		const prefix = `${FEDERATION}:`;
		if (!token.startsWith(prefix)) {
			state.store = { at: new Date().toISOString(), accepted: false, token: mask(token) };
			return json(res, 401, { error: "unknown_token" });
		}
		const sub = token.slice(prefix.length);
		state.store = { at: new Date().toISOString(), accepted: true, token: `${prefix}${mask(sub)}` };
		return json(res, 200, {
			id: `live-check-${sub}`,
			username: `${FEDERATION}-${sub.slice(-4)}`,
			name: "live-check user",
		});
	}
	// Password login is not part of a federation check.
	return json(res, 401, { error: "not_supported_by_live_check" });
}

// ---- the proxy ---------------------------------------------------------------
function proxy(req, res, url) {
	const isCallback = url.pathname === CALLBACK_PATH;
	const isStart = url.pathname === START_PATH;
	const headers = { ...req.headers, host: `localhost:${PROVIDER_PORT}` };
	const upstream = http.request(
		{ host: "127.0.0.1", port: PROVIDER_PORT, method: req.method, path: req.url, headers },
		(up) => {
			const chunks = [];
			up.on("data", (c) => chunks.push(c));
			up.on("end", () => {
				const body = Buffer.concat(chunks);
				if (isStart) {
					let to = null;
					try {
						const u = new URL(up.headers.location ?? "");
						to = `${u.origin}${u.pathname}`;
					} catch {}
					state.start = { at: new Date().toISOString(), status: up.statusCode, redirectedTo: to };
					state.callback = null;
					state.store = null;
				}
				if (isCallback) {
					const q = url.searchParams;
					const redirected = up.statusCode === 302 || up.statusCode === 303;
					let answer = null;
					if (!redirected) {
						try {
							answer = JSON.parse(body.toString("utf8"));
						} catch {
							answer = { raw: body.toString("utf8").slice(0, 300) };
						}
					}
					const setCookie = up.headers["set-cookie"] ?? [];
					state.callback = {
						at: new Date().toISOString(),
						queryKeys: [...q.keys()],
						iss: q.get("iss"),
						codeLength: q.get("code")?.length ?? 0,
						stateLength: q.get("state")?.length ?? 0,
						providerStatus: up.statusCode,
						providerLocation: up.headers.location ?? null,
						providerAnswer: answer,
						sessionCookieSet: setCookie.some((c) => c.startsWith(`${SESSION_COOKIE}=`)),
					};
				}
				res.writeHead(up.statusCode ?? 502, up.headers);
				res.end(body);
			});
		},
	);
	upstream.on("error", (err) => {
		json(res, 502, { error: "provider_unreachable", detail: String(err.message) });
	});
	req.pipe(upstream);
}

// ---- the verdict, shared by the page and the report -------------------------------
function verdict(s) {
	const c = s.callback;
	if (!c) return null;
	const issPresent = typeof c.iss === "string" && c.iss.length > 0;
	const issOk = issPresent && (s.expectedIss === null || c.iss === s.expectedIss);
	const loginOk = c.providerStatus === 302 || c.providerStatus === 303;
	return { issPresent, issOk, loginOk, ok: issOk && loginOk };
}

function report(s) {
	const c = s.callback;
	if (!c) return `live-check (${s.federation}) — no callback recorded yet\n`;
	const v = verdict(s);
	return [
		`live-check — ${s.federation} — ${c.at}`,
		"- build: this checkout, standalone template with its default config (requireAuthorizationResponseIss unset)",
		`- callback query keys: ${c.queryKeys.join(", ")}`,
		`- iss: ${c.iss ?? "(absent)"}${s.expectedIss ? ` (expected ${s.expectedIss})` : ""} ${v.issOk ? "✅" : "❌"}`,
		`- provider answer: ${
			v.loginOk
				? `${c.providerStatus} → ${c.providerLocation} (login succeeded) ✅`
				: `HTTP ${c.providerStatus} ${JSON.stringify(c.providerAnswer)} ❌`
		}`,
		`- user Store asked for: ${s.store ? s.store.token : "(none)"}`,
		`- session cookie set: ${c.sessionCookieSet ? "yes" : "no"}`,
		"- gateway: none (browser → loopback live-check proxy → provider; the query passed through untouched)",
		"",
	].join("\n");
}

// ---- the page ---------------------------------------------------------------------
const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>live-check — ${FEDERATION}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#f6f7f9;--fg:#1c1f26;--muted:#5b6170;--card:#fff;--line:#e2e5ea;--ok:#1a7f4b;--ng:#b42318;--accent:#2f5bea}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e8eaf0;--muted:#9aa1b2;--card:#171a21;--line:#2a2f3a;--ok:#3ccf7e;--ng:#ff7a6e;--accent:#7f9cff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,sans-serif}
main{max-width:720px;margin:0 auto;padding:32px 16px}
h1{font-size:20px;margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:16px}
a.btn{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600}
button{background:transparent;color:var(--accent);border:1px solid var(--line);padding:7px 12px;border-radius:8px;cursor:pointer;font:inherit}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
.ok{color:var(--ok);font-weight:600}.ng{color:var(--ng);font-weight:600}.wait{color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12.5px;white-space:pre-wrap}
.verdict{font-size:17px;font-weight:700;margin:0 0 10px}
</style></head><body><main>
<h1>live-check — <code>${FEDERATION}</code> callback</h1>
<p class="sub">standalone template, default config${EXPECTED_ISS ? ` — expecting <code>iss=${EXPECTED_ISS}</code>` : ""}</p>
<div class="card">
  <a class="btn" href="${START_PATH}">Sign in with ${FEDERATION}</a>
  <span style="margin-left:12px;color:var(--muted)">→ the IdP sends you back here and the record fills in</span>
</div>
<div class="card" id="result"><p class="verdict wait">No sign-in yet</p></div>
<div class="card"><button id="copy">Copy the report</button> <button id="reload">Refresh</button>
<pre id="report" hidden></pre></div>
</main>
<script>
const $=s=>document.querySelector(s);
function row(k,v){return '<dt>'+k+'</dt><dd>'+v+'</dd>'}
function render(s){
  const r=$('#result');
  if(!s.callback){
    r.innerHTML='<p class="verdict wait">'+(s.start?'Redirected to '+s.start.redirectedTo+' — waiting for the callback':'No sign-in yet')+'</p>';
    $('#report').hidden=true; return;
  }
  const c=s.callback, v=s.verdict;
  const banner= v.ok ? '<p class="verdict ok">OK — the callback carried iss and the login succeeded</p>'
    : !v.issPresent ? '<p class="verdict ng">NG — the callback carried no iss</p>'
    : !v.issOk ? '<p class="verdict ng">NG — iss is not the expected issuer</p>'
    : '<p class="verdict ng">iss present, but the login failed (HTTP '+c.providerStatus+')</p>';
  r.innerHTML=banner+'<dl>'
   +row('callback at',c.at)
   +row('query keys','<code>'+c.queryKeys.join(', ')+'</code>')
   +row('iss', c.iss? '<code>'+c.iss+'</code> '+(v.issOk?'<span class="ok">✓</span>':'<span class="ng">✗ not the expected issuer</span>') : '<span class="ng">✗ absent</span>')
   +row('code / state', 'code '+c.codeLength+' chars, state '+c.stateLength+' chars (values not recorded)')
   +row('provider answer', v.loginOk? '<span class="ok">'+c.providerStatus+' → '+c.providerLocation+'</span>' : '<span class="ng">HTTP '+c.providerStatus+'</span> <code>'+(c.providerAnswer?JSON.stringify(c.providerAnswer):'')+'</code>')
   +row('Store asked for', s.store? (s.store.accepted?'<span class="ok">✓</span> ':'<span class="ng">✗</span> ')+'<code>'+s.store.token+'</code>' : '<span class="wait">nothing</span>')
   +row('session cookie', c.sessionCookieSet?'<span class="ok">✓ set</span>':'<span class="ng">✗ not set</span>')
   +'</dl>';
  $('#report').textContent=s.report; $('#report').hidden=false;
}
async function load(){ try{ render(await (await fetch('/__live-check/state',{cache:'no-store'})).json()); }catch(e){} }
$('#reload').onclick=load;
$('#copy').onclick=async()=>{ await load(); const t=$('#report').textContent; if(t){ await navigator.clipboard.writeText(t); $('#copy').textContent='Copied'; setTimeout(()=>$('#copy').textContent='Copy the report',1500);} };
load(); setInterval(load,3000);
</script></body></html>`;

http
	.createServer(async (req, res) => {
		const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
		if (url.pathname === "/" && req.method === "GET") {
			res.writeHead(200, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
			});
			return res.end(PAGE);
		}
		if (url.pathname === "/__live-check/state") {
			return json(res, 200, { ...state, verdict: verdict(state), report: report(state) });
		}
		if (url.pathname === "/__live-check/report") {
			res.writeHead(200, {
				"content-type": "text/markdown; charset=utf-8",
				"cache-control": "no-store",
			});
			return res.end(report(state));
		}
		if (url.pathname.startsWith("/__store/")) return store(req, res, url);
		return proxy(req, res, url);
	})
	.listen(PORT, "127.0.0.1", () => {
		console.log(
			`live-check: http://localhost:${PORT}/ (federation ${FEDERATION}, provider :${PROVIDER_PORT})`,
		);
	});
