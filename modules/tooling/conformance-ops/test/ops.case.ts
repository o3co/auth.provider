import { generateKeyPairSync, randomBytes } from "node:crypto";
import { type AreaScene, areaTarget, faultyTarget, type Started, sceneOf } from "@mod/conformance";
import { keysArea, type SigningScene } from "@mod/conformance-keys";
import { oauthScene } from "@mod/conformance-oauth";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { opsArea, scrapePathSetting } from "../src/main.ts";

const driver = areaTarget();
const jwksPath = "/.well-known/jwks.json";
// The nine methods http labels by name; any other is "other".
const methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"];

function signing(): SigningScene {
	const pair = generateKeyPairSync("ed25519");
	return {
		kid: "ops",
		alg: "EdDSA",
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	};
}

const scene: AreaScene = sceneOf(keysArea.part({ signing: signing() }), opsArea.part({}));

/** Starts the scene once for the describe it is called in, and gives its root URL. */
function running(target: AreaScene) {
	let started: Started | undefined;
	beforeAll(async () => {
		started = await driver.start(target);
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	return () => {
		if (started?.kind !== "running") throw new Error("the target is not running");
		return started.baseUrl;
	};
}

interface Sample {
	readonly name: string;
	readonly labels: Readonly<Record<string, string>>;
	readonly value: string;
}

/** The sample lines of a scrape, each with its labels by name (their order is not compared). */
function samples(text: string): Sample[] {
	return text
		.split("\n")
		.filter((line) => line !== "" && !line.startsWith("#"))
		.map((line) => {
			const match = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (\S+)/.exec(line);
			if (!match) throw new Error("a scrape line is not a sample");
			const labels = Object.fromEntries(
				[...(match[2] ?? "").matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g)].map((m) => [
					m[1],
					m[2],
				]),
			);
			return { name: match[1] as string, labels, value: match[3] as string };
		});
}

const durations = (all: Sample[], suffix: string) =>
	all.filter((s) => s.name === `http_request_duration_seconds${suffix}`);

const seriesKey = (s: Sample) => `${s.labels.method} ${s.labels.route} ${s.labels.status}`;

describe("Q. liveness", () => {
	const base = running(scene);

	it("answers GET with 200 and ok, and HEAD with 200 and no body", async () => {
		const res = await fetch(`${base()}/_healthcheck`);
		expect(res.status).toBe(200);
		expect(((await res.json()) as { status: string }).status).toBe("ok");
		const head = await fetch(`${base()}/_healthcheck`, { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
	});
});

/** The security headers every answer carries, the policy apart. */
const securityHeaders = {
	"cross-origin-opener-policy": "same-origin",
	"cross-origin-resource-policy": "same-origin",
	"origin-agent-cluster": "?1",
	"referrer-policy": "no-referrer",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"x-content-type-options": "nosniff",
	"x-dns-prefetch-control": "off",
	"x-download-options": "noopen",
	"x-frame-options": "SAMEORIGIN",
	"x-permitted-cross-domain-policies": "none",
	"x-xss-protection": "0",
};

/** The policy every answer carries, by directive. */
const policy = {
	"default-src": ["'none'"],
	"base-uri": ["'self'"],
	"font-src": ["'self'", "https:", "data:"],
	"form-action": ["'self'"],
	"frame-ancestors": ["'none'"],
	"img-src": ["'self'", "data:"],
	"object-src": ["'none'"],
	"script-src": ["'self'"],
	"script-src-attr": ["'none'"],
	"style-src": ["'self'", "https:", "'unsafe-inline'"],
	"upgrade-insecure-requests": [],
};

/** A policy's directives by name, each with its sources; the order of directives is not compared. */
function directives(text: string | null) {
	return Object.fromEntries(
		(text ?? "")
			.split(";")
			.map((d) => d.trim().split(/\s+/))
			.filter(([name]) => name)
			.map(([name, ...sources]) => [name, sources]),
	);
}

describe("Q. security headers", () => {
	const base = running(scene);

	it("go on every answer, with a policy that loads nothing by default and lets no one frame it", async () => {
		const asked: [string, RequestInit, number][] = [
			["/_healthcheck", {}, 200],
			["/_healthcheck", { method: "HEAD" }, 200],
			["/readyz", {}, 200],
			[jwksPath, {}, 200],
		];
		for (const [path, init, status] of asked) {
			const res = await fetch(`${base()}${path}`, init);
			await res.arrayBuffer();
			const got = Object.fromEntries(
				Object.keys(securityHeaders).map((name) => [name, res.headers.get(name)]),
			);
			expect([path, res.status, got]).toEqual([path, status, securityHeaders]);
			expect(directives(res.headers.get("content-security-policy"))).toEqual(policy);
		}
	});

	it("go on the answer to a path nothing serves, its policy loading nothing by default", async () => {
		const res = await fetch(`${base()}/p${randomBytes(8).toString("hex")}`);
		await res.arrayBuffer();
		expect(res.status).toBe(404);
		for (const [name, value] of Object.entries(securityHeaders)) {
			expect([name, res.headers.get(name)]).toEqual([name, value]);
		}
		expect(directives(res.headers.get("content-security-policy"))["default-src"]).toEqual([
			"'none'",
		]);
	});
});

/** The last readiness status of up to 50 tries, 200 ms apart, stopping at the first 200. */
async function readyzSettles(base: string): Promise<number> {
	for (let i = 0; ; i++) {
		const { status } = await fetch(`${base}/readyz`);
		if (status === 200 || i === 49) return status;
		await new Promise((r) => setTimeout(r, 200));
	}
}

describe("Q. liveness and readiness with the store unreachable", () => {
	const faulty = faultyTarget(scene);

	it("answers readiness 200 and ready when the store answers, never to be cached", async () => {
		const res = await fetch(`${faulty.base()}/readyz`);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toContain("no-store");
		expect(((await res.json()) as { status: string }).status).toBe("ready");
	});

	it("keeps liveness 200 and turns readiness 503, soon and saying nothing of what failed", async () => {
		const port = new URL(faulty.base()).port;
		await faulty.whileDown(async () => {
			expect((await fetch(`${faulty.base()}/_healthcheck`)).status).toBe(200);
			const asked = Date.now();
			const res = await fetch(`${faulty.base()}/readyz`);
			expect(Date.now() - asked).toBeLessThan(3000);
			expect(res.status).toBe(503);
			expect(res.headers.get("cache-control")).toContain("no-store");
			const text = await res.text();
			expect((JSON.parse(text) as { status: string }).status).toBe("unready");
			for (const detail of ["127.0.0.1", "localhost", "ECONN", "Error", "timeout", port]) {
				expect(text).not.toContain(detail);
			}
		});
	});

	// Follows the scene above, which took the store down and brought it back.
	it("answers readiness 200 again once the store is back", async () => {
		expect(await readyzSettles(faulty.base())).toBe(200);
	});
});

describe("Q. the dependency gauge with the store unreachable", () => {
	const faulty = faultyTarget(scene);
	/** The store's series of the dependency gauge at a scrape: its labels and value. */
	const store = async () => {
		const res = await fetch(`${faulty.base()}/metrics`);
		expect(res.status).toBe(200);
		return samples(await res.text()).find(
			(s) => s.name === "auth_dependency_up" && s.labels.dependency === "redis",
		);
	};

	it("reads 0 for the store once readiness turns unready, and 1 once it is ready again", async () => {
		await faulty.whileDown(async () => {
			expect((await fetch(`${faulty.base()}/readyz`)).status).toBe(503);
			const down = await store();
			expect([Object.keys(down?.labels ?? {}), down?.value]).toEqual([["dependency"], "0"]);
		});
		expect(await readyzSettles(faulty.base())).toBe(200);
		expect((await store())?.value).toBe("1");
	});
});

describe("Q. metrics", () => {
	const base = running(scene);
	const scrape = async () => {
		const res = await fetch(`${base()}/metrics`);
		expect(res.status).toBe(200);
		return { res, text: await res.text() };
	};

	it("publishes the request time by method, route and status, and the process defaults, as Prometheus text", async () => {
		expect((await fetch(`${base()}${jwksPath}`)).status).toBe(200);
		const { res, text } = await scrape();
		// The media type and its version, in whatever order the parameters come.
		const [type, ...parameters] = (res.headers.get("content-type") ?? "").split(/\s*;\s*/);
		expect(type).toBe("text/plain");
		expect(parameters).toContain("version=0.0.4");
		expect(res.headers.get("cache-control")).toContain("no-store");
		expect(text).toContain("# TYPE http_request_duration_seconds histogram");
		const all = samples(text);
		const asked = `GET ${jwksPath} 200`;
		for (const suffix of ["_sum", "_count"]) {
			expect(durations(all, suffix).map(seriesKey)).toContain(asked);
		}
		const buckets = durations(all, "_bucket").filter((s) => seriesKey(s) === asked);
		expect(buckets.map((s) => s.labels.le)).toContain("+Inf");
		expect(all.map((s) => s.name)).toContain("auth_provider_process_cpu_user_seconds_total");
	});

	it("keeps unknown methods and unrouted paths in the other and unmatched series", async () => {
		const tokens = Array.from({ length: 5 }, () => `p${randomBytes(8).toString("hex")}`);
		for (const token of tokens) await fetch(`${base()}/${token}`);
		await fetch(`${base()}/${tokens[0]}`, { method: "PROPFIND" });
		const { text } = await scrape();
		for (const token of tokens) expect(text).not.toContain(token);
		const series = durations(samples(text), "_count");
		expect(series.map(seriesKey)).toContain("GET unmatched 404");
		expect(series.filter((s) => s.labels.method === "other").map((s) => s.labels.route)).toEqual([
			"unmatched",
		]);
		for (const s of series) expect([...methods, "other"]).toContain(s.labels.method);
	});

	it("puts no secret and no user's value sent in a request into the scrape [guarantee-8-d]", async () => {
		const secret = `s${randomBytes(12).toString("hex")}`;
		const user = `u${randomBytes(6).toString("hex")}@example.com`;
		await fetch(
			`${base()}${jwksPath}?client_secret=${secret}&username=${encodeURIComponent(user)}`,
			{
				headers: { authorization: `Bearer ${secret}`, cookie: `sid=${secret}` },
			},
		);
		const { text } = await scrape();
		for (const value of [secret, user, encodeURIComponent(user)]) {
			expect(text).not.toContain(value);
		}
	});
});

describe.runIf(driver.can(scrapePathSetting))("O. refusals about the operations routes", () => {
	let started: Started | undefined;
	afterEach(async () => {
		if (started?.kind === "running") await started.stop();
		started = undefined;
	});

	it("refuses a scrape path that does not start with /, without printing it [guarantee-8-a]", async () => {
		started = await driver.start(
			sceneOf(keysArea.part({ signing: signing() }), opsArea.part({ scrapePath: "zq9-scrape" })),
		);
		expect(started.kind).toBe("refused");
		const output = started.kind === "refused" ? started.output : "";
		expect(output).toContain("metrics-prometheus");
		expect(output).not.toContain("zq9-scrape");
	});
});

describe("O. the log level", () => {
	let started: Started | undefined;
	afterEach(async () => {
		if (started?.kind === "running") await started.stop();
		started = undefined;
	});
	const at = (logLevel: string) =>
		driver.start(sceneOf(keysArea.part({ signing: signing() }), opsArea.part({ logLevel })));

	it("boots with a level it knows, and refuses to boot with one it does not", async () => {
		started = await at("warn");
		expect(started.kind).toBe("running");
		if (started.kind === "running") await started.stop();
		started = await at("loudest");
		expect(started.kind).toBe("refused");
	});
});

const limited = oauthScene({
	issuer: "https://issuer.example",
	keys: { signing: signing() },
	clients: [
		{
			id: "app",
			kind: "confidential",
			method: "client_secret_post",
			secret: "app-secret-0123456789abcdef",
			// Its requests fail authentication before any grant is read; the grant is the one the
			// token endpoint asks to be composed at all.
			grants: ["client_credentials"],
			scopes: ["read"],
		},
	],
});

describe("Q. the operations routes and request counting", () => {
	const base = running({
		...limited,
		parts: { ...limited.parts, ...sceneOf(opsArea.part({})).parts },
	});

	it("answers without credentials, and leaves the token endpoint's limit as it was [rfc6749-2.3.1-c] [guarantee-10-a]", async () => {
		// token-endpoint's default: 60 requests per source in a 60 s window, counted in fixed windows,
		// so a window turning over inside this scene could fail it or let it pass wrongly.
		const tokenLimit = 60;
		// More than the limit, so any of these counted against it would show as an early 429.
		const opsRequests = tokenLimit + 10;
		for (const path of ["/_healthcheck", "/readyz", "/metrics"]) {
			for (let i = 0; i < opsRequests; i++) {
				const res = await fetch(`${base()}${path}`, {
					headers: i % 2 === 0 ? {} : { authorization: "Bearer not-a-token" },
				});
				expect(res.status).toBe(200);
				await res.arrayBuffer();
			}
		}
		const post = () =>
			fetch(`${base()}/oauth/token`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "client_credentials",
					client_id: "app",
					client_secret: "wrong",
				}),
			});
		for (let i = 0; i < tokenLimit; i++) expect((await post()).status).toBe(401);
		expect((await post()).status).toBe(429);
	});
});
