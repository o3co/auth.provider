import type { Pkg } from "@mod/guard-imports";
import { describe, expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { check } from "../../contract.ts";
import { reachesOf } from "../network.ts";

// Each case checks a package, its sources bound by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

/** What G26 says of a package, as `where detail`. */
const said = (p: Pkg) =>
	check([p], budget)
		.filter((v) => v.rule.startsWith("G26"))
		.map((v) => `${v.where.replace(`${p.name}/`, "")} ${v.detail}`);
const declaring = (p: Pkg, card: string) => ({ ...p, card: `# ${p.name}\n\n${card}\n` });

describe("G26 the network is reached through outbound, or as a package declares", () => {
	it("refuses shipped code that connects, serves or fetches without a declaration", () => {
		const p = pkg("@t/reach", {
			"src/a.ts": 'import { request } from "node:https";\nexport const a = request;\n',
			"src/b.ts": 'import * as net from "node:net";\nexport const b = net;\n',
			"src/c.ts": "export const c = () => fetch('https://x.example');\n",
			"src/d.ts": 'import Redis from "ioredis";\nexport const d = Redis;\n',
		});
		expect(said(p)).toEqual([
			"src/a.ts node:https request",
			"src/b.ts node:net",
			"src/c.ts fetch",
			"src/d.ts ioredis",
		]);
	});

	it("refuses the network reached by a dynamic import, a global's property, a resolver or a process", () => {
		const p = pkg("@t/around", {
			"src/a.ts": 'export const a = async () => (await import("node:https")).request;\n',
			"src/b.ts": "export const b = (name: string) => import(name);\n",
			"src/c.ts": "export const c = () => globalThis.fetch('https://x.example');\n",
			"src/d.ts": "export const d = fetch;\n",
			"src/e.ts": 'import { lookup } from "node:dns/promises";\nexport const e = lookup;\n',
			"src/f.ts": 'import { spawn } from "node:child_process";\nexport const f = spawn;\n',
			"src/g.ts": 'export const g = async () => (await import("undici")).request;\n',
			"src/i.ts": "export const i = () => globalThis[\"fetch\"]('https://x.example');\n",
			"src/h.ts":
				"export const local = (fetch: () => void) => fetch();\nexport const h = () => fetch('https://x.example');\n",
		});
		expect(said(p)).toEqual([
			"src/a.ts node:https",
			"src/b.ts import()",
			"src/c.ts fetch",
			"src/d.ts fetch",
			"src/e.ts node:dns/promises lookup",
			"src/f.ts node:child_process (forks does not name it)",
			"src/g.ts undici",
			"src/i.ts fetch",
			"src/h.ts fetch",
		]);
	});

	it("counts no type-only import, no function that never reaches the network, no local fetch, and no test", () => {
		const p = pkg("@t/quiet", {
			"src/a.ts":
				'import type { Socket } from "node:net";\nimport { type Server } from "node:http";\nimport { isIP, BlockList } from "node:net";\nexport type A = Socket | Server;\nexport const a = [isIP, BlockList];\n',
			"src/b.ts":
				"export const b = (fetch: (u: string) => unknown) => fetch('x');\nexport interface Source { fetch(url: string): Promise<unknown>; }\nexport const s = { fetch: () => 1, async get() { return this.fetch(); } };\nexport type F = typeof fetch;\nconst self = { fetch: () => 1 };\nexport const t = () => [self.fetch(), self[\"fetch\"]()];\n",
			"test/c.test.ts":
				'import { createServer } from "node:http";\nexport const c = createServer;\n',
		});
		expect(said(p)).toEqual([]);
		const tool = pkg(
			"@t/tool",
			{ "src/a.ts": 'import { createServer } from "node:net";\nexport const a = createServer;\n' },
			undefined,
			"verification",
		);
		expect(said(tool)).toEqual([]);
	});

	it("takes what a declared word covers, stated on the card, and nothing past it", () => {
		const files = {
			"src/a.ts": 'import { connect } from "node:tls";\nexport const a = connect;\n',
		};
		const manifest = { exports: { ".": "./src/contract.ts" }, network: "outbound" };
		expect(
			said(declaring(pkg("@t/out", files, manifest), "- Reaches out (`network`: `outbound`).")),
		).toEqual([]);
		expect(said(pkg("@t/unstated", files, manifest))).toEqual([
			"@t/unstated card states `network`: `outbound`",
		]);
		const served = {
			"src/a.ts": 'import { createServer } from "node:http";\nexport const a = createServer;\n',
		};
		expect(said(declaring(pkg("@t/past", served, manifest), "- (`network`: `outbound`)"))).toEqual([
			"src/a.ts node:http createServer",
			"@t/past outbound reaches nothing here",
		]);
	});

	it("refuses a word it does not know, and takes several words in a list", () => {
		const files = {
			"src/a.ts":
				'import { connect } from "node:net";\nimport Mail from "nodemailer/lib/smtp-connection";\nexport const a = [connect, Mail];\n',
		};
		const unknown = { exports: { ".": "./src/contract.ts" }, network: "carrier-pigeon" };
		expect(
			said(declaring(pkg("@t/odd", files, unknown), "- (`network`: `carrier-pigeon`)")),
		).toEqual([
			"@t/odd network carrier-pigeon is no word guard knows",
			"src/a.ts node:net connect",
			"src/a.ts nodemailer",
		]);
		const both = { exports: { ".": "./src/contract.ts" }, network: ["smtp"] };
		expect(said(declaring(pkg("@t/mail", files, both), "- (`network`: `smtp`)"))).toEqual([]);
	});
});

describe("G27 a package that talks to a server the deployment provides states that server under Deployment", () => {
	const g27 = (p: Pkg) =>
		check([p], budget)
			.filter((v) => v.rule.startsWith("G27"))
			.map((v) => `${v.where} ${v.detail}`);
	const files = {
		"src/a.ts": 'import Redis from "ioredis";\nexport const a = Redis;\n',
	};
	const manifest = { exports: { ".": "./src/contract.ts" }, network: "redis" };

	it("refuses a card without a Deployment section where a declared word reaches such a server", () => {
		expect(g27(declaring(pkg("@t/store", files, manifest), "- (`network`: `redis`)"))).toEqual([
			"@t/store card has no `## Deployment` section",
		]);
	});

	it("takes the section, and asks it of no word whose reach the deployment does not provide", () => {
		const stated = "## Invariants\n- (`network`: `redis`)\n\n## Deployment\n- Redis.";
		expect(g27(declaring(pkg("@t/store", files, manifest), stated))).toEqual([]);
		const out = {
			"src/a.ts": 'import { connect } from "node:tls";\nexport const a = connect;\n',
		};
		const outbound = { exports: { ".": "./src/contract.ts" }, network: "outbound" };
		expect(g27(declaring(pkg("@t/out", out, outbound), "- (`network`: `outbound`)"))).toEqual([]);
	});
});

describe("a re-export", () => {
	it("reaches what it re-exports, named or whole", () => {
		const p = pkg("@t/re-export", {
			"src/a.ts": 'export { request } from "node:https";\n',
			"src/b.ts": 'export * from "node:net";\n',
			"src/c.ts": 'export { exec } from "child_process";\n',
			"src/d.ts": 'export { default as Redis } from "ioredis";\n',
			"src/e.ts": 'export type { Socket } from "node:net";\n',
			"src/f.ts": 'export { default as https } from "node:https";\n',
			"src/g.ts": 'export { type ChildProcess } from "node:child_process";\n',
			"src/h.ts": 'export { type RedisOptions } from "ioredis";\n',
			"src/i.ts": 'import { type RedisOptions } from "ioredis";\nexport type R = RedisOptions;\n',
		});
		expect(said(p)).toEqual([
			"src/a.ts node:https request",
			"src/b.ts node:net",
			"src/c.ts node:child_process (forks does not name it)",
			"src/d.ts ioredis",
			"src/f.ts node:https",
		]);
	});
});

describe("a source written as .mjs", () => {
	it("is read for what it reaches, as a .ts file is", () => {
		const p = pkg("@t/mjs-reach", {
			"src/helper.mjs":
				'import { request } from "node:https";\nexport const go = () => request("https://x.example");\nfetch("https://y.example");\n',
		});
		expect(reachesOf(`${p.dir}/src/helper.mjs`)).toEqual(["node:https request", "fetch"]);
	});
});
