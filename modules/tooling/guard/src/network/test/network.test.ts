import { describe, expect, it } from "vitest";
import type { Pkg } from "../../../src/workspace.ts";
import { budget, pkg } from "../../../test/workspace.ts";
import { check } from "../../contract.ts";

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

	it("counts no type-only import, no function that never reaches the network, no local fetch, and no test", () => {
		const p = pkg("@t/quiet", {
			"src/a.ts":
				'import type { Socket } from "node:net";\nimport { type Server } from "node:http";\nimport { isIP, BlockList } from "node:net";\nexport type A = Socket | Server;\nexport const a = [isIP, BlockList];\n',
			"src/b.ts": "export const b = (fetch: (u: string) => unknown) => fetch('x');\n",
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
