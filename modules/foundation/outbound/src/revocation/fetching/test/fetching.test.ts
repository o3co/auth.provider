import * as x509Path from "@mod/x509-path";
import { expect, it, vi } from "vitest";
import { keptOver } from "../../kept/kept.ts";
import type { Certificate } from "../../trust.ts";
import { crlsOver } from "../fetching.ts";

// A CRL's reading, settled by the test: the abort lands while it is read, as nothing else can place it.
const reading = vi.hoisted(() => ({ settle: (_: unknown) => {}, started: 0 }));
vi.mock("@mod/x509-path", async (original) => ({
	...(await original<typeof import("@mod/x509-path")>()),
	verifyCrl: () => {
		reading.started++;
		return new Promise((settle) => {
			reading.settle = settle;
		});
	},
}));

it("remembers nothing of a CRL read after the check that started it ended, so the next check fetches again", async () => {
	const fetched: string[] = [];
	const crls = crlsOver(keptOver(8), {
		fetch: async (url) => {
			fetched.push(url);
			return new Uint8Array([1, 2, 3]);
		},
		inBackground: () => {},
		now: () => 0,
		failureMs: 30_000,
		crlTtlMs: 3_600_000,
	});
	const issuer = {} as Certificate;
	const starting = new AbortController();
	const started = crls.crlFor("issuer", issuer, ["http://crl.example/a.crl"], starting.signal);
	while (reading.started === 0) await new Promise((tick) => setTimeout(tick, 1));
	starting.abort();
	reading.settle({ kind: "unusable", reason: "malformed" });
	expect(await started).toBe("unreachable");
	const next = crls.crlFor(
		"issuer",
		issuer,
		["http://crl.example/a.crl"],
		new AbortController().signal,
	);
	while (reading.started === 1) await new Promise((tick) => setTimeout(tick, 1));
	reading.settle({ kind: "unusable", reason: "malformed" });
	expect(await next).toBe("malformed");
	expect(fetched).toHaveLength(2);
	expect(x509Path.verifyCrl).toBeDefined();
});
