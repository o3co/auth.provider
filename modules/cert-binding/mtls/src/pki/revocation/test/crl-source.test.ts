import * as x509Path from "@mod/x509-path";
import { crlOf, type Issued, issue } from "@mod/x509-path/testing";
import { expect, it, vi } from "vitest";
import type { Fetched } from "../../contract.ts";
import { revocationOver } from "../revocation.ts";

// Each verification of a CRL, counted: a CRL is verified once as it is fetched, not at each check.
const verified = vi.hoisted(() => ({ count: 0, aborting: false, signals: [] as unknown[] }));
vi.mock("@mod/x509-path", async (original) => {
	const real = await original<typeof import("@mod/x509-path")>();
	return {
		...real,
		verifyCrl: (...args: Parameters<typeof real.verifyCrl>) => {
			verified.count++;
			verified.signals.push(args[5]);
			if (verified.aborting) return Promise.resolve({ kind: "aborted" });
			return real.verifyCrl(...args);
		},
	};
});

it("verifies a CRL once as it is fetched, and judges what it kept for each certificate after", async () => {
	const root = await issue({ cn: "root", ca: true });
	const [one, two, three] = (await Promise.all(
		["one", "two", "three"].map((cn) => issue({ cn, by: root, crl: "http://root.example/crl" })),
	)) as [Issued, Issued, Issued];
	const crl = await crlOf({ by: root, revoked: [two] });
	const revocation = revocationOver(
		{
			mode: "crl",
			nonce: true,
			skewMs: 300_000,
			ocspFreshMs: 600_000,
			crlTtlMs: 3_600_000,
			failureMs: 30_000,
			timeoutMs: 3000,
			crlEntries: 4,
			ocspEntries: 4,
			maxFetches: 4,
			minRsaBits: 2048,
			signatureAlgorithms: x509Path.signatureAlgorithms,
		},
		{
			fetch: async (): Promise<Fetched> => ({ kind: "material", body: crl }),
			now: () => Date.now(),
			random: (n) => new Uint8Array(n),
		},
	);
	const check = (client: Issued) => revocation.check([client.certificate, root.certificate]);
	expect(await check(one)).toEqual({ kind: "good" });
	expect(await check(two)).toEqual({ kind: "revoked" });
	expect(await check(three)).toEqual({ kind: "good" });
	expect(verified.count).toBe(1);
});

it("is an outage, as a fetch past its time is, where a fetched CRL gets no turn to be read within a fetch's time, and remembers nothing of it", async () => {
	const root = await issue({ cn: "root", ca: true });
	const client = await issue({ cn: "client", by: root, crl: "http://root.example/crl" });
	const crl = await crlOf({ by: root });
	const revocation = revocationOver(
		{
			mode: "crl",
			nonce: true,
			skewMs: 300_000,
			ocspFreshMs: 600_000,
			crlTtlMs: 3_600_000,
			failureMs: 30_000,
			timeoutMs: 3000,
			crlEntries: 4,
			ocspEntries: 4,
			maxFetches: 4,
			minRsaBits: 2048,
			signatureAlgorithms: x509Path.signatureAlgorithms,
		},
		{
			fetch: async (): Promise<Fetched> => ({ kind: "material", body: crl }),
			now: () => Date.now(),
			random: (n) => new Uint8Array(n),
		},
	);
	const check = () => revocation.check([client.certificate, root.certificate]);
	// The turn's wait ended by the fetch's time, as x509-path answers it.
	verified.aborting = true;
	expect(await check()).toEqual({ kind: "outage", reason: "unreachable" });
	verified.aborting = false;
	expect(verified.signals.every((signal) => signal instanceof AbortSignal)).toBe(true);
	// Nothing was remembered: the next check reads the CRL.
	expect(await check()).toEqual({ kind: "good" });
});
