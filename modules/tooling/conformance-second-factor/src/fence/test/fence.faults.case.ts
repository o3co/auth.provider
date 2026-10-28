import { randomBytes } from "node:crypto";
import {
	type Deployed,
	type Instance,
	instanceOf,
	ready,
	recovered,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { type Browser, faultScene, heldAt, on, usedAt } from "../../faults/test/faults.ts";
import { boundaryRead, factorListWritten } from "../../faults/test/wire.ts";
import { beginBinding, browser, totp } from "../../testing.ts";

// Each scene races a change to the user's second factors with her revocation, from two instances. At
// B, a session opened before the revocation asks the change: the request passes the session's checks
// (each reads her boundary) and reads her factor list, and its one write to the list is held. At A,
// the revocation is answered complete, its follower mfa-revocation having moved her fence in that
// list. Let go, B's write finds the list changed, decides again on the fence moved, and is refused:
// nothing changes. This is where the fence holds; a request sent after the revocation is refused
// before, as her sessions are closed, which proves nothing of the fence.

const credential = randomBytes(32).toString("base64url");
const subject = "alice";
const scene = faultScene({ credential, sources: ["198.51.100.0/24"] });
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The ledger's revocation of alice at the instance, from its block over https, as its proxy forwards it. */
async function revokeAt(i: Instance) {
	const res = await fetch(`${i.baseUrl}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject }),
	});
	return {
		status: res.status,
		body: (await res.json().catch(() => ({}))) as Record<string, unknown>,
	};
}

/** Alice's TOTP and recovery codes, bound at the instance. */
async function enrolledAt(i: Instance) {
	const b = browser(() => i.baseUrl);
	expect((await b.login(subject)).status).toBe(200);
	const begun = await beginBinding(b, { kind: "totp" }, undefined);
	const done = await b.send("POST", "/session/mfa/enrollment/complete", {
		transaction_id: String(begun.body.transaction),
		proof: totp(String(begun.body.secret)),
	});
	expect(done.status).toBe(200);
	return { secret: String(begun.body.secret), codes: [...(done.body.recovery_codes as string[])] };
}

/** A session of alice's at the instance, let in by a recovery code: its browser, and the factors her login listed. */
async function signedInAt(i: Instance, code: string) {
	const { b, transaction } = await heldAt(i);
	const factors = await b.factors(transaction);
	expect((await usedAt(b, transaction, code)).status).toBe(200);
	return { b, factors };
}

/** The change asked at B held at its write to the factor list, once its session's checks have read the boundary. */
async function heldAtWrite(
	b: Instance,
	ask: () => Promise<{ status: number; body: Record<string, unknown> }>,
) {
	const from = performance.now();
	const holding = b.relay.hold(factorListWritten);
	const asked = ask();
	const held = await holding;
	const heldWhen = performance.now();
	// Past the session's checks: each read her boundary before the write was sent.
	expect(successes(b, boundaryRead(subject)).some((e) => e.at > from && e.at < heldWhen)).toBe(
		true,
	);
	return { held, asked, from };
}

/** At A, alice's revocation answered complete, her fence moved by its follower. */
async function revokedAt(a: Instance) {
	const r = await revokeAt(a);
	expect([r.status, r.body.complete]).toEqual([200, true]);
}

/** Refused at B, the held write let go: not done, and no write of B's to the list succeeded since. */
function refusedAt(
	b: Instance,
	from: number,
	answer: { status: number; body: Record<string, unknown> },
) {
	expect(answer.status).not.toBe(200);
	expect(answer.body.recovery_codes).toBeUndefined();
	expect(successes(b, factorListWritten).filter((e) => e.at > from)).toEqual([]);
}

/** After the revocation: the topology recovered, past the boundary's second (compared in seconds), a new login. */
async function afterAt(d: Deployed, i: Instance, code: string) {
	await recovered(d);
	await ready(i);
	await pause(1_100);
	return signedInAt(i, code);
}

/** The control: with no fault, B's session reissues her recovery codes; answers the ones it gave. */
async function control(b: Browser, i: Instance) {
	const from = performance.now();
	const reissued = await b.send("POST", "/session/mfa/recovery-codes");
	expect(reissued.status).toBe(200);
	expect(successes(i, factorListWritten).filter((e) => e.at > from).length).toBeGreaterThan(0);
	return [...(reissued.body.recovery_codes as string[])];
}

describe("a subject's fence refusing, from another instance, a change to her second factors her revocation overtook", () => {
	it("removes no factor for a session opened before a revocation completed at another instance [guarantee-4-d] {fault:H2}", async () => {
		await on({ name: "fence-remove-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const { codes } = await enrolledAt(a);
			const { b: browserB, factors } = await signedInAt(b, codes[0] ?? "");
			const codesNow = await control(browserB, b);
			// A second TOTP, so the one removed is not the last.
			const added = await beginBinding(browserB, { kind: "totp" }, undefined);
			const bound = await browserB.send("POST", "/session/mfa/enrollment/complete", {
				transaction_id: String(added.body.transaction),
				proof: totp(String(added.body.secret)),
			});
			expect(bound.status).toBe(200);
			const factor = factors.find((f) => f.kind === "totp")?.id ?? "";
			const { held, asked, from } = await heldAtWrite(b, () =>
				browserB.send("POST", "/session/mfa/factors/remove", { factor_id: factor }),
			);
			await revokedAt(a);
			held.release();
			refusedAt(b, from, await asked);
			// Her factor is still there.
			const after = await afterAt(d, a, codesNow[0] ?? "");
			expect(after.factors.map((f) => f.id)).toContain(factor);
		});
	});

	it("reissues no recovery codes for a session opened before a revocation completed at another instance [guarantee-4-d] {fault:H2}", async () => {
		await on({ name: "fence-reissue-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const { codes } = await enrolledAt(a);
			const { b: browserB } = await signedInAt(b, codes[0] ?? "");
			const codesNow = await control(browserB, b);
			const { held, asked, from } = await heldAtWrite(b, () =>
				browserB.send("POST", "/session/mfa/recovery-codes"),
			);
			await revokedAt(a);
			held.release();
			refusedAt(b, from, await asked);
			// The codes before still let her in: none were reissued.
			await afterAt(d, a, codesNow[0] ?? "");
		});
	});

	it("binds no factor whose enrollment a session began before a revocation completed at another instance [guarantee-4-d] {fault:H2}", async () => {
		await on({ name: "fence-bind-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const { codes } = await enrolledAt(a);
			const { b: browserB, factors } = await signedInAt(b, codes[0] ?? "");
			const codesNow = await control(browserB, b);
			const begun = await beginBinding(browserB, { kind: "totp" }, undefined);
			const { held, asked, from } = await heldAtWrite(b, () =>
				browserB.send("POST", "/session/mfa/enrollment/complete", {
					transaction_id: String(begun.body.transaction),
					proof: totp(String(begun.body.secret)),
				}),
			);
			await revokedAt(a);
			held.release();
			refusedAt(b, from, await asked);
			// Her TOTP is the one she had: the enrollment begun before is not bound. (The recovery codes'
			// factor is renamed by the control's reissue, so it is not compared.)
			const after = await afterAt(d, a, codesNow[0] ?? "");
			const totps = (fs: readonly { id: string; kind: string }[]) =>
				fs.filter((f) => f.kind === "totp").map((f) => f.id);
			expect(totps(after.factors)).toEqual(totps(factors));
		});
	});
});
