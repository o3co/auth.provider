import { createHash } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { passkeyHolders, passkeyStore, passkeys, registrations } from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { passkeysConfig } from "@mod/passkeys/testing";
import { simulatedStore } from "@mod/store/testing";
import { revocations, subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import webauthnStore from "@mod/webauthn-store/module";
import { afterEach, describe, expect, it } from "vitest";
import { resetOver } from "../src/reset.ts";

/** The kernel's clock, set by each step; a second starts at `S`. */
const S = Math.ceil(Date.now() / 1000) * 1000 + 10_000;
let now = S;
const runtime = quietRuntime({ clock: { now: () => now } });
let stop = async () => {};
afterEach(() => stop());

const T1 = S + 100;
const T2 = S + 2100;
type Step = () => Promise<void>;

/**
 * passkeys and subject-revocation composed, and a reset over them as the module wires it, its steps
 * timed: the first boundary at `T1`, the second at `T2`, and `afterFirst`, `afterRemoval` run between.
 */
async function composed() {
	const store = simulatedStore();
	const app = await assemble({
		modules: [
			store.module,
			webauthnStore,
			webauthn,
			passkeysModule,
			subjectRevocationStandIn,
			auditStandIn().module,
		],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const between: { afterFirst?: Step; afterRemoval?: Step } = {};
	const recorded = app.get(revocations);
	const holders = app.get(passkeyHolders);
	let boundaries = 0;
	const { reset } = resetOver({
		revocations: {
			record: async (subject, options) => {
				boundaries += 1;
				now = boundaries % 2 === 1 ? T1 : T2;
				const answer = await recorded.record(subject, options);
				if (boundaries % 2 === 1) await between.afterFirst?.();
				return answer;
			},
		},
		holders: {
			cleared: async (subject) => {
				const answer = await holders.cleared(subject);
				await between.afterRemoval?.();
				return answer;
			},
		},
		audit: { record: () => {} },
		log: recordingLog().log,
	});
	const regs = app.get(registrations);
	const revocation = app.get(subjectRevocation);
	const keys = new Map<string, ReturnType<typeof softwareAuthenticator>>();
	/**
	 * A registration whose challenge is made at `c`, its asks as `passkey-registration` makes them. It
	 * holds at `hold` (before its second ask, or after it passed) until `go` lets it on.
	 */
	const registering = async (c: number, hold?: "beforeSecond" | "afterSecond") => {
		now = c;
		const options = (await regs.creation("sam")).options as CreationOptions;
		const authenticator = softwareAuthenticator();
		const response = authenticator.create(options, { origin: testOrigin });
		keys.set(response.id, authenticator);
		let asks = 0;
		let reached = () => {};
		const held = new Promise<void>((resolve) => {
			reached = resolve;
		});
		let release = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const answer = regs.register("sam", response, undefined, async (challengedAt) => {
			asks += 1;
			if (asks === 2 && hold === "beforeSecond") {
				reached();
				await gate;
			}
			const valid = (await revocation.check("sam", challengedAt)) === "valid";
			if (asks === 2 && hold === "afterSecond" && valid) {
				reached();
				await gate;
			}
			return valid;
		});
		if (hold) await held;
		return {
			id: response.id,
			asks: () => asks,
			go: async () => {
				release();
				return answer;
			},
			answer,
		};
	};
	/** Whether a passkey with `id` logs in. */
	const logsIn = async (id: string) => {
		const options = (await app.get(passkeys).challenge({ by: "test", id: "app" }))
			.options as RequestOptions;
		const response = keys.get(id)?.get(options, { origin: testOrigin });
		return (
			(await app.get(passkeys).assert(response, { by: "test", id: "app" })).kind === "asserted"
		);
	};
	const listed = async () => (await regs.listed("sam")).map((p) => p.id);
	// Read raw, under the keys passkeys keeps them by: what no read of passkeys hides, a pending record included.
	const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
	const raw = app.get(passkeyStore);
	const kept = async (id: string) => ({
		listed: (
			((await raw.subjects.read(`s-${hashOf("sam")}`)) as { credentials?: string[] } | undefined)
				?.credentials ?? []
		).includes(id),
		record: await raw.credentials.read(`c-${hashOf(id)}`),
	});
	/** Whether any write the store ever took carried the id: listed, or under its record's key, even if undone after. */
	const everWritten = (id: string) => store.holds(id) || store.holds(`c-${hashOf(id)}`);
	return {
		between,
		reset: () => reset.reset("sam"),
		registering,
		logsIn,
		listed,
		kept,
		everWritten,
	};
}

const kindOf = (answer: { readonly kind: string; readonly reason?: string }) =>
	answer.kind === "registered" ? "registered" : answer.reason;

describe("a registration racing a passkey reset, by the second its challenge was made in", () => {
	it("row 1: one challenged before the first boundary whose second ask sees it is revoked", async () => {
		const p = await composed();
		const r = await p.registering(S + 50, "beforeSecond");
		p.between.afterFirst = async () => {
			expect(kindOf(await r.go())).toBe("revoked");
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 0 });
		expect(await p.listed()).toEqual([]);
	});

	it("row 1: one admitted twice and activated before the removal is removed by it", async () => {
		const p = await composed();
		const r = await p.registering(S + 50);
		expect(kindOf(await r.answer)).toBe("registered");
		expect(await p.reset()).toEqual({ kind: "done", removed: 1 });
		expect(await p.listed()).toEqual([]);
		expect(await p.logsIn(r.id)).toBe(false);
	});

	it("row 1: one admitted twice before the first boundary and activated after the removal is a conflict", async () => {
		const p = await composed();
		const r = await p.registering(S + 50, "afterSecond");
		p.between.afterRemoval = async () => {
			expect(kindOf(await r.go())).toBe("conflict");
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 1 });
		expect(await p.listed()).toEqual([]);
	});

	it("row 1, the same second: one challenged after the first boundary within its second is refused at its first ask, nothing written", async () => {
		const p = await composed();
		let asks = 0;
		let id = "";
		p.between.afterFirst = async () => {
			const r = await p.registering(T1 + 50);
			expect(kindOf(await r.answer)).toBe("revoked");
			asks = r.asks();
			id = r.id;
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 0 });
		expect(asks).toBe(1);
		expect(p.everWritten(id)).toBe(false);
		expect(await p.kept(id)).toEqual({ listed: false, record: undefined });
	});

	it("row 2: one written before the removal and activated before it is removed by it", async () => {
		const p = await composed();
		let id = "";
		p.between.afterFirst = async () => {
			const r = await p.registering(S + 1200);
			expect(kindOf(await r.answer)).toBe("registered");
			id = r.id;
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 1 });
		expect(await p.listed()).toEqual([]);
		expect(await p.logsIn(id)).toBe(false);
	});

	it("row 2: one written and admitted before the removal, activated after it, is a conflict", async () => {
		const p = await composed();
		let r: Awaited<ReturnType<typeof p.registering>> | undefined;
		p.between.afterFirst = async () => {
			r = await p.registering(S + 1200, "afterSecond");
		};
		p.between.afterRemoval = async () => {
			expect(kindOf((await r?.go()) ?? { kind: "none" })).toBe("conflict");
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 1 });
		expect(await p.listed()).toEqual([]);
	});

	it("row 2: one written before the removal whose second ask comes after the second boundary is revoked", async () => {
		const p = await composed();
		let r: Awaited<ReturnType<typeof p.registering>> | undefined;
		p.between.afterFirst = async () => {
			r = await p.registering(S + 1200, "beforeSecond");
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 1 });
		expect(kindOf((await r?.go()) ?? { kind: "none" })).toBe("revoked");
		expect(await p.listed()).toEqual([]);
	});

	it("row 3: one written after the removal, A1 < T2 < A2, is revoked", async () => {
		const p = await composed();
		let r: Awaited<ReturnType<typeof p.registering>> | undefined;
		p.between.afterRemoval = async () => {
			r = await p.registering(S + 1200, "beforeSecond");
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 0 });
		expect(kindOf((await r?.go()) ?? { kind: "none" })).toBe("revoked");
		expect(r?.asks()).toBe(2);
		expect(await p.listed()).toEqual([]);
		// Ended, not left pending: off the list, its record stripped to its subject.
		expect(await p.kept(r?.id ?? "")).toEqual({
			listed: false,
			record: { v: 1, subject: "sam", removed: true },
		});
	});

	it("row 4: one written after the removal and admitted before the second boundary stays, the reset done", async () => {
		const p = await composed();
		let r: Awaited<ReturnType<typeof p.registering>> | undefined;
		p.between.afterRemoval = async () => {
			r = await p.registering(S + 1200, "afterSecond");
		};
		expect(await p.reset()).toEqual({ kind: "done", removed: 0 });
		// Activated after the second boundary: usable all the same.
		expect(kindOf((await r?.go()) ?? { kind: "none" })).toBe("registered");
		expect(await p.listed()).toEqual([r?.id]);
		expect(await p.logsIn(r?.id ?? "")).toBe(true);
		// What the refused ones are checked against: a registration that wrote reads as written.
		expect(p.everWritten(r?.id ?? "")).toBe(true);
		expect((await p.kept(r?.id ?? "")).listed).toBe(true);
	});

	it("row 5: one challenged after the second boundary within its second is refused at its first ask, nothing written", async () => {
		const p = await composed();
		expect(await p.reset()).toEqual({ kind: "done", removed: 0 });
		const r = await p.registering(T2 + 400);
		expect(kindOf(await r.answer)).toBe("revoked");
		expect(r.asks()).toBe(1);
		expect(p.everWritten(r.id)).toBe(false);
		expect(await p.kept(r.id)).toEqual({ listed: false, record: undefined });
	});

	it("row 6: one challenged in a later second than the second boundary stays", async () => {
		const p = await composed();
		expect(await p.reset()).toEqual({ kind: "done", removed: 0 });
		const r = await p.registering(T2 + 1000);
		expect(kindOf(await r.answer)).toBe("registered");
		expect(await p.listed()).toEqual([r.id]);
	});
});
