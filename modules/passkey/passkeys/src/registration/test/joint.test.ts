import { randomBytes } from "node:crypto";
import { isUnavailable, Unavailable } from "@mod/kernel";
import {
	type CreationOptions,
	testCeremonies as ceremoniesFor,
	softwareAuthenticator,
	testOrigin,
} from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import { jointStores, memoryStores } from "../../../test/stores.ts";
import { keptChallenges } from "../../challenges/challenges.ts";
import type { ChallengeStore } from "../../store.ts";
import { registrationsOver } from "../registrations.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Registrations over `t`'s records and the challenges given, asking `admitted` as the caller gives it. */
function registering(
	t: Pick<ReturnType<typeof jointStores>, "records">,
	challenges: ChallengeStore = memoryStores().challenges,
	max = 10,
) {
	const rp = {
		id: "rp.example",
		name: "RP",
		origins: [testOrigin],
		topOrigins: [],
		timeoutMs: 120_000,
	};
	const random = (n: number) => new Uint8Array(randomBytes(n));
	const registrations = registrationsOver({
		ceremonies: ceremoniesFor(rp, random, Date.now),
		records: t.records,
		challenges: keptChallenges(challenges, Date.now, 120_000),
		verification: "preferred",
		max,
		freshHandle: fresh,
		settle: async () => {},
	});
	/** A response for `subject`'s fresh options, for `id` where given. */
	const answered = async (subject: string, id?: string) => {
		const options = (await registrations.creation(subject)).options as CreationOptions;
		const twist = id === undefined ? {} : { credentialId: id };
		return softwareAuthenticator().create(options, { origin: testOrigin }, twist);
	};
	return { registrations, answered };
}

it("decides a registration again on a race, its token made once", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t, t.stores.challenges);
	const [raced, other] = [await answered("sam"), await answered("sam")];
	// Another of sam's registrations lands once this one's write has read and decided.
	t.stores.raceNextTogether(async () => {
		expect(await registrations.register("sam", other)).toMatchObject({ kind: "registered" });
	});
	expect(await registrations.register("sam", raced)).toMatchObject({ kind: "registered" });
	expect(t.counted).toMatchObject({ together: 2, decisions: 3, tokens: 2 });
	expect(await t.listOf("sam")).toEqual([other.id, raced.id]);
	for (const r of [raced, other]) expect((await t.records.passkey(r.id))?.subject).toBe("sam");
});

it("ends what its token wrote where its write is unavailable however it was sent", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t, t.stores.challenges);
	const lost = await answered("sam");
	t.stores.loseNextTogether();
	await expect(registrations.register("sam", lost)).rejects.toSatisfy(isUnavailable);
	expect(await t.listOf("sam")).toEqual([]);
	expect(await t.recordOf(lost.id)).toEqual({ v: 1, subject: "sam", removed: true });
});

it("registers with one change of the record and the list, the passkey listed and then made usable", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t);
	const response = await answered("sam");
	expect(await registrations.register("sam", response)).toMatchObject({ kind: "registered" });
	// One change writes the record and the list; the passkey's activation is the record's own.
	expect(t.counted.together).toBe(1);
	expect(await t.listOf("sam")).toEqual([response.id]);
	expect((await t.records.passkey(response.id))?.subject).toBe("sam");
});

it("writes nothing where the first ask says no or fails, as it is asked before the write", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t);
	const response = await answered("sam");
	expect(await registrations.register("sam", response, undefined, async () => false)).toEqual({
		kind: "refused",
		reason: "revoked",
	});
	const failing = await answered("sam");
	await expect(
		registrations.register("sam", failing, undefined, async () => {
			throw new Unavailable("subject-revocation");
		}),
	).rejects.toSatisfy(isUnavailable);
	expect(t.counted.together).toBe(0);
	expect([await t.recordOf(response.id), await t.recordOf(failing.id)]).toEqual([
		undefined,
		undefined,
	]);
	expect(await t.listOf("sam")).toEqual([]);
});

it("ends its own write where the second ask says no or fails: off the list, its record stripped", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t);
	for (const second of ["no", "throws"] as const) {
		const response = await answered("sam");
		let asks = 0;
		const admitted = async () => {
			if (++asks === 1) return true;
			if (second === "no") return false;
			throw new Unavailable("subject-revocation");
		};
		const answer = registrations.register("sam", response, undefined, admitted);
		if (second === "no") expect(await answer).toEqual({ kind: "refused", reason: "revoked" });
		else await expect(answer, second).rejects.toSatisfy(isUnavailable);
		expect(await t.listOf("sam"), second).toEqual([]);
		expect(await t.recordOf(response.id), second).toEqual({ v: 1, subject: "sam", removed: true });
	}
});

it("answers conflict to one of two of a subject's registrations of one id, in either order, keeping the other's", async () => {
	for (const order of ["first writes first", "second writes first"] as const) {
		const t = jointStores();
		const { registrations, answered } = registering(t);
		const one = await answered("sam");
		const two = await answered("sam", one.id);
		let other: unknown;
		let asks = 0;
		const answer = await registrations.register("sam", one, undefined, async () => {
			asks += 1;
			// Before the first's write, or between its write and its last one.
			if ((order === "second writes first" ? 1 : 2) === asks) {
				other = await registrations.register("sam", two);
			}
			return true;
		});
		const answers = [answer, other].map(
			(a) => (a as { kind: string; reason?: string }).reason ?? "ok",
		);
		expect(answers.sort(), order).toEqual(["conflict", "ok"]);
		expect(await t.listOf("sam"), order).toEqual([one.id]);
		expect((await t.records.passkey(one.id))?.subject, order).toBe("sam");
	}
});

it("leaves a registration whose listed pending a removal took off with nothing usable", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t);
	const response = await answered("sam");
	let asks = 0;
	const answer = await registrations.register("sam", response, undefined, async () => {
		if (++asks === 2) {
			expect(await t.records.removed("sam", response.id)).toMatchObject({
				removed: true,
				empty: true,
			});
		}
		return true;
	});
	expect(answer).toEqual({ kind: "refused", reason: "conflict" });
	expect(await t.records.passkey(response.id)).toBeUndefined();
	expect(await t.listOf("sam")).toEqual([]);
});

it("takes a registration activated before a clear away with it, and leaves one after it unusable", async () => {
	const t = jointStores();
	const { registrations, answered } = registering(t);
	for (const when of ["activated first", "cleared first"] as const) {
		const response = await answered("sam");
		let asks = 0;
		const answer = await registrations.register("sam", response, undefined, async () => {
			if (++asks === 2 && when === "cleared first") await t.records.cleared("sam", fresh());
			return true;
		});
		if (when === "activated first") {
			expect(answer, when).toMatchObject({ kind: "registered" });
			expect((await t.records.cleared("sam", fresh())).removed, when).toBe(1);
		} else {
			expect(answer, when).toEqual({ kind: "refused", reason: "conflict" });
		}
		expect(await t.records.passkey(response.id), when).toBeUndefined();
		expect(await t.listOf("sam"), when).toEqual([]);
	}
});
