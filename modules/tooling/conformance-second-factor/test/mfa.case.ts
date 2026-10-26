import { generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, faultyTarget, type SentEvent, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import {
	beginBinding,
	browser,
	issuer,
	letInByRecovery,
	password,
	running,
	sessionCookie,
	stepUp,
	totp,
} from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
const sceneFor = (mode: "optional" | "required", users: string[]) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "mfa",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: users.map((identifier) => ({ identifier, password })),
			login: { returnTargets: ["https://app.example/back"], attempts: 100, windowSeconds: 600 },
		}),
		secondFactorArea.part({ mode }),
	);

describe("G. second factor at password login", () => {
	const s = running(
		sceneFor("optional", [
			"alice",
			"bob",
			"carol",
			"dave",
			"gail",
			"hana",
			"ivan",
			"judy",
			"kate",
			"lena",
			"mona",
		]),
	);

	it("binds TOTP from a signed-in session, then asks it at login and lets the right code in", async () => {
		const { secret, codes } = await s.enrol("alice");
		expect(codes).toHaveLength(10);
		const { b, answer, transaction } = await s.held("alice");
		expect([answer.status, answer.body.error]).toEqual([403, "mfa_required"]);
		const totpFactor = (await b.factors(transaction)).find((f) => f.kind === "totp");
		const wrong = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: totpFactor?.id ?? "",
			proof: "000000",
		});
		expect([wrong.status, wrong.body.error]).toEqual([401, "mfa_invalid"]);
		// Made once: the replay presents this same code, whichever step it is then.
		const code = totp(secret, 1);
		const right = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: totpFactor?.id ?? "",
			proof: code,
		});
		expect(right.status).toBe(200);
		expect(sessionCookie(b.jar)).toBeTruthy();
		const replay = await s.held("alice");
		const again = (await replay.b.factors(replay.transaction)).find((f) => f.kind === "totp");
		const replayed = await replay.b.send("POST", "/session/mfa/verify", {
			transaction_id: replay.transaction,
			factor_id: again?.id ?? "",
			proof: code,
		});
		expect(replayed.status).toBe(401);
	});

	it("takes a JSON body as a form, the transaction in it or in the MFA-Transaction header", async () => {
		const { secret } = await s.enrol("hana");
		const { b, transaction } = await s.held("hana");
		const factor_id = (await b.factors(transaction)).find((f) => f.kind === "totp")?.id ?? "";
		const header = { "mfa-transaction": transaction };
		const wrong = await b.send(
			"POST",
			"/session/mfa/verify",
			{ factor_id, proof: "000000" },
			header,
			"json",
		);
		expect([wrong.status, wrong.body.error]).toEqual([401, "mfa_invalid"]);
		const differ = await b.send(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: `${transaction}x`, factor_id, proof: totp(secret, 1) },
			header,
			"json",
		);
		expect(differ.status).toBe(400);
		const right = await b.send(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: transaction, factor_id, proof: totp(secret, 1) },
			{},
			"json",
		);
		expect(right.status).toBe(200);
		expect(sessionCookie(b.jar)).toBeTruthy();
	});

	it("refuses to complete an enrollment whose JSON label is a number, and enrols nothing", async () => {
		const b = browser(() => s.at.base);
		expect((await b.login("ivan")).status).toBe(200);
		const begun = await beginBinding(b, { kind: "totp" }, s.mail());
		const refused = await b.send(
			"POST",
			"/session/mfa/enrollment/complete",
			{
				transaction_id: String(begun.body.transaction),
				proof: totp(String(begun.body.secret)),
				label: 5,
			},
			{},
			"json",
		);
		expect([refused.status, refused.body.error]).toEqual([400, "invalid_request"]);
		// With no factor bound, the next login is not held.
		expect((await browser(() => s.at.base).login("ivan")).status).toBe(200);
	});

	it("refuses to complete an enrollment whose label is empty, and enrols nothing", async () => {
		const b = browser(() => s.at.base);
		expect((await b.login("judy")).status).toBe(200);
		const begun = await beginBinding(b, { kind: "totp" }, s.mail());
		const refused = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: totp(String(begun.body.secret)),
			label: "",
		});
		expect([refused.status, refused.body.error]).toEqual([400, "invalid_request"]);
		expect((await browser(() => s.at.base).login("judy")).status).toBe(200);
	});

	it("refuses to rename a factor with no label, and keeps its old label", async () => {
		const { secret } = await s.enrol("kate");
		const { b, transaction } = await s.held("kate");
		const factor_id = (await b.factors(transaction)).find((f) => f.kind === "totp")?.id ?? "";
		const proved = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id,
			proof: totp(secret, 1),
		});
		expect(proved.status).toBe(200);
		const named = await b.send("POST", "/session/mfa/factors/rename", { factor_id, label: "desk" });
		expect(named.status).toBe(200);
		const refused = await b.send("POST", "/session/mfa/factors/rename", { factor_id });
		expect([refused.status, refused.body.error]).toEqual([400, "invalid_request"]);
		const listed = (await b.send("GET", "/session/mfa/factors")).body.factors as {
			id: string;
			label?: string;
		}[];
		expect(listed.find((f) => f.id === factor_id)?.label).toBe("desk");
	});

	it("refuses to rename a factor with a label holding a line break, and keeps its old label", async () => {
		const { secret } = await s.enrol("lena");
		const { b, transaction } = await s.held("lena");
		const factor_id = (await b.factors(transaction)).find((f) => f.kind === "totp")?.id ?? "";
		const proved = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id,
			proof: totp(secret, 1),
		});
		expect(proved.status).toBe(200);
		const named = await b.send("POST", "/session/mfa/factors/rename", { factor_id, label: "desk" });
		expect(named.status).toBe(200);
		const refused = await b.send("POST", "/session/mfa/factors/rename", {
			factor_id,
			label: "desk\ntop",
		});
		expect([refused.status, refused.body.error]).toEqual([400, "invalid_request"]);
		const listed = (await b.send("GET", "/session/mfa/factors")).body.factors as {
			id: string;
			label?: string;
		}[];
		expect(listed.find((f) => f.id === factor_id)?.label).toBe("desk");
	});

	it("does not let another browser use a transaction, and spends nothing then", async () => {
		const { secret } = await s.enrol("bob");
		const mine = await s.held("bob");
		const factor = (await mine.b.factors(mine.transaction)).find((f) => f.kind === "totp");
		const other = await s.held("bob");
		const foreign = await other.b.send("POST", "/session/mfa/verify", {
			transaction_id: mine.transaction,
			factor_id: factor?.id ?? "",
			proof: totp(secret, 1),
		});
		expect(foreign.status).toBe(400);
		const own = await mine.b.send("POST", "/session/mfa/verify", {
			transaction_id: mine.transaction,
			factor_id: factor?.id ?? "",
			proof: totp(secret, 1),
		});
		expect(own.status).toBe(200);
	});

	it("holds a user after repeated wrong codes even for the right one, and a recovery code still works [rfc6749-10.10-d]", async () => {
		const { secret, codes } = await s.enrol("carol");
		const first = await s.held("carol");
		const factor = (await first.b.factors(first.transaction)).find((f) => f.kind === "totp");
		for (let i = 0; i < 5; i++) {
			await first.b.send("POST", "/session/mfa/verify", {
				transaction_id: first.transaction,
				factor_id: factor?.id ?? "",
				proof: "000000",
			});
		}
		const next = await s.held("carol");
		const list = await next.b.factors(next.transaction);
		const locked = await next.b.send("POST", "/session/mfa/verify", {
			transaction_id: next.transaction,
			factor_id: list.find((f) => f.kind === "totp")?.id ?? "",
			proof: totp(secret, 1),
		});
		expect([locked.status, locked.body.error]).toEqual([429, "mfa_locked"]);
		const back = await next.b.send("POST", "/session/mfa/verify", {
			transaction_id: next.transaction,
			factor_id: list.find((f) => f.kind !== "totp")?.id ?? "",
			proof: codes[0] ?? "",
		});
		expect(back.status).toBe(200);
	});

	it("lets in only one of two logins that use the same recovery code at once", async () => {
		const { codes } = await s.enrol("mona");
		const logins = await Promise.all([s.held("mona"), s.held("mona")]);
		const answers = await Promise.all(
			logins.map(({ b, transaction }) => letInByRecovery(b, transaction, codes[0] ?? "")),
		);
		const outcomes = answers
			.map((a) => [a.status, a.body.error])
			.sort(([a], [b]) => Number(a) - Number(b));
		expect(outcomes).toEqual([
			[200, undefined],
			[401, "mfa_invalid"],
		]);
	});

	it.runIf(!areaTarget().differs("mfa-login-loses-return-target"))(
		"sends the user to the checked return target once the second factor lets the login through",
		async () => {
			const { secret } = await s.enrol("gail");
			const { b, transaction } = await s.held("gail", { redirect_to: "https://app.example/back" });
			const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
			const done = await b.send("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factor?.id ?? "",
				proof: totp(secret, 1),
			});
			expect([done.status, done.body.redirect_to]).toEqual([200, "https://app.example/back"]);
		},
	);

	it("raises a session by a step-up under a new cookie, and the old cookie is no use after", async () => {
		const { secret, codes } = await s.enrol("dave");
		const { b, transaction } = await s.held("dave");
		await letInByRecovery(b, transaction, codes[0] ?? "");
		const before = sessionCookie(b.jar);
		const raised = await stepUp(b, secret);
		expect([raised.status, raised.body.step_up]).toEqual([200, "verified"]);
		expect(sessionCookie(b.jar)).not.toBe(before);
		const old = browser(() => s.at.base);
		for (const [name, value] of b.jar) old.jar.set(name, value);
		const name = [...b.jar.keys()].find((n) => /session/.test(n) && !/csrf|mfa/.test(n)) ?? "";
		old.jar.set(name, before ?? "");
		expect((await old.send("GET", "/session/mfa/factors")).status).not.toBe(200);
		expect((await b.send("GET", "/session/mfa/factors")).status).toBe(200);
	});
});

describe.runIf(areaTarget().can(auditEvents.need))("G. second factor: audit events", () => {
	const s = running(sceneFor("optional", ["mia", "noa", "oli"]));
	/** The second-factor events of a request, as kind, subject and attributes. */
	const during = async <T>(request: () => Promise<T>) => {
		const { result, events } = await s.trail().during(request);
		const own = events.filter((e: SentEvent) => e.kind.startsWith("mfa."));
		return { result, events: own.map(({ at: _at, ...rest }) => rest) };
	};
	const subject = expect.stringMatching(/./);
	const source = "198.51.100.30";

	it("records a binding, a refused and a verified proof, never a code or a secret", async () => {
		const bound = await during(() => s.enrol("mia"));
		const { secret, codes, proved } = bound.result;
		const binding = { kind: "account-email", purpose: "enroll", source };
		expect(bound.events).toEqual([
			...(proved
				? [
						{ kind: "mfa.challenge.sent", subject, attributes: binding },
						{ kind: "mfa.verified", subject, attributes: binding },
					]
				: []),
			{
				kind: "mfa.factor.enrolled",
				subject,
				attributes: { kind: "totp", factor: expect.any(String) },
			},
			{
				kind: "mfa.recovery_codes.generated",
				subject,
				attributes: { kind: "recovery_code", regenerated: "false" },
			},
		]);
		const { b, transaction } = await s.held("mia");
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp")?.id ?? "";
		const verify = (proof: string) =>
			b.send("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factor,
				proof,
			});
		const wrong = await during(() => verify("000000"));
		const right = await during(() => verify(totp(secret, 1)));
		expect([wrong.result.status, right.result.status]).toEqual([401, 200]);
		expect(wrong.events).toEqual([
			{
				kind: "mfa.verify.failure",
				subject,
				attributes: { purpose: "login", factor, reason: "invalid", source },
			},
		]);
		expect(right.events).toEqual([
			{ kind: "mfa.verified", subject, attributes: { purpose: "login", factor, source } },
		]);
		const written = JSON.stringify([bound.events, wrong.events, right.events]);
		expect([secret, ...codes].filter((c) => written.includes(c))).toEqual([]);
	});

	it("records a held subject's refusal, and a recovery code used to come back", async () => {
		const { codes } = await s.enrol("noa");
		const first = await s.held("noa");
		const totpId = (await first.b.factors(first.transaction)).find((f) => f.kind === "totp")?.id;
		for (let i = 0; i < 5; i++) {
			await first.b.send("POST", "/session/mfa/verify", {
				transaction_id: first.transaction,
				factor_id: totpId ?? "",
				proof: "000000",
			});
		}
		const next = await s.held("noa");
		const list = await next.b.factors(next.transaction);
		const way = list.find((f) => f.kind !== "totp")?.id ?? "";
		const send = (factor_id: string, proof: string) =>
			next.b.send("POST", "/session/mfa/verify", {
				transaction_id: next.transaction,
				factor_id,
				proof,
			});
		const locked = await during(() => send(totpId ?? "", "000000"));
		const back = await during(() => send(way, codes[0] ?? ""));
		expect([locked.result.status, back.result.status]).toEqual([429, 200]);
		expect(locked.events).toEqual([
			{
				kind: "mfa.locked",
				subject,
				attributes: { purpose: "login", factor: totpId, hold: expect.any(String), source },
			},
		]);
		expect(back.events).toEqual([
			{
				kind: "mfa.recovery_code.used",
				subject,
				attributes: { kind: "recovery_code", factor: way, remaining: "9" },
			},
			{ kind: "mfa.verified", subject, attributes: { purpose: "login", factor: way, source } },
		]);
	});

	it("records recovery codes reissued and a factor removed from the account", async () => {
		const { secret } = await s.enrol("oli");
		const { b, transaction } = await s.held("oli");
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp")?.id ?? "";
		const proved = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factor,
			proof: totp(secret, 1),
		});
		expect(proved.status).toBe(200);
		// A second counting factor, so the one removed is not the last: with a witness, only a reset ends an enrollment.
		const added = await beginBinding(b, { kind: "totp" }, s.mail());
		const bound = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(added.body.transaction),
			proof: totp(String(added.body.secret)),
		});
		expect(bound.status).toBe(200);
		const reissued = await during(() => b.send("POST", "/session/mfa/recovery-codes"));
		const removed = await during(() =>
			b.send("POST", "/session/mfa/factors/remove", { factor_id: factor }),
		);
		expect([reissued.result.status, removed.result.status]).toEqual([200, 200]);
		expect(reissued.events).toEqual([
			{
				kind: "mfa.recovery_codes.generated",
				subject,
				attributes: { kind: "recovery_code", regenerated: "true" },
			},
		]);
		expect(removed.events).toEqual([
			{ kind: "mfa.factor.removed", subject, attributes: { kind: "totp", factor } },
		]);
	});
});

describe("G. second factor required", () => {
	const s = running(sceneFor("required", ["erin"]));

	it("asks a first binding at login, which counts from the next sign-in unless a binding proof passed, then keeps the last counting factor", async () => {
		const { b, answer, transaction } = await s.held("erin");
		expect([answer.status, answer.body.error]).toEqual([403, "mfa_enrollment_required"]);
		const begun = await beginBinding(b, { kind: "totp", transaction_id: transaction }, s.mail());
		const done = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: transaction,
			proof: totp(String(begun.body.secret)),
		});
		expect(done.status).toBe(200);
		// Bound on the password alone, the factor does not finish this login; after a binding proof, it does.
		const before = await b.send("GET", "/session/mfa/factors");
		const unproved = [401, "login_required"];
		expect([before.status, before.body.error]).toEqual(begun.proved ? [200, undefined] : unproved);
		const next = await s.held("erin");
		expect([next.answer.status, next.answer.body.error]).toEqual([403, "mfa_required"]);
		const bound = (await next.b.factors(next.transaction)).find((f) => f.kind === "totp");
		const proved = await next.b.send("POST", "/session/mfa/verify", {
			transaction_id: next.transaction,
			factor_id: bound?.id ?? "",
			proof: totp(String(begun.body.secret), 1),
		});
		expect(proved.status).toBe(200);
		const factors = (await next.b.send("GET", "/session/mfa/factors")).body.factors as {
			id: string;
			kind: string;
		}[];
		const last = await next.b.send("POST", "/session/mfa/factors/remove", {
			factor_id: factors.find((f) => f.kind === "totp")?.id ?? "",
		});
		expect([last.status, last.body.error]).toEqual([409, "mfa_last_factor"]);
	});
});

describe.runIf(areaTarget().can("store-fault:second-factors"))(
	"G. second factor: the store failing",
	() => {
		const faulty = faultyTarget(sceneFor("optional", ["fay"]));

		it("answers 503 to a second factor while the store is unreachable, never a refusal", async () => {
			const b = browser(() => faulty.base());
			await b.login("fay");
			const begun = await beginBinding(b, { kind: "totp" }, faulty.mail());
			const secret = String(begun.body.secret);
			await b.send("POST", "/session/mfa/enrollment/complete", {
				transaction_id: String(begun.body.transaction),
				proof: totp(secret),
			});
			const other = browser(() => faulty.base());
			const held = await other.login("fay");
			const transaction = String(held.body.transaction);
			const factor = (await other.factors(transaction)).find((f) => f.kind === "totp");
			const answer = await faulty.whileDown(() =>
				other.send("POST", "/session/mfa/verify", {
					transaction_id: transaction,
					factor_id: factor?.id ?? "",
					proof: totp(secret, 1),
				}),
			);
			expect(answer.status).toBe(503);
		});
	},
);
