import { takesUnused } from "@mod/kernel/testing";
import { factorReading } from "@mod/mfa-reading";
import { revocations } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import {
	afterNextChange,
	beforeNextChange,
	clock,
	factorsDown,
	onNextRead,
	raceNextChange,
	serve,
} from "./harness.ts";

const posts = [
	"/session/mfa/factors/rename",
	"/session/mfa/factors/remove",
	"/session/mfa/recovery-codes",
];
const json = { json: true };

/** The identifier of the factor of this kind, in an answer listing factors. */
const idOf = (listed: { body: Record<string, unknown> }, kind: string) =>
	(listed.body.factors as { id: string; kind: string }[]).find((f) => f.kind === kind)?.id ?? "";

describe("the routes' policies", () => {
	it("refuses a POST without same-origin evidence before anything else", async () => {
		const s = await serve();
		await s.signIn();
		for (const path of posts) {
			const res = await fetch(`http://127.0.0.1:${s.port()}${path}`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					"x-forwarded-proto": "https",
				},
				body: new URLSearchParams({ factor_id: "x", label: "y" }),
			});
			expect([path, res.status, await res.json()]).toEqual([path, 403, { error: "csrf" }]);
		}
	});

	it("limits the forms it takes per source, after the same-origin check, and never its pages", async () => {
		const { call, signIn } = await serve({ requests: 2, window: "1m" });
		await signIn();
		const crossSite = { headers: { origin: "https://elsewhere.example" } };
		for (let i = 0; i < 2; i++) {
			expect((await call("POST", "/session/mfa/factors/rename", {}, crossSite)).status).toBe(403);
		}
		for (let i = 0; i < 2; i++) {
			expect((await call("POST", "/session/mfa/factors/rename", {})).status).not.toBe(429);
		}
		const limited = await call("POST", "/session/mfa/recovery-codes");
		expect([limited.status, limited.body]).toEqual([429, { error: "rate_limited" }]);
		expect((await call("GET", "/session/mfa/factors")).status).toBe(200);
	});

	it("counts the forms per source in a window of seconds", async () => {
		const s = await serve({ requests: 1, window: "1s" });
		await s.signIn();
		const rename = () => s.call("POST", "/session/mfa/factors/rename", {});
		expect([(await rename()).status, (await rename()).status]).toEqual([400, 429]);
		clock.shift += 1100;
		expect((await rename()).status).toBe(400);
	});

	it("answers 415 to a POST whose body is neither a form nor JSON, or that has none", async () => {
		const s = await serve();
		await s.signIn("kim");
		for (const path of posts) {
			for (const body of [{ type: "text/plain", text: "kind=code" }, undefined]) {
				const res = await fetch(`http://127.0.0.1:${s.port()}${path}`, {
					method: "POST",
					headers: {
						"x-forwarded-proto": "https",
						"x-forwarded-for": "198.51.100.1",
						origin: "https://as.example",
						cookie: [...s.jar()].map(([k, v]) => `${k}=${v}`).join("; "),
						...(body ? { "content-type": body.type } : {}),
					},
					...(body ? { body: body.text } : {}),
				});
				expect([path, res.status]).toEqual([path, 415]);
			}
		}
	});
});

describe("a session's own factors", () => {
	it("answers every route login_required without a live session", async () => {
		const s = await serve();
		for (const [method, path] of [
			["GET", "/session/mfa/factors"],
			...posts.map((p) => ["POST", p]),
		]) {
			const res = await s.call(method as "GET" | "POST", path ?? "");
			expect([path, res.status, res.body]).toEqual([path, 401, { error: "login_required" }]);
		}
	});

	it("answers 503 when the factors cannot be read, never a refusal", async () => {
		const s = await serve();
		const id = await s.bindCode();
		await s.signIn("alice", { proved: true });
		factorsDown.unavailable("read", "update");
		const answers = [
			await s.call("GET", "/session/mfa/factors"),
			await s.call("POST", "/session/mfa/factors/rename", { factor_id: id, label: "desk" }),
			await s.call("POST", "/session/mfa/factors/remove", { factor_id: id }),
			await s.call("POST", "/session/mfa/recovery-codes"),
		];
		expect(answers).toEqual(
			Array(4).fill({ status: 503, body: { error: "temporarily_unavailable" } }),
		);
	});

	it("answers 409 to a first set of codes past the factors' limit", async () => {
		const s = await serve({ "max-factors": 2 });
		await s.bindCode("fay");
		await s.signIn("fay", { proved: true });
		// Another factor takes the codes' place before the reissue writes.
		raceNextChange.change = (record) => {
			const { factors: all } = record as unknown as { factors: { id: string; kind: string }[] };
			const codes = all.filter((f) => f.kind === "code");
			return { ...record, factors: [...codes, { ...codes[0], id: "other" }] } as never;
		};
		const full = await s.call("POST", "/session/mfa/recovery-codes");
		expect([full.status, full.body]).toEqual([409, { error: "mfa_factor_limit" }]);
	});

	it("asks a recent proof to change factors, and keeps the last counting factor under required mode", async () => {
		const s = await serve({ mode: "required" });
		await s.bindCode("dana");
		await s.signIn("dana", { proved: true });
		const only = idOf(await s.call("GET", "/session/mfa/factors"), "code");
		const rename = (label: string) =>
			s.call("POST", "/session/mfa/factors/rename", { factor_id: only, label });
		expect((await rename("phone")).status).toBe(200);
		const last = await s.call("POST", "/session/mfa/factors/remove", { factor_id: only });
		expect([last.status, last.body.error]).toEqual([409, "mfa_last_factor"]);
		clock.shift += 400_000;
		for (const path of ["factors/rename", "factors/remove", "recovery-codes"]) {
			const stale = await s.call("POST", `/session/mfa/${path}`, { factor_id: only, label: "x" });
			expect([path, stale.status, stale.body.error]).toEqual([path, 403, "step_up_required"]);
		}
	});

	it("asks a recent second factor to reissue codes or remove a factor, a recent sign-in holding none not standing for one", async () => {
		const s = await serve();
		await s.signIn("eve");
		for (const path of ["factors/remove", "recovery-codes"]) {
			const none = await s.call("POST", `/session/mfa/${path}`, { factor_id: "x" });
			expect([path, none.status, none.body.error]).toEqual([path, 403, "step_up_required"]);
		}
	});

	it("hands no codes to a password-only session whose subject bound a factor while it asked", async () => {
		const s = await serve();
		await s.signIn("ivy");
		// The owner binds the first factor between the session's entry and the reissue's write.
		beforeNextChange.run = () => s.bindCode("ivy");
		const raced = await s.call("POST", "/session/mfa/recovery-codes");
		expect([raced.status, raced.body.error, raced.body.recovery_codes]).toEqual([
			403,
			"step_up_required",
			undefined,
		]);
	});
});

describe("a revocation while factors are managed", () => {
	const revokedMeanwhile = async (subject: string, path: string, body = {}) => {
		const s = await serve();
		const id = await s.bindCode(subject);
		await s.signIn(subject, { proved: true });
		clock.shift += 1000;
		// The revocation completes between the change's checks and its write.
		beforeNextChange.run = async () => {
			await s.app.get(revocations).record(subject);
			clock.shift += 1000;
		};
		const answer = await s.call("POST", `/session/mfa/${path}`, { factor_id: id, ...body });
		return { answer, held: await s.app.get(factorReading).held(subject) };
	};

	it("reissues no codes once the subject was revoked while they were written", async () => {
		const { answer } = await revokedMeanwhile("kit", "recovery-codes");
		expect([answer.status, answer.body.error, answer.body.recovery_codes]).toEqual([
			401,
			"login_required",
			undefined,
		]);
	});

	it("hands no codes once a revocation completed after they were written, before the store answered", async () => {
		const s = await serve();
		await s.bindCode("mo");
		await s.signIn("mo", { proved: true });
		clock.shift += 1000;
		afterNextChange.run = async () => {
			await s.app.get(revocations).record("mo");
			clock.shift += 1000;
		};
		const slow = await s.call("POST", "/session/mfa/recovery-codes");
		expect([slow.status, slow.body.error, slow.body.recovery_codes]).toEqual([
			401,
			"login_required",
			undefined,
		]);
	});

	it("hands no codes once a revocation completed while the last entry waited on its requirement", async () => {
		const s = await serve();
		await s.bindCode("nia");
		await s.signIn("nia", { proved: true });
		clock.shift += 1000;
		// Once the codes are written, the next read is the requirement's, in the last entry before they go out.
		afterNextChange.run = async () => {
			onNextRead.run = async () => {
				await s.app.get(revocations).record("nia");
				clock.shift += 1000;
			};
		};
		const answer = await s.call("POST", "/session/mfa/recovery-codes");
		expect([answer.status, answer.body.error, answer.body.recovery_codes]).toEqual([
			401,
			"login_required",
			undefined,
		]);
	});

	it("removes no factor once the subject was revoked while it was removed", async () => {
		const { answer, held } = await revokedMeanwhile("lou", "factors/remove");
		expect([answer.status, answer.body.error]).toEqual([401, "login_required"]);
		expect(held.map((f) => f.kind).sort()).toEqual(["backup", "code"]);
	});
});

describe("management bodies", () => {
	it("takes every POST's values from a JSON body as from a form, a member that is not a string being absent", async () => {
		const s = await serve();
		const id = await s.bindCode("judy");
		await s.signIn("judy", { proved: true });
		const rename = (body: Record<string, unknown>) =>
			s.call("POST", "/session/mfa/factors/rename", body, json);
		expect((await rename({ factor_id: id, label: "desk" })).status).toBe(200);
		expect((await rename({ factor_id: { id }, label: "desk" })).status).toBe(404);
		const codes = await s.call("POST", "/session/mfa/recovery-codes", {}, json);
		expect([codes.status, (codes.body.recovery_codes as string[]).length]).toEqual([200, 2]);
		const remove = (body: Record<string, unknown>) =>
			s.call("POST", "/session/mfa/factors/remove", body, json);
		expect((await remove({ factor_id: true })).status).toBe(404);
		expect((await remove({ factor_id: id })).status).toBe(200);
	});

	it("renames only with a label of mfa's shape, judged after the session and before the factor", async () => {
		const s = await serve();
		const id = await s.bindCode("omar");
		await s.signIn("omar", { proved: true });
		const rename = async (body: Record<string, unknown>, how: { json?: boolean } = json) => {
			const res = await s.call("POST", "/session/mfa/factors/rename", body, how);
			const listed = await s.call("GET", "/session/mfa/factors");
			return [res.status, res.body, listed.body.factors];
		};
		const named = await rename({ factor_id: id, label: "desk" });
		expect(named.slice(0, 2)).toEqual([200, {}]);
		const refused = [
			400,
			{ error: "invalid_request", error_description: "invalid label" },
			named[2],
		];
		for (const label of [
			undefined,
			"",
			null,
			5,
			{ name: "desk" },
			["desk"],
			"de\nsk",
			"d".repeat(65),
		]) {
			expect([label, ...(await rename({ factor_id: id, label }))]).toEqual([label, ...refused]);
		}
		expect(await rename({ factor_id: id, label: "" }, {})).toEqual(refused);
		expect((await rename({ factor_id: `${id}x` })).slice(0, 2)).toEqual(refused.slice(0, 2));
		clock.shift += 400_000;
		const stale = await rename({ factor_id: id });
		expect([stale[0], (stale[1] as { error: string }).error]).toEqual([403, "step_up_required"]);
	});
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused((await serve()).input))["mfa-management"]).toBeUndefined();
});
