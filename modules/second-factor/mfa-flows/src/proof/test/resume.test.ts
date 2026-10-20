import { jsonAnswer } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { LoginOutcome } from "@mod/login-gates";
import type { Session } from "@mod/session";
import { expect, it } from "vitest";
import type { Transaction } from "../../transactions/records.ts";
import { resumeOver } from "../proof.ts";

const session: Session = { id: "h1", context: { subject: "sue", amr: ["pwd"] } as never };
const t = {
	subject: "sue",
	purpose: "enroll-login",
	browser: "b",
	startedAt: 0,
	deadline: 1,
	attemptsLeft: 1,
	done: { next: "/home" },
} as unknown as Transaction & { readonly purpose: "enroll-login" };

/** resumeOver over stand-ins; `calls` lists what reached them, the carried answer's making included. */
function standIn() {
	const calls: string[] = [];
	const set = {
		resumed: { kind: "opened", session, cookies: ["session=s1"] } as LoginOutcome,
		revokeOnOpen: false,
		revoked: false,
		closing: async () => {},
	};
	const resume = resumeOver({
		sessions: {
			close: async (id) => {
				calls.push(`close ${id}`);
				await set.closing();
				return { kind: "closed", cookies: [] };
			},
		},
		logins: {
			resume: async () => {
				set.revoked ||= set.revokeOnOpen;
				return set.resumed;
			},
		},
		revocation: { check: async () => (set.revoked ? "revoked" : "valid") },
		transactions: { cleared: () => "mfa=" } as never,
		log: recordingLog().log,
	});
	return {
		calls,
		set,
		resume: (carried: Parameters<typeof resume>[3]) => resume(testRequest(), t, ["otp"], carried),
	};
}

it("makes what it carries only once the login opened and no revocation came, adding it to done", async () => {
	const s = standIn();
	const carried = async () => {
		s.calls.push("made");
		return { factor: "f" };
	};
	const opened = await s.resume(carried);
	expect([opened.status, opened.body, opened.cookies]).toEqual([
		200,
		{ json: { next: "/home", factor: "f" } },
		["session=s1", "mfa="],
	]);
	s.set.resumed = { kind: "held", gate: "next", answer: { error: "next" }, cookies: [] };
	expect((await s.resume(carried)).status).toBe(403);
	s.set.resumed = { kind: "opened", session, cookies: ["session=s1"] };
	s.set.revokeOnOpen = true;
	expect((await s.resume(carried)).status).toBe(401);
	expect(s.calls).toEqual(["made", "close h1"]);
});

it("closes the opened session and answers what carried answered when it is a response; the session's cookie never goes out", async () => {
	const s = standIn();
	const refused = await s.resume(async () => jsonAnswer(401, { error: "login_required" }));
	expect([refused.status, refused.body, refused.cookies]).toEqual([
		401,
		{ json: { error: "login_required" } },
		["mfa="],
	]);
	expect(s.calls).toEqual(["close h1"]);
});

it("closes the opened session as best it can when carried throws, throwing what carried threw", async () => {
	const s = standIn();
	s.set.closing = async () => {
		throw new Error("close");
	};
	await expect(
		s.resume(async () => {
			throw new Error("carried");
		}),
	).rejects.toThrow("carried");
	expect(s.calls).toEqual(["close h1"]);
});

it("answers 503 clearing the transaction, never the session's cookie, when carried is unavailable", async () => {
	const s = standIn();
	const failed = await s.resume(async () => {
		throw new Unavailable("mfa");
	});
	expect([failed.status, failed.body, failed.cookies]).toEqual([
		503,
		{ json: { error: "temporarily_unavailable" } },
		["mfa="],
	]);
	expect(s.calls).toEqual(["close h1"]);
});

it("answers 503 clearing the transaction when the session cannot be closed after a response carried made, its cookie never going out", async () => {
	const s = standIn();
	s.set.closing = async () => {
		throw new Unavailable("session");
	};
	const failed = await s.resume(async () => jsonAnswer(409, { error: "mfa_factor_limit" }));
	expect([failed.status, failed.cookies]).toEqual([503, ["mfa="]]);
	s.set.closing = async () => {
		throw new TypeError("session");
	};
	await expect(
		s.resume(async () => jsonAnswer(409, { error: "mfa_factor_limit" })),
	).rejects.toThrow(TypeError);
	expect(s.calls).toEqual(["close h1", "close h1"]);
});
