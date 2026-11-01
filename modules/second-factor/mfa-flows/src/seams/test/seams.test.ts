import { jsonAnswer } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { Session } from "@mod/session";
import { expect, it } from "vitest";
import { resumeOver } from "../../proof/proof.ts";
import type { Transaction } from "../../transactions/records.ts";
import { flowPartsOf, type ResumeMade } from "../seams.ts";

const t = { subject: "sue", purpose: "enroll-login" } as unknown as Transaction & {
	readonly purpose: "enroll-login";
};

/** The parts over a resume that answers what its maker made, marked, as it saw it. */
function parts() {
	const seen: ResumeMade[] = [];
	const built = flowPartsOf({
		transactions: {} as never,
		audit: { record: () => {} },
		policy: {} as never,
		resume: async (_request, _t, _proved, made) => {
			if (made) seen.push(await made());
			return jsonAnswer(200, {});
		},
	});
	return { built, seen };
}

it("passes a marked maker to the resume as it is", async () => {
	const { built, seen } = parts();
	const answer = jsonAnswer(409, { error: "mfa_factor_limit" });
	await built.resumeWith(testRequest(), t, ["otp"], async () => ({ answer }));
	await built.resumeWith(testRequest(), t, ["otp"], async () => ({ adds: { status: "x" } }));
	expect(seen).toEqual([{ answer }, { adds: { status: "x" } }]);
});

it("resumes with no maker through resume, which carries nothing", async () => {
	const { built, seen } = parts();
	const carried = async () => ({ adds: { factor: "f" } });
	// A maker given anyway is no part of resume's contract, and never reaches the resume.
	await (built.resume as (...args: unknown[]) => Promise<unknown>)(
		testRequest(),
		t,
		["otp"],
		carried,
	);
	expect(seen).toEqual([]);
});

/** The parts over the package's own resume, a login opening; `closes` says how its close answers. */
function opening(closes: () => Promise<void> = async () => {}) {
	const session: Session = { id: "h1", context: { subject: "sue", amr: ["pwd"] } as never };
	const closed: string[] = [];
	const resume = resumeOver({
		sessions: {
			close: async (id) => {
				closed.push(id);
				await closes();
				return { kind: "closed", cookies: [] };
			},
		},
		logins: { resume: async () => ({ kind: "opened", session, cookies: ["session=s1"] }) },
		transactions: { cleared: () => "mfa=" } as never,
		log: recordingLog().log,
	});
	const built = flowPartsOf({
		transactions: {} as never,
		audit: { record: () => {} },
		policy: {} as never,
		resume,
	});
	return { built, closed };
}

it("answers 503 clearing the transaction through resumeWith where the maker is unavailable, the session's cookie never going out", async () => {
	const { built, closed } = opening();
	const failed = await built.resumeWith(testRequest(), t, ["otp"], async () => {
		throw new Unavailable("mfa");
	});
	expect([failed.status, failed.cookies, closed]).toEqual([503, ["mfa="], ["h1"]]);
});

it("answers 503 clearing the transaction through resumeWith where the session cannot be closed after the maker's answer", async () => {
	const { built, closed } = opening(async () => {
		throw new Unavailable("session");
	});
	const answer = jsonAnswer(409, { error: "mfa_factor_limit" });
	const failed = await built.resumeWith(testRequest(), t, ["otp"], async () => ({ answer }));
	expect([failed.status, failed.cookies, closed]).toEqual([503, ["mfa="], ["h1"]]);
});
