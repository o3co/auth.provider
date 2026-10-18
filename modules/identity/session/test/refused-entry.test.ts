import { noStore } from "@mod/http";
import { expect, it } from "vitest";
import { refusedEntry } from "../src/contract.ts";

it("answers an absent session 401 login_required, and a short one 403 with the requirement's answer, kept out of caches", () => {
	expect(refusedEntry({ kind: "absent" })).toEqual({
		status: 401,
		headers: noStore,
		body: { json: { error: "login_required" } },
	});
	const answer = { error: "step_up_required" };
	expect(refusedEntry({ kind: "short", requirement: "mfa", answer })).toEqual({
		status: 403,
		headers: noStore,
		body: { json: answer },
	});
});
