import { loginSource } from "@mod/login-attributes";
import { expect, it } from "vitest";
import { askedFrom } from "../transactions.ts";

const facts = (values: Record<string, unknown>, source: string = loginSource.users) => ({
	subject: "sue",
	amr: ["pwd"],
	attributes: { source, values },
});

it("asks mfa's kinds for a held login by the email its login gave, and for a session by its handle", () => {
	for (const purpose of ["login", "enroll-login"] as const) {
		expect(askedFrom({ purpose, facts: facts({ email: "sue@example.com" }) })).toEqual({
			kind: "login",
			email: "sue@example.com",
			vouched: true,
		});
		// An upstream's word is its own, whatever its IdP is named.
		const upstream = facts({ email: "sue@example.com" }, loginSource.upstream("users"));
		expect(askedFrom({ purpose, facts: upstream })).toEqual({
			kind: "login",
			email: "sue@example.com",
		});
		expect(askedFrom({ purpose, facts: facts({}) })).toEqual({ kind: "login" });
		expect(askedFrom({ purpose })).toEqual({ kind: "login" });
	}
	for (const purpose of ["step-up", "enroll"] as const) {
		expect(askedFrom({ purpose, handle: "h1" })).toEqual({ kind: "session", handle: "h1" });
	}
});
