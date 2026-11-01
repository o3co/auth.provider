import { logins } from "@mod/login-gates";
import loginGates from "@mod/login-gates/module";
import { expect, it } from "vitest";
import { harness, origin } from "./harness.ts";

it("lets a login sent from the connect return to it, on the public origin and its path alone", async () => {
	const h = await harness({ modules: [loginGates] });
	const lodged = await h.lodge();
	// A browser with no session is sent to log in, then back to the connect it opened.
	const connect = new URL(String(lodged.json?.connect_uri));
	const gates = await h.app.get(logins);
	expect(gates.returnAllowed(connect.href)).toBe(true);
	expect(gates.returnAllowed(`${origin}/session/federation-grants/connect?request=any`)).toBe(true);
	for (const other of [
		"https://other.example/session/federation-grants/connect?request=any",
		`${origin}:8443/session/federation-grants/connect?request=any`,
		`${origin}/session/federation-grants/connect/more?request=any`,
		`${origin}/session/federation-grants/callback/cal?request=any`,
		`${origin}/session/federation-grants/connect?request=any#there`,
	]) {
		expect(gates.returnAllowed(other), other).toBe(false);
	}
});
