import { subjectRevocation } from "@mod/subject-revocation";
import { expect, it } from "vitest";
import { clock, serve } from "../../../test/harness.ts";

it("answers the browser's own transaction by its cookie, with its identifier, where no header names one", async () => {
	const s = await serve();
	await s.enrollCode();
	const { tx, jar } = await s.heldLogin();
	const own = await s.call("GET", "/session/mfa/transaction", {}, { jar });
	expect([own.status, own.body.transaction, own.body.purpose]).toEqual([200, tx, "login"]);
	const named = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx }, { jar });
	expect([named.status, "transaction" in named.body]).toEqual([200, false]);
});

it("answers a login held for a first binding by its cookie too, whatever its purpose", async () => {
	const s = await serve({ mode: "required" });
	const held = await s.login("nina");
	if (held.kind !== "held") throw new Error(held.kind);
	const tx = String((held.answer as { transaction: string }).transaction);
	const own = await s.call("GET", "/session/mfa/transaction");
	expect([own.status, own.body.transaction, own.body.purpose]).toEqual([200, tx, "enroll-login"]);
});

it("answers a browser without the cookie as it answers an unknown transaction", async () => {
	const s = await serve();
	await s.enrollCode();
	await s.heldLogin();
	const other = await s.call("GET", "/session/mfa/transaction", {}, { jar: new Map() });
	expect([other.status, other.body.error]).toEqual([400, "invalid_request"]);
});

it("lets no other origin read it, an allowed one included, keeps it out of caches, and says so failing too", async () => {
	const s = await serve();
	await s.enrollCode();
	const { jar } = await s.heldLogin();
	for (const [held, status] of [
		[jar, 200],
		[new Map<string, string>(), 400],
	] as const) {
		for (const origin of ["https://as.example", "https://app.example", "https://other.example"]) {
			const read = await s.call(
				"GET",
				"/session/mfa/transaction",
				{},
				{ jar: held, headers: { origin } },
			);
			expect([read.status, read.headers.get("access-control-allow-origin")], origin).toEqual([
				status,
				null,
			]);
			expect(read.headers.get("cross-origin-resource-policy")).toBe("same-origin");
			expect(read.headers.get("cache-control")).toContain("no-store");
			expect(read.headers.get("x-content-type-options")).toBe("nosniff");
		}
	}
});

it("answers by the cookie as by the header once the transaction is used, past its end, or its subject revoked", async () => {
	const s = await serve({ "transaction-lifetime": "1m" });
	const { secret } = await s.enrollCode();
	const used = await s.heldLogin();
	const proved = await s.call("POST", "/session/mfa/verify", {
		transaction_id: used.tx,
		factor_id: used.factor(),
		proof: `${secret}:1`,
	});
	expect(proved.status).toBe(200);
	const read = (jar: Map<string, string>) => s.call("GET", "/session/mfa/transaction", {}, { jar });
	expect((await read(used.jar)).status).toBe(400);
	const late = await s.heldLogin();
	clock.shift += 60_000;
	expect((await read(late.jar)).status).toBe(400);
	const revoked = await s.heldLogin();
	clock.shift += 2000;
	await s.app.get(subjectRevocation).revoke("alice");
	const answer = await read(revoked.jar);
	expect([answer.status, answer.body.error]).toEqual([401, "login_required"]);
});

it("answers a cookie of the earlier form, or one that is not well formed, as no transaction where no header names one", async () => {
	const s = await serve();
	await s.enrollCode();
	const { tx, jar } = await s.heldLogin();
	const value = String(jar.get("__Host-mfa"));
	const secret = value.slice(tx.length + 1);
	for (const sent of [secret, `${tx}.`, `${tx}.${secret}.x`, `${secret}.${tx}`]) {
		const read = await s.call(
			"GET",
			"/session/mfa/transaction",
			{},
			{ jar: new Map([...jar, ["__Host-mfa", sent]]) },
		);
		expect([read.status, read.body.error], sent).toEqual([400, "invalid_request"]);
	}
	// The earlier form still reads where the header names the transaction.
	const named = await s.call(
		"GET",
		"/session/mfa/transaction",
		{ transaction_id: tx },
		{ jar: new Map([...jar, ["__Host-mfa", secret]]) },
	);
	expect(named.status).toBe(200);
});
