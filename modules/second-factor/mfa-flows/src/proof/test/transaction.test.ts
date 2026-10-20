import { expect, it } from "vitest";
import { serve } from "../../../test/harness.ts";

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
