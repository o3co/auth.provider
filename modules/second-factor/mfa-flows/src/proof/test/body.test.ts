import { defineModule } from "@mod/kernel";
import { factorKinds } from "@mod/mfa";
import { expect, it } from "vitest";
import { serve } from "../../../test/harness.ts";

/** Every proof the kind was given, in order; it takes only an object's JSON text. */
const given: string[] = [];
const echo = defineModule({ name: "kind-echo" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "echo",
		amr: ["hwk"],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
		enroll: async () => ({ secret: "s", show: {} }),
		verify: async (_secret, _state, proof) => {
			given.push(proof);
			return proof === '{"ok":true}'
				? { kind: "valid" as const, state: given.length }
				: { kind: "invalid" as const };
		},
	})),
]);

it("hands a kind an object proof as its JSON text, and takes a number or an array as none", async () => {
	const s = await serve({}, [echo]);
	await s.signIn("ola");
	const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "echo" });
	const transaction_id = String(begun.body.transaction);
	const complete = (proof: unknown) =>
		s.call("POST", "/session/mfa/enrollment/complete", { transaction_id, proof }, { json: true });
	expect((await complete(5)).status).toBe(401);
	expect((await complete([{ ok: true }])).status).toBe(401);
	expect((await complete({ ok: true })).status).toBe(200);
	const { tx, factor } = await s.heldLogin("ola");
	const verify = (proof: unknown) =>
		s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: tx, factor_id: factor("echo"), proof },
			{ json: true },
		);
	expect((await verify(null)).status).toBe(401);
	expect((await verify({ ok: true })).status).toBe(200);
	expect(given).toEqual(["", "", '{"ok":true}', "", '{"ok":true}']);
});
