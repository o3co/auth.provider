import { defineModule } from "@mod/kernel";
import { factorKinds, type Sending } from "@mod/mfa";
import { expect, it } from "vitest";
import { serve } from "./harness.ts";

const mail = { answer: undefined as Sending | undefined };
/** A counting kind that sends its challenge to a contact, as an email one does. */
const mailKind = defineModule({ name: "kind-mail" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "mail",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => ({ secret: "m1", show: {} }),
		challenge: async () => mail.answer ?? { kind: "sent" as const, show: {}, kept: "k" },
		verify: async (secret: string, _state: unknown, proof: string) =>
			proof === secret ? { kind: "valid" as const, state: null } : { kind: "invalid" as const },
	})),
]);

it("records the mismatch only for a kind's refusal saying the factor's contact changed", async () => {
	const s = await serve({}, [mailKind]);
	await s.signIn("max");
	const { transaction } = (await s.call("POST", "/session/mfa/enrollment", { kind: "mail" })).body;
	await s.call("POST", "/session/mfa/enrollment/complete", {
		transaction_id: transaction,
		proof: "m1",
	});
	const { tx, factor } = await s.heldLogin("max");
	s.events.length = 0;
	const challenge = () =>
		s.call("POST", "/session/mfa/challenge", { transaction_id: tx, factor_id: factor("mail") });
	mail.answer = { kind: "refused" };
	expect((await challenge()).status).toBe(403);
	mail.answer = { kind: "refused", reason: "contact-changed" };
	expect(await challenge()).toEqual({ status: 403, body: { error: "mfa_factor_refused" } });
	expect(s.events.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
		[
			"mfa.email_address_mismatch",
			"max",
			{ kind: "mail", purpose: "login", source: "198.51.100.1" },
		],
	]);
});
