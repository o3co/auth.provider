import { metadataSections } from "@mod/clients";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { z } from "zod";
import { admit } from "./admission.ts";
import { bindingReader, outcomeOf } from "./binding.ts";
import { clientBindings, senderBinding, senderBindings } from "./contract.ts";
import { requirementsOver } from "./requirement.ts";

/** As 0.17's: DPoP's explicit proof wins over a certificate the request also proves. */
const section = z.strictObject({
	dispatch: z
		.enum(["intent-explicit", "strict-mutual-exclusion"])
		.prefault("intent-explicit")
		.describe(
			"How a request proving two bindings is read: an explicit kind wins over ambient ones, or any two are refused.",
		),
});

// Its own kinds are collected, so named; its own bindings and their refusals are not.
export default defineModule(
	{ name: "sender-binding", section, takes: [senderBindings, issuer] },
	(m) => [
		m
			.contribute(metadataSections)
			.by(async (c) => requirementsOver(await c.collect(senderBindings)).section),
		m.provide(clientBindings).by(async (c) => {
			const kinds = await c.collect(senderBindings);
			const names = kinds.flatMap((kind) => (kind.name ? [kind.name] : []));
			if (new Set(names).size < names.length) {
				return c.refuse("sender-binding", "two binding kinds share a name");
			}
			return { refusalOf: requirementsOver(kinds).refusalOf };
		}),
		m.provide(senderBinding).by(async (c) => {
			// In member order, so the assembly's order never decides which refusal answers.
			const kinds = [...(await c.collect(senderBindings))].sort((a, b) =>
				a.member < b.member ? -1 : 1,
			);
			const issuerUrl = (await c.get(issuer)).url;
			const schemes = [...new Set(["Bearer", ...kinds.map((kind) => kind.tokenType)])];
			const readBinding = bindingReader(kinds, issuerUrl, c.section.dispatch);
			const tokenTypeOf = (member: string) =>
				kinds.find((kind) => kind.member === member)?.tokenType;
			return {
				bindingOf: async (request, scene) => outcomeOf(await readBinding(request, scene)),
				tokenTypeOf,
				admitted: (request, tokens) =>
					admit(request, tokens, { readBinding, tokenTypeOf }, schemes),
			};
		}),
	],
);
