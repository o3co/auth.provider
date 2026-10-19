import type { Client, Section } from "@mod/clients";
import { z } from "zod";
import type { Binding, SenderBinding } from "./contract.ts";

export interface BindingRequirement {
	readonly required: boolean;
	readonly kinds?: readonly string[] | undefined;
}

const requirementSection: Section<BindingRequirement> = {
	name: "sender-binding",
	schema: z.strictObject({
		required: z
			.boolean()
			.prefault(false)
			.describe(
				"Whether every token issued to the client is bound to its sender: a request that proves no binding is refused.",
			),
		kinds: z
			.array(z.string())
			.min(1)
			.optional()
			.describe(
				"The binding kinds the client's tokens may be bound by, by the names they give operators (such as dpop), each one composed; unwritten, any.",
			),
	}),
};

/** The section, refusing a name no composed kind has, and the answer over the composed kinds. */
export function requirementsOver(kinds: readonly SenderBinding[]) {
	const memberOf = new Map(kinds.flatMap((kind) => (kind.name ? [[kind.name, kind.member]] : [])));
	const section: Section<BindingRequirement> = {
		...requirementSection,
		checkAtBoot: ({ kinds: named }) =>
			named?.every((name) => memberOf.has(name)) === false
				? "names a binding kind nothing composed offers"
				: undefined,
	};
	const refusalOf = (client: Client, binding: Binding | undefined) => {
		const { required, kinds: named } = client.section(requirementSection);
		if (binding === undefined) return required ? "required" : undefined;
		const listed =
			named === undefined || named.some((name) => memberOf.get(name) === binding.member);
		return listed ? undefined : "kind";
	};
	return { section, refusalOf };
}
