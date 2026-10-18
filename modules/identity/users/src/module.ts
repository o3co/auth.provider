import { defineModule } from "@mod/kernel";
import { z } from "zod";
import { ledgers, users } from "./contract.ts";
import { contributedSource } from "./contributed.ts";
import { ledgerUsers } from "./ledger.ts";
import { keyOf, record, registeredUsers } from "./registered.ts";
import { contactStore, linkStore } from "./store.ts";

/** Identifiers match exactly; this form, folding case fully ("straße", "STRASSE", "STRAẞE"), only finds look-alikes. */
const confusable = (identifier: string) =>
	identifier.normalize("NFKC").trim().toLowerCase().toUpperCase();
const distinct = (values: string[]) => new Set(values).size === values.length;

const section = z
	.strictObject({
		registered: z
			.array(record)
			.prefault([])
			.describe("The users the settings register, each with its identifier and password hash."),
	})
	.refine((s) => distinct(s.registered.map((r) => confusable(r.identifier))), {
		message:
			"identifiers are duplicated or differ only in case, Unicode normal form, or leading/trailing whitespace",
		path: ["registered"],
	})
	.refine((s) => distinct(s.registered.map((r) => r.subject ?? r.identifier)), {
		message: "two identifiers map to the same subject",
		path: ["registered"],
	})
	.refine((s) => distinct(s.registered.flatMap((r) => r.upstream.map(keyOf))), {
		message: "an upstream identity is linked to more than one user",
		path: ["registered"],
	});

export default defineModule({ name: "users", section }, (m) => [
	m.provide(users).by(async (c) => {
		const [ledger, ...more] = await c.collect(ledgers);
		if (more.length > 0) return c.refuse("users", "more than one user ledger is contributed");
		if (ledger && c.section.registered.length > 0) {
			return c.refuse(
				"users.registered",
				"users are registered while a user ledger is contributed",
			);
		}
		const source = ledger
			? contributedSource(ledger, c.log)
			: registeredUsers(c.section.registered, c.random.bytes);
		return ledgerUsers(source, await c.get(linkStore), await c.get(contactStore));
	}),
]);
