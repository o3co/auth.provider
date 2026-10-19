import { defineModule } from "@mod/kernel";
import { secretCheckers } from "@mod/secret-hash";
import { z } from "zod";
import { ledgers, type UpstreamNames, upstreamNames, users } from "./contract.ts";
import { contributedSource } from "./ledger/contributed.ts";
import { ledgerUsers } from "./ledger.ts";
import { keptLinks } from "./links/kept.ts";
import { ledgerLinks } from "./links/ledger.ts";
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

function namesRefused(declarations: readonly UpstreamNames[]): string[] {
	const declared = declarations.flatMap((d) =>
		d.names.map((n) => ({ ...n, declaredBy: d.declaredBy })),
	);
	// Told by the modules that declare them alone: a name and an issuer are configured values.
	const empty = declared.filter((n) => n.name === "" || n.issuer === "");
	const byName = Map.groupBy(declared, (n) => n.name);
	const shared = [...byName].filter(([, all]) => new Set(all.map((n) => n.issuer)).size > 1);
	const asDeclared = (all: readonly (typeof declared)[number][]) => {
		const by = [...new Set(all.map((n) => n.declaredBy))];
		return `as ${by.join(", ")} ${by.length === 1 ? "declares" : "declare"} it`;
	};
	return [
		...empty.map((n) => `an IdP name or its issuer is empty, ${asDeclared([n])}`),
		...shared.map(([, all]) => `an IdP name stands for more than one issuer, ${asDeclared(all)}`),
	];
}

/** Each registered link through an IdP no module declares a name for: nothing would ever look it up. */
function undeclaredLinks(
	registered: z.output<typeof section>["registered"],
	declarations: readonly UpstreamNames[],
) {
	const declared = new Set(declarations.flatMap((d) => d.names.map((n) => n.name)));
	return registered.flatMap((user, i) =>
		user.upstream.flatMap((link, j) =>
			declared.has(link.idp)
				? []
				: [
						{
							where: `users.registered.${i}.upstream.${j}.idp`,
							reason: "no module declares this IdP name",
						},
					],
		),
	);
}

export default defineModule({ name: "users", section }, (m) => [
	m.provide(users).by(async (c) => {
		const declarations = await c.collect(upstreamNames);
		const refused = namesRefused(declarations);
		if (refused.length > 0) return c.refuse("users", refused.join("; "));
		const undeclared = undeclaredLinks(c.section.registered, declarations);
		if (undeclared.length > 0) return c.refuseAll(undeclared);
		const [ledger, ...more] = await c.collect(ledgers);
		if (more.length > 0) return c.refuse("users", "more than one user ledger is contributed");
		if (ledger && c.section.registered.length > 0) {
			return c.refuse(
				"users.registered",
				"users are registered while a user ledger is contributed",
			);
		}
		// This assembly's checkers, which share its limit on checks under way.
		const checkers = await c.get(secretCheckers);
		const source = ledger
			? contributedSource(ledger, c.log)
			: registeredUsers(c.section.registered, (inUse) => checkers.checkerOf(inUse));
		// A ledger that looks users up by upstream identity has the last word there, so no link store is asked for.
		const linking = ledger?.byUpstream
			? ledgerLinks(source)
			: keptLinks(source, await c.get(linkStore));
		return ledgerUsers(source, linking, await c.get(contactStore));
	}),
]);
