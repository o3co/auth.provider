import { defineModule } from "@mod/kernel";
import { z } from "zod";
import { ledgers, type UpstreamNames, upstreamNames, users } from "./contract.ts";
import { contributedSource } from "./ledger/contributed.ts";
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

function namesRefused(declarations: readonly UpstreamNames[]): string[] {
	const declared = declarations.flatMap((d) =>
		d.names.map((n) => ({ ...n, declaredBy: d.declaredBy })),
	);
	const told = (n: (typeof declared)[number]) => `${n.issuer} (by ${n.declaredBy})`;
	const empty = declared.filter((n) => n.name === "" || n.issuer === "");
	const byName = Map.groupBy(declared, (n) => n.name);
	const shared = [...byName].filter(([, all]) => new Set(all.map((n) => n.issuer)).size > 1);
	return [
		...empty.map((n) => `an IdP name and its issuer cannot be empty: "${n.name}" ${told(n)}`),
		...shared.map(
			([name, all]) =>
				`the IdP name ${name} stands for more than one issuer: ${all.map(told).join(", ")}`,
		),
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
							reason: `no module declares the IdP name ${link.idp}`,
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
		const source = ledger
			? contributedSource(ledger, c.log)
			: registeredUsers(c.section.registered, c.random.bytes);
		return ledgerUsers(source, await c.get(linkStore), await c.get(contactStore));
	}),
]);
