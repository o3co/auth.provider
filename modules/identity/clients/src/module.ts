import { contract, defineModule } from "@mod/kernel";
import { type SecretChecker, secretCheckers } from "@mod/secret-hash";
import { z } from "zod";
import {
	authMethods,
	type Client,
	type ClientRecord,
	clientSources,
	clients,
	metadataSections,
	type Section,
} from "./contract.ts";
import {
	hashesOf,
	none,
	secretBasic,
	secretMethods,
	secretPost,
	secretSection,
} from "./methods.ts";
import { clientRecord, methodIssues, readRecord, registry } from "./registry.ts";

const section = z
	.strictObject({
		registered: z
			.array(clientRecord)
			.prefault([])
			.describe(
				"The clients the operator registers: each an id (unique), a kind (public or confidential), a method and sections (values by section name, client-secret holding its hash).",
			),
	})
	.refine((s) => new Set(s.registered.map((r) => r.id)).size === s.registered.length, {
		message: "duplicate client id",
		path: ["registered"],
	});

/** A refusal at a registered client's section, by its place alone: never the client's id or a value. */
const sectionRefusal = (where: string, name: string, reason: string) => ({
	where: `${where}.sections.${name}`,
	reason,
});

/** The boot checks of a registered client that reads well: its secret, and each section check it carries. */
function refusedAtBoot(
	entry: ClientRecord,
	client: Client,
	known: ReadonlyMap<string, Section<unknown>>,
	where: string,
) {
	// Not a checkAtBoot: that runs only for a client that carries its section.
	const secret =
		secretMethods.includes(entry.method) && client.section(secretSection).hash === undefined
			? [
					sectionRefusal(
						where,
						secretSection.name,
						"its method needs a secret, and it holds no hash",
					),
				]
			: [];
	return secret.concat(
		[...known.values()].flatMap((s) => {
			if (!s.checkAtBoot || !Object.hasOwn(entry.sections, s.name)) return [];
			const reason = s.checkAtBoot(client.section(s), client);
			return reason === undefined ? [] : [sectionRefusal(where, s.name, reason)];
		}),
	);
}

const byName = (sections: readonly Section<unknown>[]) => new Map(sections.map((s) => [s.name, s]));

const registered = contract<ReadonlyMap<string, Client>>("clients.registered");
const secrets = contract<SecretChecker>("clients.secrets");

/** Each registered client read, by id, and every refusal of the entries, each at its place. */
async function registeredOf(
	entries: readonly ClientRecord[],
	known: ReadonlyMap<string, Section<unknown>>,
	methods: ReadonlySet<string>,
) {
	const found = new Map<string, Client>();
	const issues: { where: string; reason: string }[] = [];
	for (const [i, entry] of entries.entries()) {
		if (!methods.has(entry.method)) {
			issues.push({
				where: `clients.registered.${i}.method`,
				reason: "unknown authentication method",
			});
		}
		const read = await readRecord(entry, known, "registered");
		if ("client" in read) {
			found.set(entry.id, read.client);
			issues.push(...refusedAtBoot(entry, read.client, known, `clients.registered.${i}`));
		} else {
			issues.push(
				...read.issues.map((issue) => ({
					where: `clients.registered.${i}.sections.${issue.path}`,
					reason: issue.message,
				})),
			);
		}
	}
	return { found, issues };
}

export default defineModule(
	{
		name: "clients",
		// Safe on many instances given the same registered clients on each (deployment-guarantees, Several
		// instances).
		replicaSafe: true,
		section,
		takes: [authMethods, metadataSections, clientSources, secretCheckers],
	},
	(m) => [
		// This assembly's checkers, which share its limit on checks under way.
		m
			.provide(secrets)
			.by(async (c) => (await c.get(secretCheckers)).checkerOf(hashesOf(c.section.registered))),
		m.contribute(authMethods).by(async (c) => secretBasic(await c.get(secrets))),
		m.contribute(authMethods).by(async (c) => secretPost(await c.get(secrets))),
		m.contribute(authMethods).by(() => none),
		m.contribute(metadataSections).by(() => secretSection),
		m.provide(registered).by(async (c) => {
			const known = byName(await c.collect(metadataSections));
			const methods = new Set((await c.collect(authMethods)).map((a) => a.name));
			const { found, issues } = await registeredOf(c.section.registered, known, methods);
			if (issues.length > 0) return c.refuseAll(issues);
			return found;
		}),
		m.provide(clients).by(async (c) => {
			const methods = await c.collect(authMethods);
			// Refused before the registered clients are read: assembly builds `registered` on its own all
			// the same, so its refusals are reported with these in the one boot.
			const issues = methodIssues(methods);
			if (issues.length > 0) return c.refuseAll(issues);
			return registry(
				await c.get(registered),
				await c.collect(clientSources),
				methods,
				byName(await c.collect(metadataSections)),
			);
		}),
	],
);
