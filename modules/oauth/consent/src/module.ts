import { metadataSections } from "@mod/clients";
import { routes, site } from "@mod/http";
import { defineModule, Unavailable } from "@mod/kernel";
import { askKey, storedOf } from "./ask.ts";
import { clientSection } from "./client-section.ts";
import { consents } from "./contract.ts";
import { answerRoute, showRoute } from "./routes.ts";
import { section } from "./section.ts";
import { httpsUrl, spaceOrControl } from "./shapes.ts";
import { askStore, grantStore, type StoredGrant } from "./store.ts";

/** A grant is kept as its range, distinct and sorted. */
const rangeOf = (record: StoredGrant | undefined) =>
	(record as unknown as readonly string[] | undefined) ?? [];
const grantOf = (range: readonly string[]) => [...new Set(range)].sort() as unknown as StoredGrant;
/** One key per subject and client, whatever either holds. */
const grantKey = (clientId: string, subject: string) => JSON.stringify([subject, clientId]);
/** A consent range: distinct strings, none empty, none holding whitespace or a control character. */
const isRange = (range: readonly string[]) =>
	range.every((r) => r !== "" && !spaceOrControl.test(r)) && new Set(range).size === range.length;

export default defineModule({ name: "consent", section }, (m) => [
	m.contribute(metadataSections).by(() => clientSection),
	m.provide(consents).by(async (c) => {
		const grants = await c.get(grantStore);
		const asks = await c.get(askStore);
		const origin = (await c.get(site)).origin;
		if (origin === undefined) return c.refuse("consent", "a public origin is required");
		/** Destinations are https URLs on this deployment's own origin; the caller made them. */
		const onOrigin = (url: string) => httpsUrl(url)?.origin === origin;
		const { page } = c.section;
		return {
			granted: async (clientId, subject) => rangeOf(await grants.read(grantKey(clientId, subject))),
			covers: async (clientId, subject, range) => {
				const record = await grants.read(grantKey(clientId, subject));
				const known = new Set(rangeOf(record));
				return record !== undefined && range.every((r) => known.has(r));
			},
			grant: async (clientId, subject, range) => {
				const key = grantKey(clientId, subject);
				const widen = (record: StoredGrant) => ({ value: grantOf([...rangeOf(record), ...range]) });
				if (await grants.update(key, widen)) return;
				if ((await grants.save(key, grantOf(range), "endless")) === "created") return;
				// Another request saved it first: widen what it saved.
				if (!(await grants.update(key, widen))) throw new Unavailable("consent");
			},
			asking: page !== undefined,
			ask: async (session, asked) => {
				if (page === undefined) throw new TypeError("consent: no consent page is set to ask on");
				if (!onOrigin(asked.onAccept) || !onOrigin(asked.onDeny)) {
					throw new TypeError("consent: destinations must be https URLs on the public origin");
				}
				if (!isRange(asked.range)) {
					throw new TypeError("consent: a range is distinct strings without spaces or controls");
				}
				const challenge = Buffer.from(c.random.bytes(32)).toString("base64url");
				const lifetimeMs = c.section["challenge-lifetime"] * 1000;
				const record = storedOf({
					...asked,
					range: [...asked.range],
					subject: session.context.subject,
					deadline: c.clock.now() + lifetimeMs,
				});
				const saved = await asks.save(askKey(session.id, challenge), record, lifetimeMs);
				if (saved !== "created") throw new Unavailable("consent");
				const sent = new URL(page);
				sent.searchParams.set("challenge", challenge);
				return sent.href;
			},
		};
	}),
	m.contribute(routes).by(showRoute),
	m.contribute(routes).by(answerRoute),
]);
