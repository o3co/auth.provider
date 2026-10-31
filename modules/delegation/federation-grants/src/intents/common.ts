import { declaredAudit } from "@mod/audit";
import events from "../audit-events.ts";
import type { Back, GrantIntents, Sourced } from "../browser.ts";
import { connectionsIn, type Intent, returnsTo, type Step, secretFrom } from "../grant/grant.ts";
import { type Found, foundOf } from "./found.ts";
import { browserBase, type IntentsParts } from "./intents.ts";

/** What every step of a grant's intents works with: the grant and its intent read and changed, a step taken once, and the way back. */
export function commonWith(p: IntentsParts) {
	const { records, settings } = p;
	const secret = secretFrom(p.random);
	const connections = connectionsIn(settings, p.upstreams);
	const audited = declaredAudit(p.audit, events);
	const callbackUrl = (name: string) => `${p.origin}${browserBase}/callback/${name}`;
	const failure = ({ grant }: Found, outcome: string, from: Sourced) =>
		audited.record("federation.grant.authorization_failed", {
			subject: grant.subject,
			attributes: {
				client: grant.client,
				connection: grant.connection,
				outcome,
				...(from.source ? { source: from.source } : {}),
			},
		});

	/** The grant and its intent, while the intent is the grant's current one, not ended and within its time. */
	const liveIntent = async (step: Pick<Step, "grant" | "intent"> | undefined) => {
		if (!step) return undefined;
		const grant = records.grantOf(await p.grants.read(step.grant));
		const intent = grant?.intent;
		if (!grant || !intent || intent.id !== step.intent || intent.ended) return undefined;
		if (intent.endsAt <= p.clock.now() || grant.status === "revoked") return undefined;
		return { grant, intent };
	};
	/** Changes the intent only while it is still the grant's current one, unended and, unless the change ends it, within its time. */
	const changeIntent = (
		{ grant, intent }: Found,
		next: (intent: Intent) => Intent | undefined,
		{ ending = false } = {},
	) =>
		p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (!now?.intent || now.intent.id !== intent.id || now.intent.ended) return undefined;
			if (!ending && now.intent.endsAt <= p.clock.now()) return undefined;
			const changed = next(now.intent);
			return changed && { value: records.stored({ ...now, intent: changed }) };
		});
	/** Takes a step once: answers it as it was, or none when it was taken already or does not match. */
	const take = async (secretText: string, kind: Step["kind"]) => {
		const changed = await p.steps.change(secretText, (stored) => {
			const step = records.stepOf(stored);
			if (!step || step.kind !== kind || step.taken) return undefined;
			return { value: records.storedStep({ ...step, taken: true }) };
		});
		const before = records.stepOf(changed?.before);
		const after = records.stepOf(changed?.after);
		return before && !before.taken && after?.taken ? before : undefined;
	};
	/** Back to the intent's return URI with the grant, the client's state and what came of it, if the client still lists it. */
	const back = async ({ grant, intent }: Found, error?: string): Promise<Back> => {
		if (!returnsTo(await p.clients.find(grant.client), intent.returnUri)) return { kind: "stale" };
		const to = new URL(intent.returnUri);
		to.searchParams.set("grant_id", grant.id);
		to.searchParams.set("state", intent.state);
		if (error) to.searchParams.set("error", error);
		return { kind: "back", location: to.href };
	};
	const failed: GrantIntents["failed"] = async (ref, error, from) => {
		const found = foundOf(ref);
		await changeIntent(found, (i) => ({ ...i, ended: error }), { ending: true });
		failure(found, from.outcome ?? error, from);
		return back(found, error);
	};
	return {
		p,
		records,
		connections,
		secret,
		audited,
		callbackUrl,
		failure,
		liveIntent,
		changeIntent,
		take,
		back,
		failed,
	};
}

export type Common = ReturnType<typeof commonWith>;
