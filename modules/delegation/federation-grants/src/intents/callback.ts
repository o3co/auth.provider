import type { GrantIntents, HeldTokens } from "../browser.ts";
import { credentialsFrom, type Grant, retentionMs } from "../grant/grant.ts";
import type { Common } from "./common.ts";
import { foundOf, type Judged, refOf } from "./found.ts";
import { carried } from "./intents.ts";

/** An intent's callback from the upstream: its round trip resumed, its tokens judged, and the grant activated. */
export function callbackWith({
	p,
	records,
	connections,
	secret,
	audited,
	liveIntent,
	back,
	failed,
}: Common): Pick<GrantIntents, "resumed" | "stillValid" | "judged" | "activated"> {
	return {
		resumed: async (taken) => {
			const kept = carried.safeParse(taken);
			const step = kept.success ? kept.data : undefined;
			const found = step ? await liveIntent(step) : undefined;
			if (!step || !found) return { kind: "stale" };
			const configured = connections.configured(found.grant.connection);
			if (!configured) return { kind: "unconfigured", ref: refOf(found) };
			const { grant, intent } = found;
			const { connection } = configured;
			return {
				kind: "resumed",
				ref: refOf(found),
				view: {
					subject: grant.subject,
					connection: grant.connection,
					idp: connection.idp,
					expected: {
						...(grant.upstream ? { held: grant.upstream } : {}),
						...(intent.expectedUpstream === undefined ? {} : { subject: intent.expectedUpstream }),
					},
					scopes: intent.scopes,
					...(connection.resource ? { resource: connection.resource } : {}),
					session: step.session,
				},
			};
		},
		stillValid: async (ref) => {
			const { grant, intent } = foundOf(ref);
			if (await p.judge.intentRevoked(grant, intent)) return "access_denied";
			if (intent.kind === "reauthorization" && (await p.judge.revoked(grant)))
				return "access_denied";
			return undefined;
		},
		judged: (ref, tokens) => {
			const { grant, intent } = foundOf(ref);
			const connection = connections.of(grant.connection);
			if (!connection) return { kind: "refused", why: "grant_not_authorizable" };
			const now = p.clock.now();
			const read = credentialsFrom(tokens, {
				now,
				maxAccessMs: connection["max-access-token-lifetime"] * 1000,
				shown: intent.scopes,
			});
			if (read.kind === "refused") return { kind: "refused", why: read.why };
			const judged: Judged = { credentials: read.credentials, now };
			return { kind: "held", tokens: Object.freeze(judged) as unknown as HeldTokens };
		},
		activated: async (ref, reached) => {
			const found = foundOf(ref);
			const { grant, intent } = found;
			// Judged at `now`, which the activation keeps.
			const { credentials, now } = reached.tokens as unknown as Judged;
			const { upstream } = reached;
			const changed = await p.grants.change(grant.id, (stored) => {
				const was = records.grantOf(stored);
				if (
					!was?.intent ||
					was.intent.id !== intent.id ||
					was.intent.ended ||
					was.intent.endsAt <= now ||
					was.status === "revoked"
				)
					return undefined;
				const { reason: _cleared, ...rest } = was;
				const next: Grant = {
					...rest,
					status: "active",
					scopes: intent.scopes,
					authorizedAt: now,
					expiresAt: now + intent.lifetimeMs,
					upstream: { issuer: upstream.issuer, subject: upstream.subject },
					intent: { ...intent, ended: "connected" },
					version: secret(),
					rotations: { from: now, count: 0 },
				};
				return {
					value: records.stored({ ...next, sealed: records.seal(next, credentials) }),
					lifetimeMs: intent.lifetimeMs + retentionMs,
				};
			});
			if (
				records.grantOf(changed?.after)?.intent?.ended !== "connected" ||
				records.grantOf(changed?.before)?.intent?.id !== intent.id
			) {
				return failed(ref, "grant_not_authorizable", reached);
			}
			audited.record(
				intent.kind === "initial" ? "federation.grant.authorized" : "federation.grant.reauthorized",
				{
					subject: grant.subject,
					attributes: {
						client: grant.client,
						connection: grant.connection,
						outcome: reached.identityCheck,
						...(reached.source ? { source: reached.source } : {}),
					},
				},
			);
			// The grant is active: what is left only tidies, and does not undo it.
			if (intent.kind === "initial") {
				try {
					await p.pending.remove(`${grant.client}\n${grant.subject}`, grant.id);
				} catch (error) {
					const kind = error instanceof Error ? error.name : typeof error;
					p.log.warn("federation-grants.pending_remove_failed", { kind });
				}
			}
			await p.listed(grant, intent.lifetimeMs + retentionMs);
			return back(found);
		},
	};
}
