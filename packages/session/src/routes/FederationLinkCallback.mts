/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The link callback: a federated identity linked to the account of the
 * session the link start recorded, and the federation attached to that live
 * session. It never mints a session, and a half-attached federation is
 * rolled back.
 */

import {
	cookieClaim,
	emitAuditEvent,
	type FederationProvider,
	type Logger,
	linkClaim,
	sanitizeErrorText,
	supportsClaimMapping,
	type UserRepository,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { consentedScope } from "../federations/consented-scope.mjs";
import type { LinkIntent } from "../federations/transaction.mjs";
import {
	admissionUnavailable,
	SESSION_STORE_UNAVAILABLE,
	USER_DIRECTORY_UNAVAILABLE,
} from "../internal/cookieSession.mjs";
import type { LinkedTokenLifetime } from "./FederationCallbackIdentity.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
import {
	cleanUp,
	type FederationStore,
	type FederationStoreStep,
	logStoreUnavailable,
} from "./FederationLog.mjs";
import { redirectAfterCallback } from "./FederationRedirectAnswer.mjs";

/**
 * The record's `tokenType` for what an adapter answered: the upstream's
 * spelling verbatim, even when it is not a token type, because the
 * disclosing route reads only an absent field as `Bearer` — erasing an
 * unusable value would turn a refusal into a 200. A non-string is recorded
 * as `""`, which that route also refuses.
 */
export const recordedTokenType = (named: unknown): string | undefined => {
	if (named === undefined) return undefined;
	return typeof named === "string" ? named : "";
};

/**
 * Link a federated identity to the account the browser is signed in as,
 * without minting a session. Reached only from an explicit `?link=1` start
 * whose envelope was verified like a login's. An identity resolving to
 * nobody asks the Store to link; to someone else is `409` (linking never
 * merges accounts); to this account links nothing new. The federation is
 * then attached to the live session (its upstream tokens under the current
 * `sid`, and a join through core's session lifecycle); no `UserSession` is
 * created and the session is not
 * regenerated. The session is admitted as `session.link_callback`; a
 * step-up is `login_required`, since the IdP's callback has no page to
 * return to.
 */
export const completeLink = async (
	ctx: FederationRouterContext,
	provider: FederationProvider,
	profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>,
	lifetime: LinkedTokenLifetime,
	identityToken: string,
	resolved: Awaited<ReturnType<UserRepository["authenticateByToken"]>>,
	redirectTo: string | undefined,
	link: LinkIntent,
	req: Request,
	res: Response,
	log: Logger,
): Promise<unknown> => {
	const { admitLink, auditSink, userRepository, federationTokenStore, sessionLifecycle } = ctx;
	// The link belongs to the session the start recorded, not whichever
	// session the browser holds now: a `form_post` callback arrives without
	// the session cookie (SameSite=Lax), so the recorded `sid` is the only
	// binding. A request that does carry an authenticated session must carry
	// that same one — switching accounts in between links nothing.
	const currentSid = link.sid;
	const cookie = cookieClaim(req);
	if (cookie.authenticated && cookie.sid !== currentSid) {
		return res.status(401).json({
			error: "login_required",
			error_description: "The link was started from a different session",
		});
	}
	const notLive = () =>
		res.status(401).json({
			error: "login_required",
			error_description: "Linking a federated identity requires a live session",
		});
	// A transaction recorded without a subject cannot form the link claim
	// (the sid and subject together): the user starts the link again.
	if (typeof link.subject !== "string" || link.subject.length === 0) return notLive();
	const admission = await admitLink(
		linkClaim({ sid: currentSid, subject: link.subject }),
		"session.link_callback",
		log,
	);
	if (admission.outcome === "unavailable") {
		return res.status(503).json(admissionUnavailable(admission.store));
	}
	// Not live, revoked, a requirement not met — or one asking for a
	// step-up, which the callback has no page to return to.
	if (admission.outcome !== "admitted" || admission.session === null) return notLive();
	const current = admission.session;
	// Every line the link writes names the session it was for.
	const linkContext = { sid: currentSid };
	// The three emissions below spell their `type` literally, which is what
	// the audit-inventory guard reads.
	const auditBase = () => ({
		timestamp: new Date(),
		subject: current.sub,
		ip: req.ip,
		userAgent: req.get("user-agent"),
	});

	if (resolved && resolved.id !== current.sub) {
		void emitAuditEvent(auditSink, {
			...auditBase(),
			type: "federation.identity.link_refused",
			details: { provider: provider.name, reason: "conflict" },
		});
		return res.status(409).json({
			error: "identity_conflict",
			error_description: "This federated identity is already linked to another account",
		});
	}
	if (!resolved) {
		if (typeof userRepository.linkFederatedIdentity !== "function") {
			return res.status(400).json({
				error: "link_unsupported",
				error_description: "The user repository does not support linking federated identities",
			});
		}
		const mapped = supportsClaimMapping(provider) ? provider.mapClaims(profile) : {};
		let outcome: Awaited<ReturnType<NonNullable<typeof userRepository.linkFederatedIdentity>>>;
		try {
			outcome = await userRepository.linkFederatedIdentity(current.sub, {
				provider: provider.name,
				sub: profile.sub,
				token: identityToken,
				claims: { ...(mapped as Record<string, unknown>) },
			});
		} catch (err) {
			logStoreUnavailable(
				log,
				"federation_link_store_unavailable",
				"user_repository",
				"link",
				err,
				linkContext,
			);
			return res.status(503).json(USER_DIRECTORY_UNAVAILABLE);
		}
		if (!outcome.ok) {
			void emitAuditEvent(auditSink, {
				...auditBase(),
				type: "federation.identity.link_refused",
				details: { provider: provider.name, reason: outcome.reason },
			});
			const conflict = outcome.reason === "conflict";
			return res.status(conflict ? 409 : 403).json({
				error: conflict ? "identity_conflict" : "link_refused",
				// The Store's own words when it gave any: an adapter's text, held to
				// RFC 6749's characters (Appendix A.8), with ours for one that is
				// absent, empty or not a string.
				error_description:
					sanitizeErrorText(outcome.description) ||
					(conflict
						? "This federated identity is already linked to another account"
						: "The user directory refused to link this identity"),
			});
		}
		void emitAuditEvent(auditSink, {
			...auditBase(),
			type: "federation.identity.linked",
			details: { provider: provider.name },
		});
	}

	// Whether the session already carried this federation, as the lifecycle
	// lists the federations it joined: a failed re-link must not take an
	// existing attachment down with it. `listed` says the read answered at
	// all — until it has, nothing was attached to the session and there is
	// nothing this request may undo (the Store's link above stands either
	// way).
	let hadFederation = false;
	let listed = false;
	// The step in flight, so the one catch that answers them all can log
	// the one that failed.
	let linking: { store: FederationStore; step: FederationStoreStep } = {
		store: "session_lifecycle",
		step: "federations",
	};
	try {
		const carried = await sessionLifecycle.federations(currentSid);
		if (carried.outcome !== "listed") {
			throw new Error("the session lifecycle did not list the session's federations");
		}
		hadFederation = carried.federations.includes(provider.name);
		listed = true;
		if (profile.accessToken) {
			linking = { store: "federation_token", step: "attach" };
			const consented = consentedScope(profile.scope, provider.scope);
			const tokenType = recordedTokenType(profile.tokenType);
			await federationTokenStore.attach(currentSid, provider.name, {
				accessToken: profile.accessToken,
				refreshToken: profile.refreshToken,
				idToken: profile.idToken,
				// The end, and when the token was obtained if that end counts
				// from this server's call, as the code exchange was read.
				...lifetime,
				// The consented scope: `scope` moves with the token;
				// `grantedScope` is the ceiling a refresh is bounded by (RFC 6749
				// §6) and never moves. They start equal.
				scope: consented,
				grantedScope: consented,
				// Recorded, not judged: a login does not need the access token,
				// so a type this provider cannot hand on must not cost the
				// sign-in; the disclosing route decides. Always written as a key,
				// since `FederationTokens` requires it.
				tokenType,
			});
		}
		// The federation joins the session once its tokens are attached: a
		// session closed since its admission is refused, and the lifecycle
		// removes those tokens.
		linking = { store: "session_lifecycle", step: "join" };
		const { outcome: joined } = await sessionLifecycle.join(currentSid, {
			federation: provider.name,
		});
		if (joined === "refused") return notLive();
		if (joined !== "joined") {
			throw new Error(`the session lifecycle answered ${joined} to the join`);
		}
	} catch (err) {
		logStoreUnavailable(
			log,
			"federation_link_store_unavailable",
			linking.store,
			linking.step,
			err,
			linkContext,
		);
		// Best-effort rollback. The Store's link stands (the identity is the
		// account's), but a half-attached federation's tokens must not be left
		// on the live session — unless the session already carried the
		// federation, or its federations could not even be read (then nothing
		// was written). Membership is the lifecycle's, written by the join.
		if (listed && !hadFederation) {
			await cleanUp(
				log,
				"federation_token",
				"delete",
				() => federationTokenStore.delete(currentSid, provider.name),
				linkContext,
			);
		}
		return res.status(503).json(SESSION_STORE_UNAVAILABLE);
	}
	return redirectAfterCallback(ctx, provider, redirectTo, res, log);
};
