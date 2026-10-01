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
 * `POST /oauth/token`: dispatches on `grant_type` to the registered grant,
 * after the checks every grant inherits (the client's grant-type allowlist,
 * its sender constraint, a strict grant's deny-by-absence), and answers
 * RFC 6749 §5.1 or §5.2. It audits every issuance and refusal it answers.
 */

import {
	type AuditSink,
	auditErrorText,
	emitAuditEvent,
	errorEnvelope,
	type GrantHandlerResolver,
	type GrantHandlerResult,
	isGrantTypeAllowed,
	isWellFormedErrorCode,
	type Logger,
	ownedConfirmation,
	type SenderConstraint,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { stepUpOf } from "../admission.mjs";
import { resolveRealm } from "../middleware/clientAuth.mjs";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";

/**
 * The `reason` of a grant handler's `token.issued.failure`: its
 * `error_description`, or its `error` when it gives none.
 *
 * A grant's `error` alone does not tell its refusals apart — token exchange
 * answers a malformed request and a stolen, unproven bound token alike with
 * `invalid_request` (RFC 8693 §2.2.2) — while the description names the check
 * that refused. Some descriptions quote client input, so it is recorded
 * through core's `auditErrorText` (sanitised and capped) to bound what a
 * client can put into the audit stream. A description that is empty or not a
 * string — a JavaScript policy's deny can carry anything — falls back to the
 * code.
 */
const auditReason = (error: string, errorDescription: unknown): string =>
	auditErrorText(errorDescription) || auditErrorText(error);

export const createTokenHandler =
	({
		registry,
		options,
		canonicalIssuer,
		auditSink,
		logger,
	}: {
		/** Where `grant_type` is looked up, per request. */
		readonly registry: Pick<GrantHandlerResolver, "get">;
		readonly options: Pick<ResolvedOAuthOptions, "requireGrantTypeAllowlist">;
		readonly canonicalIssuer: string;
		readonly auditSink: AuditSink | undefined;
		readonly logger: Logger;
	}): RequestHandler =>
	async (req: Request, res: Response) => {
		const { grant_type } = req.body;

		if (typeof grant_type !== "string" || grant_type === "") {
			await emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "token.issued.failure",
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { reason: "missing_grant_type" },
			});
			// RFC 6749 §5.2: a missing required parameter is `invalid_request`;
			// `unsupported_grant_type` is reserved for a value the server does
			// not support, which the next branch answers.
			return res.status(400).json({
				error: "invalid_request",
				error_description: "grant_type must be a non-empty string",
			});
		}

		const handler = registry.get(grant_type);
		if (!handler) {
			await emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "token.issued.failure",
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { reason: "unsupported_grant_type", grant_type: auditErrorText(grant_type) },
			});
			return res.status(400).json({
				error: "unsupported_grant_type",
				error_description: sanitizeErrorText(`grant_type '${grant_type}' is not supported`),
			});
		}

		// `clientAuthMw` populates `req.oauthClient` after RFC 6749 §2.3
		// authentication. Grant handlers consult `ctx.authenticatedClient`
		// rather than the raw body so identity flows are not body-spoofable.
		const ctx = {
			body: req.body,
			session: req.session,
			issuer: canonicalIssuer,
			metadata: { ip: req.ip },
			ip: req.ip,
			userAgent: req.get("user-agent"),
			tokenBinding: req.tokenBinding,
			authenticatedClient: req.oauthClient
				? {
						clientId: req.oauthClient.clientId,
						tokenEndpointAuthMethod: req.oauthClient.tokenEndpointAuthMethod,
						allowedScopes: req.oauthClient.allowedScopes,
						defaultScopes: req.oauthClient.defaultScopes,
						allowedGrantTypes: req.oauthClient.allowedGrantTypes,
						allowedAudiences: req.oauthClient.allowedAudiences,
						senderConstrained: req.oauthClient.senderConstrained,
						// The authorization-code grant applies the same
						// per-client PKCE method list `/authorize` applied when
						// it minted the code, so the opt-in has to travel with
						// the authenticated identity.
						allowPlainPkce: req.oauthClient.allowPlainPkce,
					}
				: null,
		};
		// allowedGrantTypes is enforced at dispatch, like the
		// sender-constraint check below: it runs once for every grant_type
		// before the concrete handler, so every grant — including one
		// registered later through `GrantFactory` — inherits it without
		// opting in.
		//
		// Absence of the field is "no policy declared", not "deny", so a
		// registration written before the field existed keeps its grants.
		// A deployment that has audited its registrations flips that with
		// `oauth.requireGrantTypeAllowlist`, read once at composition for
		// both enforcement points. Handlers that declare
		// `requiresExplicitGrantAllowlist` add deny-by-absence on top (just
		// before the handler runs, below), so machine-to-machine access is
		// never acquired by omission.
		//
		// RFC 6749 §5.2 `unauthorized_client`: "The authenticated client is
		// not authorized to use this authorization grant type."
		if (
			!isGrantTypeAllowed(ctx.authenticatedClient?.allowedGrantTypes, grant_type, {
				requireAllowlist: options.requireGrantTypeAllowlist,
			})
		) {
			await emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "token.issued.failure",
				clientId: req.oauthClient?.clientId,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { reason: "grant_type_not_allowed", grant_type },
			});
			return res.status(400).json({
				error: "unauthorized_client",
				error_description: sanitizeErrorText(
					`client is not authorized for grant_type '${grant_type}'`,
				),
			});
		}

		// senderConstrained enforcement at dispatch: runs once for every
		// grant_type before the concrete handler, so custom grants
		// registered via GrantFactory inherit the check. No-op when the
		// client did not opt into a sender constraint.
		const sc: SenderConstraint | undefined = ctx.authenticatedClient?.senderConstrained;
		if (sc?.required) {
			// Use truthy check (not `=== undefined`) so a custom downstream
			// middleware that sets `req.tokenBinding = null` cannot bypass
			// the constraint. The type contract is `tokenBinding?:
			// TokenBinding` so this is purely defensive at the JS layer.
			if (!ctx.tokenBinding) {
				await emitAuditEvent(auditSink, {
					timestamp: new Date(),
					type: "token.issued.failure",
					clientId: req.oauthClient?.clientId,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: {
						reason: "sender_constraint_no_binding",
						grant_type,
						required_methods: sc.methods,
					},
				});
				// The realm is a property of the deployment, so it comes from
				// the router-scope `canonicalIssuer` (config only) through the
				// same filter `clientAuthMw` uses.
				//
				// `Basic` challenge: this response is `invalid_client` + 401,
				// and RFC 6749 §5.2 requires a challenge matching the scheme
				// the client authenticated with via the Authorization header.
				// Whether `invalid_client` is the right code here is a
				// separate, breaking question; changing the challenge alone
				// would make the pair non-conformant.
				return res
					.status(401)
					.set("WWW-Authenticate", `Basic realm="${resolveRealm(canonicalIssuer)}"`)
					.json(
						errorEnvelope(
							"invalid_client",
							sanitizeErrorText("sender-constrained binding required, none provided"),
						),
					);
			}
			if (!sc.methods.includes(ctx.tokenBinding.kind)) {
				await emitAuditEvent(auditSink, {
					timestamp: new Date(),
					type: "token.issued.failure",
					clientId: req.oauthClient?.clientId,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: {
						reason: "sender_constraint_kind_mismatch",
						grant_type,
						presented_kind: ctx.tokenBinding.kind,
						required_methods: sc.methods,
					},
				});
				return res
					.status(400)
					.json(
						errorEnvelope(
							"unauthorized_client",
							sanitizeErrorText(`client not allowed to use kind=${ctx.tokenBinding.kind}`),
						),
					);
			}
			// The kind is allowed, but the binding must also carry a member
			// that kind owns: every grant stamps `ownedConfirmation` and
			// nothing else, so a binding with none — a DPoP binding
			// presenting an mTLS thumbprint, a contributed kind core has no
			// confirmation for — would be minted an unbound Bearer token,
			// and the required constraint downgraded without a word. A client
			// that does not require a constraint gets that unbound token,
			// advertised as Bearer; this one is refused.
			if (ownedConfirmation(ctx.tokenBinding) === undefined) {
				await emitAuditEvent(auditSink, {
					timestamp: new Date(),
					type: "token.issued.failure",
					clientId: req.oauthClient?.clientId,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: {
						reason: "sender_constraint_unowned_confirmation",
						grant_type,
						presented_kind: ctx.tokenBinding.kind,
						required_methods: sc.methods,
					},
				});
				return res
					.status(400)
					.json(
						errorEnvelope(
							"invalid_request",
							"sender-constrained binding carries no confirmation its mechanism owns",
						),
					);
			}
		}
		// Deny-by-absence for handlers that declare
		// `requiresExplicitGrantAllowlist`. The base check above admits an
		// absent allowlist ("no policy declared"); a strict handler refuses
		// exactly that case, so the grant is never acquired by omission.
		// Strictness is a property of the handler contract, and this is the
		// single place both rules compose.
		// - Position: after the sender-constraint gate, immediately before
		//   the handler.
		// - Skipped when `authenticatedClient` is null: client_credentials
		//   rejects null itself with `invalid_client`, and WebAuthn
		//   deliberately serves unauthenticated passkey callers.
		// - The denial goes through the shared result path below (not an
		//   early `res.json`), so it is audited like any grant's refusal.
		//   Its description is the base check's, word for word, so a client
		//   cannot tell which of the two rules refused it.
		const strictAllowlistDenial: GrantHandlerResult | null =
			handler.requiresExplicitGrantAllowlist === true &&
			ctx.authenticatedClient !== null &&
			ctx.authenticatedClient.allowedGrantTypes === undefined
				? {
						result: {
							status: 400,
							error: "unauthorized_client",
							errorDescription: `client is not authorized for grant_type '${grant_type}'`,
						},
					}
				: null;
		const { result, sessionMutation } = strictAllowlistDenial ?? (await handler.handle(ctx));

		if (sessionMutation?.clear) {
			for (const key of sessionMutation.clear) {
				(req.session as unknown as Record<string, unknown>)[key] = undefined;
			}
		}
		if (sessionMutation?.set) {
			Object.assign(req.session, sessionMutation.set);
		}

		if ("tokens" in result) {
			res.set("Cache-Control", "no-store");
			res.set("Pragma", "no-cache");
			await emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "token.issued",
				// Prefer the authenticated client over the raw body — body
				// `client_id` is not authoritative once `clientAuthMw` runs.
				clientId: req.oauthClient?.clientId,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { grant_type },
			});
			return res.status(result.status).json(result.tokens);
		}
		// RFC 6749 §5.2: `error` is 1*NQSCHAR. A grant can hand back any
		// code — a policy deny carries the policy's own — so one outside
		// that set, or none, goes out as `invalid_request`, and the code is
		// logged, sanitised, for whoever wired the grant or its policy.
		let error = result.error;
		if (!isWellFormedErrorCode(error)) {
			logger.warn(
				{ grant_type, error: auditErrorText(String(error)) },
				"token_error_code_malformed",
			);
			error = "invalid_request";
		}
		const errorBody: Record<string, unknown> = { error };
		// RFC 6749 §5.2's character set, whichever grant wrote it: several
		// quote the client's own input (a scope, an audience, a token type).
		// A description that is empty or not a string is not sent: RFC 6749
		// A.8 makes the field 1*NQSCHAR, and a JavaScript policy's deny,
		// passed through by core's policy evaluation, can carry anything.
		const errorDescription = sanitizeErrorText(result.errorDescription);
		if (errorDescription) errorBody.error_description = errorDescription;
		// A grant whose session can be met by a step-up names the
		// requirement beside `invalid_grant`, the one error it qualifies, so
		// an updated client can offer it (ADR 2026-09-28-session-admission).
		// A requirement's name is held to the same character set as `error`:
		// core refuses to register one outside it (the same
		// `isWellFormedErrorCode`), and a grant built by hand may set any
		// `step_up`, so it is checked again.
		const stepUp = error === "invalid_grant" ? stepUpOf(result) : undefined;
		if (stepUp !== undefined && isWellFormedErrorCode(stepUp)) errorBody.step_up = stepUp;
		// Do NOT inject `WWW-Authenticate: Bearer` here: the token endpoint
		// is not a protected resource (RFC 6750 §3), and `clientAuthMw`
		// already set the `WWW-Authenticate: Basic realm="..."` challenge
		// for client-auth failures, which Bearer would clobber for any grant
		// returning 401. RFC 6749 §5.2 does not mandate WWW-Authenticate.
		await emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "token.issued.failure",
			clientId: req.oauthClient?.clientId,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: {
				grant_type,
				error,
				reason: auditReason(error, result.errorDescription),
			},
		});
		return res.status(result.status).json(errorBody);
	};
