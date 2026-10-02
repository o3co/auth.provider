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
 * `POST /session/mfa/lock/release`: the signed-in subject's own release of
 * its MFA lock, mounted from `routes.mts` behind its `no-store`, body
 * parsing, CSRF and flood guards, the session admitted as `mfa.manage`
 * through `routes.mts` first. What is released, and when, is
 * `lockRecovery.mts`'s; this file answers what it came to.
 *
 * - `200 {"lock":"released"}`: given back — or given back before, on the
 *   same authorization.
 * - `200 {"lock":"held","hold":"hard"}` with a description and
 *   `rebind_after`: the week and the backoff may be given back, but
 *   guessable factors stay held until each is replaced after
 *   `rebind_after`; the page says so, never "released". Replacing them
 *   first, then releasing, spends one exempt proof.
 * - `403 mfa_exempt_proof_required`: no authorization stands in this
 *   session — a recovery code or a passkey verifies one.
 * - `409 mfa_lock_release_refused` with `reason`: `not_revoked_since`, no
 *   revocation of the subject's sessions since the attack began — the page
 *   asks for a password change — with `rebind_after` while the hard hold
 *   stands; `no_revocation_boundary`, none can be read here.
 * - `rebind_after` is from when a rebind counts, in ISO 8601 as
 *   `created_at` is in `GET /factors`: shown to the account holder, never
 *   logged.
 * - `409 mfa_factors_busy` with `Retry-After`; `503` for an outage, logged
 *   once at error.
 * - Logged `mfa_lock_released`, `mfa_lock_release_held` (the hard hold
 *   stands) and `mfa_lock_release_refused` at info; an
 *   authorization applied now is audited `mfa.lock.recovered` with the
 *   operation, the generation and what it cleared.
 */

import {
	type AuditSink,
	emitAuditEvent,
	errorEnvelope,
	type Logger,
	loggableError,
} from "@o3co/auth-provider-core";
import express, { type Request, type Response, type Router } from "express";
import type { MfaCeremonySession } from "./ceremony.mjs";
import type { MfaLockRecovery } from "./lockRecovery.mjs";

const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const EXEMPT_PROOF_REQUIRED = errorEnvelope(
	"mfa_exempt_proof_required",
	"Verify a recovery code or a passkey first, then release",
);
const FACTORS_BUSY = errorEnvelope(
	"mfa_factors_busy",
	"The account's second factors are being changed: try again",
);
const REFUSED = {
	not_revoked_since: {
		...errorEnvelope(
			"mfa_lock_release_refused",
			"Change the account's password, sign in again, then release",
		),
		reason: "not_revoked_since",
	},
	no_revocation_boundary: {
		...errorEnvelope(
			"mfa_lock_release_refused",
			"This deployment cannot give the hold back early: wait for it to end, or ask for a reset",
		),
		reason: "no_revocation_boundary",
	},
} as const;
const RELEASED = { lock: "released" } as const;
const HELD = {
	lock: "held",
	hold: "hard",
	description:
		"Guessable second factors stay held until each is replaced: replace them, verify a recovery code or a passkey again, then release",
} as const;

export interface MfaLockReleaseOptions {
	readonly lockRecovery: Pick<MfaLockRecovery, "release">;
	/** The signed-in session the request's cookie carries, admitted as `mfa.manage`; `undefined` once the refusal is answered. */
	readonly admit: (req: Request, res: Response) => Promise<MfaCeremonySession | undefined>;
	readonly logger: Logger;
	readonly auditSink: AuditSink | undefined;
}

/** The release's router (see this file's header). */
export function createMfaLockReleaseRouter(options: MfaLockReleaseOptions): Router {
	const { lockRecovery, admit, logger, auditSink } = options;
	const router = express.Router();

	router.post("/lock/release", async (req: Request, res: Response) => {
		const session = await admit(req, res);
		if (session === undefined) return;
		const released = await lockRecovery.release(session.subject, session.sid);
		switch (released.outcome) {
			case "released":
			case "held": {
				// A standing hard hold is never said as released.
				logger.info(
					{
						sub: session.subject,
						generation: released.generation,
						applied: released.applied,
						...(released.outcome === "held" ? { hold: released.hold } : {}),
					},
					released.outcome === "held" ? "mfa_lock_release_held" : "mfa_lock_released",
				);
				if (released.applied) {
					emitAuditEvent(auditSink, {
						timestamp: new Date(),
						type: "mfa.lock.recovered",
						subject: session.subject,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: {
							operation: "recover",
							generation: released.generation,
							cleared: { ...released.cleared },
						},
					});
				}
				res
					.status(200)
					.json(
						released.outcome === "held"
							? { ...HELD, rebind_after: released.rebindAfter.toISOString() }
							: RELEASED,
					);
				return;
			}
			case "refused":
				logger.info({ sub: session.subject, reason: released.reason }, "mfa_lock_release_refused");
				if (released.reason === "exempt_proof_required") {
					res.status(403).json(EXEMPT_PROOF_REQUIRED);
					return;
				}
				if (released.reason === "not_revoked_since" && released.rebindAfter !== null) {
					res.status(409).json({
						...REFUSED.not_revoked_since,
						rebind_after: released.rebindAfter.toISOString(),
					});
					return;
				}
				res.status(409).json(REFUSED[released.reason]);
				return;
			case "busy":
				res.set("Retry-After", String(Math.max(1, released.retryAfterSeconds)));
				res.status(409).json(FACTORS_BUSY);
				return;
			case "unavailable":
				logger.error(
					{
						route: "lock-release",
						store: released.store,
						step: released.step,
						err: loggableError(released.cause),
					},
					"mfa_store_unavailable",
				);
				res.status(503).json(MFA_UNAVAILABLE);
				return;
		}
	});

	return router;
}
