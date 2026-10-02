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
 * `POST /session/mfa/recovery-codes`: the signed-in subject's regeneration of
 * its recovery codes, mounted from `routes.mts` behind its `no-store`, body
 * parsing, CSRF and flood guards, the session admitted as `mfa.manage`
 * through `routes.mts` first, with where its factor-set write begins. What a
 * new set replaces, and how, is `recovery/issue.mts`'s; the lease is
 * `factorSet.mts`'s; this file answers what it came to.
 *
 * - `200 {"recovery_codes": [...]}`: the new set's codes, answered once — the
 *   set bound by `mfa`, and every set that stood retired and removed —
 *   audited `mfa.recovery_codes.generated` (`by: "user"`, `binding: "mfa"`,
 *   `regenerated`, and `unreplaced: true` when a retired set is left stored,
 *   said once at error). Codes marked shown are answered whatever else the
 *   write came to: a lease that ended before its release is said at error.
 * - `409 mfa_enrollment_required`: no record that may count stands, so
 *   admission took the session on a recent primary; codes are issued beside a
 *   counting factor only.
 * - `409 mfa_recovery_codes_conflict`: another set won at the same
 *   generation; this one was removed, its codes never answered (warn).
 * - `409 mfa_factors_busy` with `Retry-After`; `409 mfa_factors_changed` for a
 *   recovery or a reset since the request was admitted, nothing written.
 * - `400` while the recovery-code factor is off, before any lease; `503` for
 *   an outage — the codes not answered, the set left unshown — logged once at
 *   error.
 */

import {
	type AuditSink,
	emitAuditEvent,
	errorEnvelope,
	type Logger,
	loggableError,
	type MfaFactorRecord,
	type MfaFactorResolver,
} from "@o3co/auth-provider-core";
import express, { type Request, type Response, type Router } from "express";
import type { MfaFactorSet } from "./factorSet.mjs";
import { mayCount } from "./firstBinding.mjs";
import type { MfaManagingSession } from "./management.mjs";
import { RECOVERY_CODE_FACTOR_KIND } from "./recovery/factor.mjs";
import { issueRecoveryCodes, type MfaIssuedRecoveryCodes } from "./recovery/issue.mjs";
import type { MfaSealing } from "./sealing.mjs";

const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const NOT_ISSUED = errorEnvelope("invalid_request", "Recovery codes are not issued here");
const NO_COUNTING_FACTOR = errorEnvelope(
	"mfa_enrollment_required",
	"Recovery codes are issued beside a second factor that counts: enroll one first",
);
const CONFLICT = errorEnvelope(
	"mfa_recovery_codes_conflict",
	"The recovery codes were regenerated elsewhere at the same time: read them again",
);
const FACTORS_BUSY = errorEnvelope(
	"mfa_factors_busy",
	"The account's second factors are being changed: try again",
);
const FACTORS_CHANGED = errorEnvelope(
	"mfa_factors_changed",
	"The account's second factors changed: read them again",
);

/** The route's own name in its log lines. */
const ROUTE = "recovery-codes";

export interface MfaRecoveryCodesOptions {
	readonly factors: MfaFactorResolver;
	/** The subject's writes under its lease. */
	readonly factorSet: MfaFactorSet;
	readonly sealing: MfaSealing;
	/** The signed-in session the request's cookie carries, admitted as `mfa.manage`; `undefined` once the refusal is answered. */
	readonly admit: (req: Request, res: Response) => Promise<MfaManagingSession | undefined>;
	readonly logger: Logger;
	readonly auditSink: AuditSink | undefined;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

/** What the write under the lease came to. */
type Regenerated =
	| { readonly outcome: "unlisted"; readonly cause: unknown }
	| { readonly outcome: "no_counting_factor" }
	| { readonly outcome: "issued"; readonly codes: MfaIssuedRecoveryCodes };

/** The regeneration route's router (see this file's header). */
export function createMfaRecoveryCodesRouter(options: MfaRecoveryCodesOptions): Router {
	const { factors, factorSet, sealing, admit, logger, auditSink } = options;
	const now = options.now ?? (() => Date.now());
	const router = express.Router();

	/** A store's outage: logged once, answered `503`. */
	const unavailable = (res: Response, store: string, step: string, cause: unknown): void => {
		logger.error({ route: ROUTE, store, step, err: loggableError(cause) }, "mfa_store_unavailable");
		res.status(503).json(MFA_UNAVAILABLE);
	};

	router.post("/recovery-codes", async (req: Request, res: Response) => {
		const session = await admit(req, res);
		if (session === undefined) return;
		if (factors.get(RECOVERY_CODE_FACTOR_KIND) === undefined) {
			res.status(400).json(NOT_ISSUED);
			return;
		}
		const { subject } = session;
		const nowMs = now();
		const bound = await factorSet.bind(
			session.factorSetStart,
			subject,
			async (writes): Promise<Regenerated> => {
				let records: MfaFactorRecord[];
				try {
					const listed: unknown = await writes.factorStore.list(subject);
					if (!Array.isArray(listed)) {
						throw new TypeError("MfaFactorStore.list answered something that is not a list");
					}
					records = listed as MfaFactorRecord[];
				} catch (cause) {
					return { outcome: "unlisted", cause };
				}
				// Admission took a subject with none on a recent primary: no codes stand alone.
				if (!records.some((record) => mayCount(factors, record))) {
					return { outcome: "no_counting_factor" };
				}
				return {
					outcome: "issued",
					codes: await issueRecoveryCodes({
						factors,
						writes,
						sealing,
						subject,
						binding: "mfa",
						nowMs,
						listed: records,
					}),
				};
			},
		);
		if (bound.overran === true) {
			// What the write did stands; a recovery or a reset may have run beside it.
			logger.error({ route: ROUTE, sub: subject }, "mfa_subject_lease_overrun");
		}
		switch (bound.outcome) {
			case "busy":
				res.set("Retry-After", String(Math.max(1, bound.retryAfterSeconds)));
				res.status(409).json(FACTORS_BUSY);
				return;
			case "changed":
				res.status(409).json(FACTORS_CHANGED);
				return;
			case "unavailable":
				unavailable(res, bound.store, bound.step, bound.cause);
				return;
			case "bound":
				break;
		}
		const done = bound.done;
		if (done.outcome === "unlisted") {
			unavailable(res, "mfa_factor", "list", done.cause);
			return;
		}
		if (done.outcome === "no_counting_factor") {
			res.status(409).json(NO_COUNTING_FACTOR);
			return;
		}
		const codes = done.codes;
		if (codes === undefined) {
			res.status(400).json(NOT_ISSUED);
			return;
		}
		if (!codes.issued) {
			if (codes.conflict === true) {
				logger.warn({ sub: subject }, "mfa_recovery_codes_conflict");
				res.status(409).json(CONFLICT);
				return;
			}
			logger.error(
				{ sub: subject, err: loggableError(codes.cause) },
				"mfa_recovery_codes_unwritten",
			);
			res.status(503).json(MFA_UNAVAILABLE);
			return;
		}
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "mfa.recovery_codes.generated",
			subject,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: {
				kind: RECOVERY_CODE_FACTOR_KIND,
				binding: "mfa",
				by: "user",
				regenerated: codes.regenerated,
				// A retired set left stored: its codes verify nothing.
				...(codes.unreplaced === undefined ? {} : { unreplaced: true }),
			},
		});
		if (codes.unreplaced !== undefined && "cause" in codes.unreplaced) {
			logger.error(
				{ sub: subject, err: loggableError(codes.unreplaced.cause) },
				"mfa_recovery_codes_unreplaced",
			);
		}
		res.status(200).json({ recovery_codes: codes.codes });
	});

	return router;
}
