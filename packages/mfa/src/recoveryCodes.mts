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
 * - `401 login_required` with `Retry-After`: the subject's first-binding mark
 *   (`firstBindingMark.mts`), read under the lease, distrusts the session's
 *   sign-in — one made before a first binding, which admission may have taken
 *   on a recent primary while no factor stood; said at info
 *   (`mfa_first_binding_distrusted`). A mark that cannot be read is `503`.
 *   The distrust is widened by one lease — the owner's factor may land up to
 *   a lease after its mark, and a sign-in in that stretch on a clock up to
 *   the skew ahead must not pass. Every mark distrusts, so it also refuses,
 *   until the sign-in is later than the mark plus the skew and a lease: the session that bound the first
 *   factor (it got codes then), one whose login reconciled the witness, one
 *   signed in before a binding and stepped up after it, and a fresh MFA login
 *   on another device within the skew; a step-up in a session whose witness
 *   is not `enrolled` notes the mark again, and so arms it again. The mark is
 *   used because admission's verdicts cannot say "met only on recent MFA,
 *   else enrollment required" for one action, and the route may not read the
 *   session record's `mfaAt` beside admission's view.
 * - `409 mfa_request_stale`: the request reached its lease longer after it
 *   began than a mark can be relied on — its lifetime less the skew and a
 *   lease — so a mark noted meanwhile may have lapsed; nothing written.
 * - `409 mfa_factor_limit`: the set would take the subject past
 *   `mfa.maxFactorsPerSubject` (`recordsAfterRecoveryCodes`: replacing a set
 *   at the limit stays allowed); nothing written.
 * - `409 mfa_recovery_codes_conflict`: the subject's factor set changed
 *   after the lease read it — another write landed, which only a writer past
 *   its own lease can make — so the new set was not written, the floor not
 *   raised, and no codes answered (warn).
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
	type MfaFactorResolver,
} from "@o3co/auth-provider-core";
import express, { type Request, type Response, type Router } from "express";
import type { MfaFactorSet } from "./factorSet.mjs";
import { mayCount, recordsAfterRecoveryCodes } from "./firstBinding.mjs";
import { type FirstBindingMark, readFirstBindingMark } from "./firstBindingMark.mjs";
import type { MfaManagingSession } from "./management.mjs";
import { RECOVERY_CODE_FACTOR_KIND } from "./recovery/factor.mjs";
import { issueRecoveryCodes, type MfaIssuedRecoveryCodes } from "./recovery/issue.mjs";
import type { MfaSealing } from "./sealing.mjs";

const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const NOT_ISSUED = errorEnvelope("invalid_request", "Recovery codes are not issued here");
const LOGIN_REQUIRED = errorEnvelope("login_required", "Log in again");
const REQUEST_STALE = errorEnvelope(
	"mfa_request_stale",
	"The request took too long to be checked safely: try again",
);
const FACTOR_LIMIT = errorEnvelope(
	"mfa_factor_limit",
	"The subject holds as many second factors as it may",
);
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
	/** `mfa.maxFactorsPerSubject`. */
	readonly maxFactorsPerSubject: number;
	/** The subject's first-binding mark (`MfaTransactionStore.firstBindingAt`), read under the lease. */
	readonly firstBindingAt: (subject: string, nowMs: number) => Promise<unknown>;
	/** The first-binding mark as every reader judges it (`createFirstBindingMark`). */
	readonly firstBindingMark: FirstBindingMark;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

/** What the write under the lease came to. */
type Regenerated =
	| { readonly outcome: "no_counting_factor" }
	| { readonly outcome: "unmarked"; readonly cause: unknown }
	| { readonly outcome: "distrusted"; readonly retryAfterMs: number }
	| { readonly outcome: "stale" }
	| { readonly outcome: "factor_limit" }
	| { readonly outcome: "issued"; readonly codes: MfaIssuedRecoveryCodes };

/** The regeneration route's router (see this file's header). */
export function createMfaRecoveryCodesRouter(options: MfaRecoveryCodesOptions): Router {
	const { factors, factorSet, sealing, admit, logger, auditSink, maxFactorsPerSubject } = options;
	const now = options.now ?? (() => Date.now());
	const router = express.Router();

	/** A store's outage: logged once, answered `503`. */
	const unavailable = (res: Response, store: string, step: string, cause: unknown): void => {
		logger.error({ route: ROUTE, store, step, err: loggableError(cause) }, "mfa_store_unavailable");
		res.status(503).json(MFA_UNAVAILABLE);
	};

	router.post("/recovery-codes", async (req: Request, res: Response) => {
		// Taken before the admission: what the lease's mark read is measured against.
		const startedAtMs = now();
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
				const records = writes.factors.records;
				// Admission took a subject with none on a recent primary: no codes stand alone.
				if (!records.some((record) => mayCount(factors, record))) {
					return { outcome: "no_counting_factor" };
				}
				// A session signed in before a first binding may have been admitted while no factor stood.
				let mark: number | null;
				try {
					mark = readFirstBindingMark(
						await writes.read(() => options.firstBindingAt(subject, nowMs)),
						nowMs,
					);
				} catch (cause) {
					return { outcome: "unmarked", cause };
				}
				if (mark !== null && options.firstBindingMark.distrusts(session.authTimeMs, mark)) {
					return {
						outcome: "distrusted",
						retryAfterMs: options.firstBindingMark.retryAfterMs(mark, nowMs),
					};
				}
				// Two legs: admission's own mark read covers a mark noted before this request
				// began; this read covers one noted since, while it stands.
				if (now() - startedAtMs > options.firstBindingMark.readCoversMs) {
					return { outcome: "stale" };
				}
				if (recordsAfterRecoveryCodes(factors, records, "mfa") > maxFactorsPerSubject) {
					return { outcome: "factor_limit" };
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
		if (done.outcome === "no_counting_factor") {
			res.status(409).json(NO_COUNTING_FACTOR);
			return;
		}
		if (done.outcome === "unmarked") {
			unavailable(res, "mfa_transaction", "firstBindingAt", done.cause);
			return;
		}
		if (done.outcome === "distrusted") {
			logger.info({ route: ROUTE, sub: subject }, "mfa_first_binding_distrusted");
			res.set("Retry-After", String(Math.max(1, Math.ceil(done.retryAfterMs / 1000))));
			res.status(401).json(LOGIN_REQUIRED);
			return;
		}
		if (done.outcome === "stale") {
			res.status(409).json(REQUEST_STALE);
			return;
		}
		if (done.outcome === "factor_limit") {
			res.status(409).json(FACTOR_LIMIT);
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
