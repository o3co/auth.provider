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
 * The account page's management of the signed-in subject's second factors,
 * under `/session/mfa/factors`, mounted from `routes.mts` behind its
 * `no-store`, body parsing, CSRF and flood guards, each route admitting the
 * session through `routes.mts` first.
 *
 * - `GET /factors`, admitted as `mfa.view`: every record of the subject,
 *   oldest first, with its state (`factorState.mts`) — `address_changed`
 *   for an email factor whose recorded address is not the one the
 *   session's login `User` holds — and a recovery set's codes left; never a
 *   record's data.
 * - `POST /factors/rename {factor_id, label}`, admitted as `mfa.manage`: the
 *   label written by compare-and-set at the version read, the data and last
 *   use as read; a lost race is `409`, nothing retried.
 * - `POST /factors/remove {factor_id}`, admitted as `mfa.manage`: under
 *   `required`, refused `409` when no other record of an installed counting
 *   kind stands. Audited `mfa.factor.removed`; once the records read again
 *   after it — or, unreadable, those read before less the one removed —
 *   hold none that may count (`mayCount`), the enrollment witness is cleared, and
 *   a clear that fails is said at warn, the removal standing.
 * - A factor named that is not the subject's is `400`; a store that cannot
 *   answer, or answers outside its port's contract, is `503`, logged once.
 */

import {
	type AuditSink,
	emitAuditEvent,
	errorEnvelope,
	isMfaFactorLabel,
	isMfaFactorUpdateWritten,
	type Logger,
	loggableError,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";
import express, { type Request, type Response, type Router } from "express";
import type { MfaAdmissionAction } from "./admissionActions.mjs";
import { type MfaCeremonySession, OUTSIDE_CONTRACT } from "./ceremony.mjs";
import { enrolledAddressDigest } from "./email/factor.mjs";
import { byAge, readFactorRecord } from "./factorState.mjs";
import { mayCount } from "./firstBinding.mjs";
import { matchesRecordedAddress } from "./mail.mjs";
import { recoveryCodesLeft } from "./recovery/factor.mjs";
import type { MfaRequirementMode } from "./requirement.mjs";
import type { MfaSealing } from "./sealing.mjs";
import type { MfaEnrollmentWitness } from "./witness.mjs";

const UNKNOWN_FACTOR = errorEnvelope("invalid_request", "Unknown second factor");
const INVALID_LABEL = errorEnvelope("invalid_request", "Invalid label");
const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const LAST_FACTOR = errorEnvelope(
	"mfa_last_factor",
	"The last second factor that counts cannot be removed",
);
const FACTOR_CONFLICT = errorEnvelope(
	"mfa_factor_conflict",
	"The factor changed while it was renamed: try again",
);

/** A record's state as the list names it: `factorState.mts`'s, or an email factor's changed address. */
export type MfaListedState =
	| "usable"
	| "unreadable"
	| "not_installed"
	| "exhausted"
	| "address_changed";

export interface MfaManagementOptions {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly sealing: MfaSealing;
	/** `mfa.mode`: under `required` the last record of an installed counting kind stays. */
	readonly mode: MfaRequirementMode;
	/** The enrollment witness a removal that leaves nothing that may count clears. */
	readonly witness: MfaEnrollmentWitness;
	/** The signed-in session the request's cookie carries, admitted for `action`; `undefined` once the refusal is answered. */
	readonly admit: (
		req: Request,
		res: Response,
		action: MfaAdmissionAction,
	) => Promise<MfaCeremonySession | undefined>;
	readonly logger: Logger;
	readonly auditSink: AuditSink | undefined;
}

/** A date as the list answers it; none for one that is not a valid date. */
const isoOf = (at: Date | undefined): string | undefined =>
	at instanceof Date && Number.isFinite(at.getTime()) ? at.toISOString() : undefined;

/** The management routes' router (see this file's header). */
export function createMfaManagementRouter(options: MfaManagementOptions): Router {
	const { factors, factorStore, sealing, mode, witness, admit, logger, auditSink } = options;
	const router = express.Router();

	/** A factor store's outage: logged once, answered `503`. */
	const unavailable = (res: Response, step: string, cause: unknown): void => {
		logger.error(
			{ route: "factors", store: "mfa_factor", step, err: loggableError(cause) },
			"mfa_store_unavailable",
		);
		res.status(503).json(MFA_UNAVAILABLE);
	};

	/** The subject's records, oldest first; `undefined` once the outage is answered. */
	const recordsOf = async (
		res: Response,
		subject: string,
	): Promise<MfaFactorRecord[] | undefined> => {
		let records: unknown;
		try {
			records = await factorStore.list(subject);
		} catch (cause) {
			unavailable(res, "list", cause);
			return undefined;
		}
		if (!Array.isArray(records)) {
			unavailable(res, "list", OUTSIDE_CONTRACT);
			return undefined;
		}
		return [...(records as MfaFactorRecord[])].sort(byAge);
	};

	/** The record `factorId` names among `records`, else none. */
	const named = (
		records: readonly MfaFactorRecord[],
		factorId: unknown,
	): MfaFactorRecord | undefined =>
		typeof factorId === "string" ? records.find((record) => record.id === factorId) : undefined;

	/** `record`'s state for `session`, and the codes a recovery set has left. */
	const listed = (
		session: MfaCeremonySession,
		record: MfaFactorRecord,
	): { readonly state: MfaListedState; readonly codesLeft?: number } => {
		const read = readFactorRecord({ factors, sealing }, session.subject, record);
		if (read.state === "not_installed" || read.state === "unreadable") return read;
		const codesLeft = recoveryCodesLeft(read.factor, read.data);
		const recorded = enrolledAddressDigest(read.factor, read.data);
		if (read.state === "usable" && recorded !== undefined) {
			const compared = matchesRecordedAddress(
				sealing.digestsFor(record.kind),
				session.user.email,
				recorded,
			);
			if (compared !== "match") {
				return { state: compared === "mismatch" ? "address_changed" : "unreadable" };
			}
		}
		return codesLeft === undefined ? { state: read.state } : { state: read.state, codesLeft };
	};

	router
		.get("/factors", async (req: Request, res: Response) => {
			const session = await admit(req, res, "mfa.view");
			if (session === undefined) return;
			const records = await recordsOf(res, session.subject);
			if (records === undefined) return;
			res.status(200).json({
				factors: records.map((record) => {
					const { state, codesLeft } = listed(session, record);
					const createdAt = isoOf(record.createdAt);
					const lastUsedAt = isoOf(record.lastUsedAt);
					return {
						id: record.id,
						kind: record.kind,
						...(typeof record.label === "string" ? { label: record.label } : {}),
						...(createdAt === undefined ? {} : { created_at: createdAt }),
						...(lastUsedAt === undefined ? {} : { last_used_at: lastUsedAt }),
						...(record.binding === undefined ? {} : { binding: record.binding }),
						state,
						...(codesLeft === undefined ? {} : { recovery_codes_remaining: codesLeft }),
					};
				}),
			});
		})
		.post("/factors/rename", async (req: Request, res: Response) => {
			const session = await admit(req, res, "mfa.manage");
			if (session === undefined) return;
			const body = req.body as { factor_id?: unknown; label?: unknown } | undefined;
			const label = body?.label;
			if (!isMfaFactorLabel(label)) {
				res.status(400).json(INVALID_LABEL);
				return;
			}
			const records = await recordsOf(res, session.subject);
			if (records === undefined) return;
			const record = named(records, body?.factor_id);
			if (record === undefined) {
				res.status(400).json(UNKNOWN_FACTOR);
				return;
			}
			let written: unknown;
			try {
				written = await factorStore.update(session.subject, record.id, record.version, {
					data: record.data,
					label,
					lastUsedAt: record.lastUsedAt,
				});
			} catch (cause) {
				unavailable(res, "update", cause);
				return;
			}
			if (written === null) {
				res.status(409).json(FACTOR_CONFLICT);
				return;
			}
			const asked = {
				subject: session.subject,
				id: record.id,
				expectedVersion: record.version,
				next: { data: record.data },
			};
			if (!isMfaFactorUpdateWritten(written, asked)) {
				unavailable(res, "update", OUTSIDE_CONTRACT);
				return;
			}
			res.status(200).json({ factor: { id: record.id, kind: record.kind, label } });
		})
		.post("/factors/remove", async (req: Request, res: Response) => {
			const session = await admit(req, res, "mfa.manage");
			if (session === undefined) return;
			const records = await recordsOf(res, session.subject);
			if (records === undefined) return;
			const record = named(records, (req.body as { factor_id?: unknown } | undefined)?.factor_id);
			if (record === undefined) {
				res.status(400).json(UNKNOWN_FACTOR);
				return;
			}
			const others = records.filter((other) => other.id !== record.id);
			if (
				mode === "required" &&
				!others.some((other) => factors.get(other.kind)?.counting === true)
			) {
				res.status(409).json(LAST_FACTOR);
				return;
			}
			try {
				await factorStore.remove(session.subject, record.id);
			} catch (cause) {
				unavailable(res, "remove", cause);
				return;
			}
			emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "mfa.factor.removed",
				subject: session.subject,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: {
					kind: record.kind,
					...(record.binding === undefined ? {} : { binding: record.binding }),
					by: "user",
				},
			});
			let remaining: readonly MfaFactorRecord[] = others;
			try {
				const again: unknown = await factorStore.list(session.subject);
				if (Array.isArray(again)) {
					remaining = (again as MfaFactorRecord[]).filter((other) => other.id !== record.id);
				}
			} catch {
				// The records read before, less the one removed, decide.
			}
			if (!remaining.some((other) => mayCount(factors, other))) {
				const cleared = await witness.clear(session.subject);
				if (cleared.outcome === "unwritten") {
					logger.warn(
						{ sub: session.subject, err: loggableError(cleared.cause) },
						"mfa_enrollment_witness_uncleared",
					);
				}
			}
			res.status(200).json({});
		});

	return router;
}
