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
 * How `/oauth/introspect` answers when a store it needs did not answer: `503`,
 * never RFC 7662 §2.2's `active: false`, which is a verdict on the token.
 * Each such answer is audited as `introspect.store_unavailable`.
 */

import {
	type AuditSink,
	auditedError,
	emitAuditEvent,
	type Logger,
	loggableError,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { refuseVerificationUnavailable } from "../verificationUnavailable.mjs";

/** The answers, reported through the router's audit sink and logger. */
export const createIntrospectUnavailableAnswers = ({
	auditSink,
	logger,
}: {
	readonly auditSink: AuditSink | undefined;
	readonly logger: Logger;
}) => {
	/**
	 * Introspection that could not verify the token because the keystore or a
	 * revocation store did not answer: `503`, never RFC 7662 §2.2's
	 * `active: false`, which is a statement about the token and would send
	 * the client to discard a credential that may be perfectly good. Audited
	 * as `introspect.store_unavailable`. See README, "Introspection: which
	 * tokens a caller may ask about".
	 */
	const answerIntrospectionUnavailable = (
		req: Request,
		res: Response,
		err: Parameters<typeof refuseVerificationUnavailable>[1],
	): Response => {
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "introspect.store_unavailable",
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { reason: err.reason, cause: auditedError(err) },
		});
		return refuseVerificationUnavailable(res, err, logger, "introspect");
	};

	/**
	 * Introspection whose family or session check could not be made because
	 * the store did not answer: the same `503` as a verification outage, for
	 * the same reason, logged as `introspect_store_unavailable` with the
	 * error's projection — never the error, which can carry what the store
	 * was sent — and audited as `introspect.store_unavailable`, whose `cause`
	 * is core's `auditedError` (the error's name and code, never its message);
	 * the log line carries the rest. Core's session lifecycle answers its
	 * outage with no error, which it logs itself: that line and event carry
	 * none.
	 */
	const answerStoreUnavailable = (
		req: Request,
		res: Response,
		outage:
			| {
					readonly store: "refresh_token_family" | "user_session";
					readonly details: Readonly<Record<string, string>>;
					readonly cause: unknown;
			  }
			| {
					readonly store: "session_lifecycle";
					readonly details: Readonly<Record<string, string>>;
			  },
	): Response => {
		const cause = "cause" in outage ? { cause: outage.cause } : undefined;
		logger.error(
			{ store: outage.store, ...(cause ? { err: loggableError(cause.cause) } : {}) },
			"introspect_store_unavailable",
		);
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "introspect.store_unavailable",
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { ...outage.details, ...(cause ? { cause: auditedError(cause.cause) } : {}) },
		});
		return res.status(503).json({
			error: "temporarily_unavailable",
			error_description:
				outage.store === "refresh_token_family"
					? "refresh token store unavailable"
					: "session store unavailable",
		});
	};

	return { answerIntrospectionUnavailable, answerStoreUnavailable };
};
