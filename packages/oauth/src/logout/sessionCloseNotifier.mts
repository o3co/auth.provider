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
 * The session-close notifier oauth contributes to core's session lifecycle:
 * one OIDC Back-Channel Logout token per notice, posted to the relying
 * party's `backchannel_logout_uri` as its registration reads when the notice
 * is sent. A notice is settled — resolved — once delivered, or when there is
 * nowhere to send it (no URI, no registration) or the relying party refused it
 * for good; it rejects only when it is worth sending again, so the lifecycle
 * keeps the work pending: the registry or the key store could not answer, the
 * request did not complete, or the answer was 408, 429 or a 5xx.
 *
 * A session's token carries its `sid` unless the relying party declined
 * one (`backchannel_logout_session_required: false`). A subject revocation's
 * is sub-scoped: it carries the `sid` only for a relying party that
 * registered for one.
 */

import {
	auditErrorText,
	type ClientRepository,
	type EventLogger,
	generateLogoutToken,
	type KeyStore,
	type SessionCloseNotice,
	type SessionCloseNotifier,
} from "@o3co/auth-provider-core";
import { postLogoutToken } from "./broadcastBackchannel.mjs";

export interface SessionCloseNotifierOptions {
	readonly clientRepository: ClientRepository;
	readonly keyStore: KeyStore;
	/** This provider's issuer, the logout token's `iss`. */
	readonly issuer: string;
	/** Defaults to the global `fetch`, as the back-channel broadcast's. */
	readonly fetchImpl?: typeof fetch;
	/** The deadline of one delivery, in milliseconds. Defaults to the broadcast's. */
	readonly timeoutMs?: number;
	/** Where a refusal settled for good is said, at warn; the broadcast's line. */
	readonly logger?: Pick<EventLogger, "warn">;
}

/** Whether an answer that is not a success is worth sending the notice again. */
const retryable = (status: number): boolean => status === 408 || status === 429 || status >= 500;

/** Whether `notice`'s token carries its `sid`, by the relying party's registration. */
const carriesSid = (notice: SessionCloseNotice, sessionRequired: boolean | undefined): boolean =>
	notice.cause === "subject_revocation" ? sessionRequired === true : sessionRequired !== false;

export function createSessionCloseNotifier(
	options: SessionCloseNotifierOptions,
): SessionCloseNotifier {
	return {
		async notify(notice) {
			const client = await options.clientRepository.findById(notice.clientId);
			const uri = client?.backchannelLogoutUri;
			if (client === null || client === undefined || uri === undefined || uri === "") return;
			const { token } = await generateLogoutToken({
				issuer: options.issuer,
				sub: notice.sub,
				aud: notice.clientId,
				sid: notice.sid,
				includeSid: carriesSid(notice, client.backchannelLogoutSessionRequired),
				keyStore: options.keyStore,
			});
			const answer = await postLogoutToken(uri, token, {
				...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
				...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
			});
			// The status alone, never the relying party's words for it.
			if (answer.ok) return;
			if (retryable(answer.status)) {
				throw new Error(`back-channel logout answered ${answer.status}; worth sending again`);
			}
			options.logger?.warn(
				{ clientId: auditErrorText(notice.clientId), status: answer.status },
				"logout_backchannel_rejected",
			);
		},
	};
}
