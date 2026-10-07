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
 * is sent, through the fetch it is built with alone (core's outbound fetch,
 * under `core.outbound`). A notice is settled — resolved — once delivered, or
 * when there is nowhere to send it (no URI, no registration), the relying
 * party refused it for good, or the fetch refused the destination or the
 * answer (a redirect among them, never followed); it rejects only when it is
 * worth sending again, so the lifecycle keeps the work pending: the registry
 * or the key store could not answer, the request did not complete, or the
 * answer was 408, 429 or a 5xx.
 *
 * Every token carries the session's `sid` unless the relying party declined
 * one (`backchannel_logout_session_required: false`), whatever closed it.
 */

import {
	auditErrorText,
	type ClientRepository,
	type EventLogger,
	generateLogoutToken,
	isOutboundRefusal,
	type KeyStore,
	loggableError,
	type SessionCloseNotifier,
} from "@o3co/auth-provider-core";
import { postLogoutToken } from "./broadcastBackchannel.mjs";

export interface SessionCloseNotifierOptions {
	readonly clientRepository: ClientRepository;
	readonly keyStore: KeyStore;
	/** This provider's issuer, the logout token's `iss`. */
	readonly issuer: string;
	/**
	 * The fetch every POST goes through: core's
	 * `createOutboundFetch({ policy, source: "registration" })` over the
	 * `outboundPolicy` slot, so `core.outbound` applies. Anything else
	 * replaces that policy.
	 */
	readonly fetchImpl: typeof fetch;
	/** The deadline of one delivery, in milliseconds. Defaults to the broadcast's. */
	readonly timeoutMs?: number;
	/** Where a notice settled undelivered is said, at warn; the broadcast's lines. */
	readonly logger?: Pick<EventLogger, "warn">;
}

/** Whether an answer that is not a success is worth sending the notice again. */
const retryable = (status: number): boolean => status === 408 || status === 429 || status >= 500;

export function createSessionCloseNotifier(
	options: SessionCloseNotifierOptions,
): SessionCloseNotifier {
	// Required at run time too: no notice is posted outside the fetch it was given.
	if (typeof options.fetchImpl !== "function") {
		throw new TypeError(
			'createSessionCloseNotifier: fetchImpl is required; pass createOutboundFetch({ policy, source: "registration" })',
		);
	}
	const fetchImpl = options.fetchImpl;
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
				includeSid: client.backchannelLogoutSessionRequired !== false,
				keyStore: options.keyStore,
			});
			let answer: { readonly ok: boolean; readonly status: number };
			try {
				answer = await postLogoutToken(uri, token, {
					fetchImpl,
					...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
				});
			} catch (err) {
				if (!isOutboundRefusal(err)) throw err;
				// Refused by policy: sending it again is refused again.
				options.logger?.warn(
					{
						clientId: auditErrorText(notice.clientId),
						step: "destination",
						err: loggableError(err),
					},
					"logout_backchannel_failed",
				);
				return;
			}
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
