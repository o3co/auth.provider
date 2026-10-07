/*
 * Copyright 2026 1o1 Co. Ltd.
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

import {
	auditErrorText,
	generateLogoutToken,
	isOutboundRefusal,
	type KeyStore,
	type Logger,
	loggableError,
} from "@o3co/auth-provider-core";

export interface BroadcastRP {
	readonly clientId: string;
	readonly backchannelLogoutUri?: string | undefined;
	/**
	 * Whether the RP requires `sid` in the logout_token for session correlation.
	 * Defaults to `true` — include sid unless explicitly set to `false`.
	 */
	readonly backchannelLogoutSessionRequired?: boolean | undefined;
}

export interface BroadcastBackchannelLogoutOptions {
	readonly rps: ReadonlyArray<BroadcastRP>;
	/** Issuer URL of this auth provider. */
	readonly issuer: string;
	/** Subject identifier of the user being logged out. */
	readonly sub: string;
	/** Session ID being terminated. Included in each logout_token when the RP requires sid. */
	readonly sid: string;
	readonly keyStore: KeyStore;
	/**
	 * The fetch every POST goes through: core's
	 * `createOutboundFetch({ policy, source: "registration" })` over the
	 * `outboundPolicy` slot, built once, so `core.outbound` applies. Anything
	 * else replaces that policy.
	 */
	readonly fetchImpl: typeof fetch;
	/** Per-request timeout in milliseconds. Defaults to 5000ms. */
	readonly timeoutMs?: number;
	/** Optional structured logger. Defaults to `console`. */
	readonly logger?: Logger;
}

const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * POSTs one logout_token to `uri` as OIDC Back-Channel Logout 1.0 §2.5 has
 * it, a form body, through `options.fetchImpl` alone, under one deadline
 * (default 5000ms): the relying party's answer's status, its body left unread
 * and cancelled, or the rejection of a request that did not complete or that
 * the fetch refused.
 */
export async function postLogoutToken(
	uri: string,
	token: string,
	options: { readonly fetchImpl: typeof fetch; readonly timeoutMs?: number },
): Promise<{ readonly ok: boolean; readonly status: number }> {
	const fetchImpl = options.fetchImpl;
	const abort = new AbortController();
	const timer = setTimeout(() => abort.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
	try {
		const answer = await fetchImpl(uri, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ logout_token: token }).toString(),
			signal: abort.signal,
		});
		// Nothing of the body is read: release it.
		answer.body?.cancel().catch(() => undefined);
		return { ok: answer.ok, status: answer.status };
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Best-effort parallel POST of OIDC Back-Channel Logout 1.0 logout_token to each RP's
 * `backchannelLogoutUri`. Never throws; 4xx/5xx/network/timeout failures, and a
 * destination the outbound fetch refuses (`step: "destination"`, the RP treated as
 * unreachable), are logged via `opts.logger ?? console`. RPs without a
 * `backchannelLogoutUri` are skipped.
 */
export async function broadcastBackchannelLogout(
	opts: BroadcastBackchannelLogoutOptions,
): Promise<void> {
	const logger = opts.logger ?? console;

	const tasks = opts.rps
		.filter(
			(rp): rp is BroadcastRP & { backchannelLogoutUri: string } =>
				typeof rp.backchannelLogoutUri === "string" && rp.backchannelLogoutUri.length > 0,
		)
		.map(async (rp) => {
			try {
				const includeSid = rp.backchannelLogoutSessionRequired !== false;
				const { token } = await generateLogoutToken({
					issuer: opts.issuer,
					sub: opts.sub,
					aud: rp.clientId,
					sid: opts.sid,
					includeSid,
					keyStore: opts.keyStore,
				});
				try {
					const res = await postLogoutToken(rp.backchannelLogoutUri, token, {
						fetchImpl: opts.fetchImpl,
						...(opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs }),
					});
					if (!res.ok) {
						// The status, not the RP's own words for it.
						logger.warn(
							{ clientId: auditErrorText(rp.clientId), status: res.status },
							"logout_backchannel_rejected",
						);
					}
				} catch (err) {
					const step = isOutboundRefusal(err) ? "destination" : "post";
					logger.warn(
						{ clientId: auditErrorText(rp.clientId), step, err: loggableError(err) },
						"logout_backchannel_failed",
					);
				}
			} catch (err) {
				// The logout token could not be built or signed: no POST was made.
				logger.warn(
					{ clientId: auditErrorText(rp.clientId), step: "logout_token", err: loggableError(err) },
					"logout_backchannel_failed",
				);
			}
		});

	await Promise.all(tasks);
}
