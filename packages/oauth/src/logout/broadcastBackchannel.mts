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

import { generateLogoutToken, type KeyStore, type Logger } from "@o3co/auth-provider-core";

export interface BroadcastRP {
	readonly clientId: string;
	readonly backchannelLogoutUri?: string;
	/**
	 * Whether the RP requires `sid` in the logout_token for session correlation.
	 * Defaults to `true` — include sid unless explicitly set to `false`.
	 */
	readonly backchannelLogoutSessionRequired?: boolean;
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
	/** Override for unit tests. Defaults to the global `fetch`. */
	readonly fetchImpl?: typeof fetch;
	/** Per-request timeout in milliseconds. Defaults to 5000ms. */
	readonly timeoutMs?: number;
	/** Optional structured logger. Defaults to `console`. */
	readonly logger?: Logger;
}

const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Best-effort parallel POST of OIDC Back-Channel Logout 1.0 logout_token to each RP's
 * `backchannelLogoutUri`. Never throws; 4xx/5xx/network/timeout failures are logged via
 * `opts.logger ?? console`. RPs without a `backchannelLogoutUri` are skipped.
 */
export async function broadcastBackchannelLogout(
	opts: BroadcastBackchannelLogoutOptions,
): Promise<void> {
	const fetchImpl = opts.fetchImpl ?? fetch;
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
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
				const body = new URLSearchParams({ logout_token: token }).toString();
				const abort = new AbortController();
				const timer = setTimeout(() => abort.abort(), timeoutMs);
				try {
					const res = await fetchImpl(rp.backchannelLogoutUri, {
						method: "POST",
						headers: { "Content-Type": "application/x-www-form-urlencoded" },
						body,
						signal: abort.signal,
					});
					if (!res.ok) {
						logger.warn(
							`broadcastBackchannelLogout: RP ${rp.clientId} returned ${res.status} ${res.statusText ?? ""}`.trim(),
						);
					}
				} catch (err) {
					logger.warn(
						`broadcastBackchannelLogout: RP ${rp.clientId} POST to ${rp.backchannelLogoutUri} failed:`,
						err,
					);
				} finally {
					clearTimeout(timer);
				}
			} catch (err) {
				logger.warn(`broadcastBackchannelLogout: RP ${rp.clientId} broadcast failed:`, err);
			}
		});

	await Promise.all(tasks);
}
