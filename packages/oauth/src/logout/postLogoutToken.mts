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
