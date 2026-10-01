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
 * The write of the MFA enrollment witness to the Store's `markMfaEnrolled`
 * endpoint (README, "The Store's MFA endpoints"), on the transport of the
 * client that sends it.
 *
 * Guarantees: only `{ subject, enrolled }` — a non-empty string and a
 * boolean — is sent, and anything else is a `RangeError` before any request;
 * `204` alone is done; `404` throws `unknown_subject` and any other status
 * `unexpected_status`, through `storeFailure.mts`, the body released unread;
 * a transport failure, the deadline and a refused credential throw the
 * transport's errors, naming the client given as `owner`.
 */

import type { MfaStoreMarkEnrolledRequest } from "@o3co/auth-provider-core";
import { postToStore, type StoreRequestSettings } from "../storeTransport.mjs";
import { mfaStoreRequestMessages, mfaStoreStatusError } from "./storeFailure.mjs";

/** Posts `{ subject, enrolled }` to `url`; resolves on a `204` and throws on anything else. */
export async function markMfaEnrolledAtStore(
	url: string,
	settings: StoreRequestSettings,
	owner: string,
	subject: string,
	enrolled: boolean,
): Promise<void> {
	if (typeof subject !== "string" || subject.length === 0) {
		throw new RangeError(`${owner}: markMfaEnrolled takes a non-empty subject`);
	}
	if (typeof enrolled !== "boolean") {
		throw new RangeError(`${owner}: markMfaEnrolled takes enrolled as a boolean`);
	}
	const body: MfaStoreMarkEnrolledRequest = { subject, enrolled };
	const { response } = await postToStore(
		url,
		body,
		settings,
		mfaStoreRequestMessages(owner, "markMfaEnrolled", url),
		() => false,
	);
	if (response.status === 204) return;
	throw mfaStoreStatusError("markMfaEnrolled", url, response);
}
