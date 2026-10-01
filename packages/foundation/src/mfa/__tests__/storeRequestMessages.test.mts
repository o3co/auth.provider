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
 * The wording of a transport failure at the Store's MFA endpoints, which
 * `mfaStoreRequestMessages` holds for every client that sends to them:
 * `HttpMfaFactorStore`'s factor endpoints and `HttpUserRepository`'s witness
 * endpoint throw the same message for the same failure, each naming its own
 * client and operation and the endpoint by origin and path.
 */

import { createServer as createNetServer, type Server as NetServer } from "node:net";
import { refusedOrigin } from "@o3co/auth-provider-test-kit";
import { afterEach, describe, expect, it } from "vitest";
import { HttpMfaFactorStore, HttpUserRepository, StoreTransportError } from "#/index.mjs";
import { mfaStoreRequestMessages } from "#/mfa/storeFailure.mjs";

let netServers: NetServer[] = [];
afterEach(async () => {
	await Promise.all(
		netServers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
	);
	netServers = [];
});

/** A loopback server that answers every request's head with `answer`, raw, and closes. */
async function answering(answer: string): Promise<string> {
	const server = createNetServer((socket) => {
		socket.on("error", () => {});
		let head = "";
		socket.on("data", (chunk: Buffer) => {
			head += chunk.toString("latin1");
			if (head.includes("\r\n\r\n")) socket.end(answer, "latin1");
		});
	});
	netServers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	return `http://127.0.0.1:${port}`;
}

/** Each transport failure: how a Store makes it, and the message key it is said with. */
const FAILURES = {
	unreachable: { origin: refusedOrigin, key: "unreachable" },
	connection_closed: { origin: () => answering(""), key: "closed" },
	malformed_response: {
		origin: () => answering(`HTTP/1.1 200 OK\r\nX-Big: ${"a".repeat(70_000)}\r\n\r\n`),
		key: "malformed",
	},
	unreadable: {
		origin: () =>
			answering(
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\nZZ broken\r\n",
			),
		key: "unreadable",
	},
} as const;

/** The error `promise` rejects with. */
async function rejection(promise: Promise<unknown>): Promise<StoreTransportError> {
	try {
		await promise;
	} catch (error) {
		return error as StoreTransportError;
	}
	throw new Error("expected a rejection");
}

/** What a failure of `reason` is said as, given `messages`: its message, and the code when there is one. */
const said = (
	messages: ReturnType<typeof mfaStoreRequestMessages>,
	key: (typeof FAILURES)[keyof typeof FAILURES]["key"],
	code: string | undefined,
): string => (code === undefined ? messages[key] : `${messages[key]} (${code})`);

describe("mfaStoreRequestMessages", () => {
	it("names the client, the operation and the endpoint by origin and path, never the query", () => {
		const messages = mfaStoreRequestMessages(
			"HttpUserRepository",
			"markMfaEnrolled",
			"https://store.example/mfa/enrolled?key=QUERY-SECRET",
		);
		const endpoint =
			"the Store's MFA markMfaEnrolled endpoint at https://store.example/mfa/enrolled";
		expect(messages).toEqual({
			owner: "HttpUserRepository",
			unreachable: `HttpUserRepository: ${endpoint} could not be reached`,
			closed: `HttpUserRepository: the connection to ${endpoint} closed before a complete response arrived`,
			malformed: `HttpUserRepository: ${endpoint} answered with a malformed HTTP response`,
			unreadable: `HttpUserRepository: the answer of ${endpoint} could not be read`,
		});
	});
});

describe("a transport failure at the Store's MFA endpoints is said in one wording by every client", () => {
	it.each(Object.keys(FAILURES) as (keyof typeof FAILURES)[])(
		"%s: HttpMfaFactorStore's list and HttpUserRepository's mark",
		async (reason) => {
			const { origin: make, key } = FAILURES[reason];
			const origin = await make();
			const listUrl = `${origin}/mfa/list`;
			const store = new HttpMfaFactorStore({
				listUrl,
				createUrl: `${origin}/mfa/create`,
				updateUrl: `${origin}/mfa/update`,
				deleteUrl: `${origin}/mfa/delete`,
				timeout: 5000,
			});
			const listed = await rejection(store.list("user-1"));
			expect(listed).toBeInstanceOf(StoreTransportError);
			expect(listed.reason).toBe(reason);
			expect(listed.message).toBe(
				said(mfaStoreRequestMessages("HttpMfaFactorStore", "list", listUrl), key, listed.code),
			);

			// The mark reads no body, so a body that breaks is a status it does not take.
			if (reason === "unreadable") return;
			const markUrl = `${origin}/mfa/enrolled`;
			const repository = new HttpUserRepository({
				authenticateUrl: `${origin}/authenticate`,
				authenticateByTokenUrl: `${origin}/authenticate-by-token`,
				markMfaEnrolledUrl: markUrl,
				timeout: 5000,
			});
			const marked = await rejection(repository.markMfaEnrolled?.("user-1", true) as Promise<void>);
			expect(marked).toBeInstanceOf(StoreTransportError);
			expect(marked.reason).toBe(reason);
			expect(marked.message).toBe(
				said(
					mfaStoreRequestMessages("HttpUserRepository", "markMfaEnrolled", markUrl),
					key,
					marked.code,
				),
			);
		},
	);
});
