/*
 * Copyright 2026 1o1 Inc.
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
import { RESTClient } from "./base/RESTClient.mjs";

export class AppClient extends RESTClient {
	constructor({ baseURL, timeout }: { baseURL: string; timeout: number }) {
		super({ baseURL, timeout });
	}

	async authenticate({
		clientId,
		password,
	}: {
		clientId: string;
		password: string;
	}): Promise<Record<string, unknown>> {
		return await this.post("/client/authenticate", {
			body: {
				clientId,
				password,
			},
		});
	}

	async listAllowedRedirectUris(clientId: string): Promise<string[]> {
		return await this.get(`/clients/${clientId}/allowedRedirectUris`);
	}

	async listAllowedScopes(clientId: string): Promise<string[]> {
		return await this.get(`/clients/${clientId}/allowedScopes`);
	}

	async getCallbackUrl(clientId: string): Promise<{ url: string }> {
		return await this.get(`/clients/${clientId}/callbackUrl`);
	}
}
