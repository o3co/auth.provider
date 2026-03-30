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
import { Client as BaseClient } from "./BaseClient.mjs";

export class HttpError extends Error {
	constructor(
		public readonly status: number,
		message: string,
	) {
		super(message);
		this.name = "HttpError";
	}
}

export class RESTClient extends BaseClient {
	private baseURL: string;

	private timeout: number;

	constructor({ baseURL, timeout }: { baseURL: string; timeout: number }) {
		super();
		this.baseURL = baseURL;
		this.timeout = timeout;
	}

	async get<T>(
		endpoint: string,
		options: {
			params?: Record<string, string>;
			headers?: Record<string, string>;
		} = {},
	): Promise<T> {
		return await this.fetch<T>({
			endpoint,
			method: "GET",
			params: options.params,
			headers: options.headers,
		});
	}

	async post<T>(
		endpoint: string,
		options: {
			body?: unknown;
			params?: Record<string, string>;
			headers?: Record<string, string>;
		} = {},
	): Promise<T> {
		return await this.fetch<T>({
			endpoint,
			method: "POST",
			body: options.body,
			params: options.params,
			headers: options.headers,
		});
	}

	async delete<T>(
		endpoint: string,
		options: {
			params?: Record<string, string>;
			headers?: Record<string, string>;
		} = {},
	): Promise<T> {
		return await this.fetch<T>({
			endpoint,
			method: "DELETE",
			params: options.params,
			headers: options.headers,
		});
	}

	async put<T>(
		endpoint: string,
		options: {
			body?: unknown;
			params?: Record<string, string>;
			headers?: Record<string, string>;
		} = {},
	): Promise<T> {
		return await this.fetch<T>({
			endpoint,
			method: "PUT",
			body: options.body,
			params: options.params,
			headers: options.headers,
		});
	}

	async fetch<T>({
		endpoint,
		method,
		body,
		params,
		headers,
	}: {
		endpoint: string;
		method: string;
		body?: unknown;
		params?: Record<string, string>;
		headers?: Record<string, string>;
	}): Promise<T> {
		const qs = params ? `?${new URLSearchParams(params).toString()}` : "";

		let res: Response;
		try {
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), this.timeout);
			try {
				res = await fetch(`${this.baseURL + endpoint}${qs}`, {
					method,
					headers: {
						"Content-Type": "application/json",
						...headers,
					},
					body: body ? JSON.stringify(body) : undefined,
					signal: controller.signal,
				});
			} finally {
				clearTimeout(timer);
			}
		} catch (cause) {
			throw new Error("Network error", { cause });
		}

		if (!res.ok) {
			throw new HttpError(res.status, `HTTP ${res.status}: ${res.statusText}`);
		}

		return (await res.json()) as T;
	}
}
