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
import { createClient, type RedisClientType } from "redis";
import logger from "#/logger.mjs";
import { Client as BaseClient } from "./BaseClient.mjs";

export class RedisClient extends BaseClient {
	protected _redis: RedisClientType;

	constructor({ endpointUri, password }: { endpointUri: string; password: string }) {
		super();

		this._redis = createClient({
			url: endpointUri,
			password: password,
			socket: {
				reconnectStrategy: (retries) => {
					const jitter = Math.floor(Math.random() * 200);
					const delay = Math.min(2 ** retries * 50, 2000);
					return delay + jitter;
				},
			},
		});
	}

	async initialize(): Promise<void> {
		try {
			await this._redis.connect();
		} catch (cause) {
			logger.error(cause);
			throw cause;
		}
	}

	get redis(): RedisClientType {
		return this._redis;
	}
}
