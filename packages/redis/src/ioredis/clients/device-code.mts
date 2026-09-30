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
 * The device authorization store's client over one ioredis connection: each operation one
 * script. A reply the create script does not document is an error, never a collision.
 */

import type { Redis } from "ioredis";
import type { DeviceCodeStoreClient } from "../../clients.mjs";
import { deviceCodeRecordOf } from "../codec.mjs";
import { runScript } from "../commands.mjs";
import {
	DEVICE_CODE_CREATE,
	DEVICE_CODE_DECIDE,
	DEVICE_CODE_FIND_PENDING,
	DEVICE_CODE_POLL,
	DEVICE_CODE_REMOVE,
} from "../scripts/device-code.mjs";

export function makeIoredisDeviceCodeStoreClient(io: Redis): DeviceCodeStoreClient {
	// Each device-code operation is one Lua script; see the `LUA_DEVICE_CODE_*` docblocks.
	const deviceCodeStoreClient: DeviceCodeStoreClient = {
		async create(keys, input) {
			const fields = Object.entries(input.fields).flatMap(([field, value]) =>
				value === undefined ? [] : [field, value],
			);
			const reply = await runScript(
				io,
				DEVICE_CODE_CREATE,
				[keys.codeKeyPrefix + input.deviceCode, keys.userKeyPrefix + input.userCode],
				[input.deviceCode, String(input.expiresAtMs), ...fields],
			);
			// 1 written, 0 a key already there. Any other reply is an error, not a collision the
			// endpoint would re-draw codes against.
			if (reply === 1) return true;
			if (reply === 0) return false;
			throw new Error(
				`deviceCodeStoreClient.create: unexpected reply from the create script (${typeof reply})`,
			);
		},
		async findPending(keys, userCode, nowMs) {
			const reply = await runScript(
				io,
				DEVICE_CODE_FIND_PENDING,
				[keys.userKeyPrefix + userCode],
				[keys.codeKeyPrefix, String(nowMs)],
			);
			return reply === null ? null : deviceCodeRecordOf(reply);
		},
		async decide(keys, userCode, nowMs, input) {
			const approval = input.decision === "approved" ? input : undefined;
			const reply = (await runScript(
				io,
				DEVICE_CODE_DECIDE,
				[keys.userKeyPrefix + userCode],
				[
					keys.codeKeyPrefix,
					String(nowMs),
					input.decision,
					approval?.subject ?? "",
					approval?.grantedScope === undefined ? "requested" : "narrow",
					JSON.stringify(approval?.grantedScope ?? []),
				],
			)) as [string, unknown?];
			switch (reply[0]) {
				case "ok":
					return { kind: "ok", fields: deviceCodeRecordOf(reply[1]) };
				case "already_decided":
					return {
						kind: "already_decided",
						status: reply[1] === "approved" ? "approved" : "denied",
					};
				case "expired":
					return { kind: "expired" };
				default:
					return { kind: "not_found" };
			}
		},
		async poll(keys, deviceCode, nowMs, slowDownIncrementSeconds) {
			const reply = (await runScript(
				io,
				DEVICE_CODE_POLL,
				[keys.codeKeyPrefix + deviceCode],
				[String(nowMs), keys.userKeyPrefix, String(slowDownIncrementSeconds)],
			)) as [string, unknown?];
			switch (reply[0]) {
				case "approved":
					return { kind: "approved", fields: deviceCodeRecordOf(reply[1]) };
				case "slow_down":
					return { kind: "slow_down", intervalSeconds: Number(reply[1]) };
				case "expired":
					return { kind: "expired" };
				case "denied":
					return { kind: "denied" };
				case "pending":
					return { kind: "pending" };
				default:
					return { kind: "not_found" };
			}
		},
		async remove(keys, deviceCode) {
			await runScript(
				io,
				DEVICE_CODE_REMOVE,
				[keys.codeKeyPrefix + deviceCode],
				[keys.userKeyPrefix],
			);
		},
	};
	return deviceCodeStoreClient;
}
