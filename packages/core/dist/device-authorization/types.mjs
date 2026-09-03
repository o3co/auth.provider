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
 * Absence policy for the `deviceCodeStore` slot (#363 discipline).
 *
 * Optional to wire, not optional to decide: a composition that mounts the
 * device grant without a store has no way to remember that a device is
 * waiting, so the grant cannot work at all. The policy makes that a boot
 * failure with a config key to set rather than a runtime surprise on the
 * first `/oauth/device_authorization` request.
 */
export const DEVICE_CODE_STORE_ABSENCE_POLICY = {
    configKey: ["oauth", "deviceAuthorization", "store"],
    absentValue: "unsupported",
    hint: "the device authorization grant has nowhere to record a pending authorization, " +
        "so no device can ever be authorized — every /oauth/device_authorization request " +
        "would fail at runtime instead of at boot",
};
