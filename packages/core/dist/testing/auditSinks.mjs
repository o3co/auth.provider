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
import { defineModule } from "../modules/manifest/index.mjs";
export function createRecordingAuditSink() {
    let events = Object.freeze([]);
    let failure;
    return {
        kind: "recording",
        get events() {
            return events;
        },
        async record(event) {
            if (failure !== undefined)
                throw failure.error;
            events = Object.freeze([...events, event]);
        },
        failWith(error) {
            failure = { error };
        },
        recover() {
            failure = undefined;
        },
    };
}
/**
 * A module named `audit-hooks-<name>` that contributes each of `hooks` as an
 * `auditHooks` entry, in order. `name` is one kebab-case word or more.
 */
export function auditHooksModule(name, ...hooks) {
    return defineModule({
        name: `audit-hooks-${name}`,
        contributes: { auditHooks: hooks.map((hook) => () => hook) },
    });
}
