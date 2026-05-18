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
 * Per-client sender-constraint requirement. See Wave 2 Token-binding
 * Cluster spec §4.8.
 *
 * When `required: true` and no binding is presented, the request is
 * rejected `invalid_client`. When `required: true` and a binding is
 * presented whose `kind` is not in `methods`, the request is rejected
 * `unauthorized_client`. When `required: false`, `methods` is advisory
 * (no rejection occurs based on it).
 */
export interface SenderConstraint {
	readonly required: boolean;
	readonly methods: readonly string[];
}
