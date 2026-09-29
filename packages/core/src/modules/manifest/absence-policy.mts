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
 * The declared-absence vocabulary for optional DI slots.
 *
 * An `optional` key alone reads as "absence means nothing to do", which lets a
 * capability look wired when it is not (revocation with no denylist, a
 * watermark nothing consults, an audit sink that discards every event). A
 * module attaches an {@link AbsencePolicy} to an optional key, and boot's
 * stage-1 guard (`checkDeclaredAbsence`) refuses to start with
 * `component-absence-undeclared` unless the slot is filled or config declares
 * the capability absent (e.g. `oauth.revocation.accessToken = "unsupported"`).
 *
 * The policy is **data, not code** (a config path and the one value that counts
 * as the declaration), so stage 1 stays deterministic and side-effect-free and
 * the boot error can name the exact line to write. A policy that needs to
 * compute absence means the declaration vocabulary is wrong, not that this
 * type needs a callback.
 */
export interface AbsencePolicy {
	/**
	 * Path into the parsed application config, one segment per element
	 * (`["audit", "sink", "type"]` reads `config.audit.sink.type`), where an
	 * operator declares the capability absent on purpose.
	 */
	readonly configKey: readonly string[];
	/**
	 * The one value at {@link configKey} that counts as the declaration,
	 * compared with `===`. A declaration that needs coercion should point at a
	 * schema-validated key instead.
	 */
	readonly absentValue: string;
	/**
	 * Operator-facing sentence appended to the boot error: what the slot does,
	 * so an operator choosing between wiring it and declaring it absent knows
	 * what the deployment loses.
	 */
	readonly hint: string;
}
