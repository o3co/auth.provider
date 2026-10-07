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
 * The one log line for a {@link ClientRepository} that could not answer.
 *
 * Every route and grant that looks a client up answers a repository that
 * throws with `503 temporarily_unavailable` ("client repository unavailable")
 * — the store's outage, never the client's fault. Each also writes this line,
 * at error level, so the outage is seen where it is answered and reads the same
 * wherever it happened: client authentication, `/authorize`, token exchange,
 * the federation token route.
 *
 * @see ClientRepository
 */
import { auditErrorText } from "../errors/envelope.mjs";
import { loggableError } from "../logging/loggableError.mjs";
/**
 * Logs `client_repository_unavailable` at error level: the outage's `step`,
 * its `site` when given, the client id sanitised and capped, and the error's
 * projection (`loggableError`) — never the error, which can carry what the
 * store was sent.
 */
export function logClientRepositoryUnavailable(logger, outage, cause) {
    logger?.error({
        ...(outage.site !== undefined ? { site: outage.site } : {}),
        step: outage.step,
        clientId: auditErrorText(outage.clientId),
        err: loggableError(cause),
    }, "client_repository_unavailable");
}
