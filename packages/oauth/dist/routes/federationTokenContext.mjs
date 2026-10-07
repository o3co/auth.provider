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
 * What every stage of the federation token route reads: the router's options,
 * the per-request context (the federation's name as sent and as logged, the
 * logger, the store-outage line) and the claims of the caller's access token.
 */
import { loggableError, } from "@o3co/auth-provider-core";
/**
 * A store that cannot answer is `503`, logged once as
 * `federation_token_store_unavailable` with `store` and `step` and the
 * error's projection — never the error, which may quote a token record.
 */
export const createStoreUnavailableLog = (logger) => (federation, store, step, error) => {
    logger.error({ federation, store, step, err: loggableError(error) }, "federation_token_store_unavailable");
};
