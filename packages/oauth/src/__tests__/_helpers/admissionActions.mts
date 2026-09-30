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
 * Every action this package's modules register, for a test that builds a
 * resolver by hand beside a consumer it constructs itself.
 */

import {
	AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
	OAUTH_ROUTER_ADMISSION_ACTIONS,
	REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS,
	SESSION_GRANT_ADMISSION_ACTIONS,
} from "#/admissionActions.mjs";

export const OAUTH_ADMISSION_ACTIONS = {
	...OAUTH_ROUTER_ADMISSION_ACTIONS,
	...SESSION_GRANT_ADMISSION_ACTIONS,
	...AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
	...REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS,
};
