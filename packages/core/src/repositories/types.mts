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

export interface Client {
	clientId: string;
	clientSecret: string;
	allowedRedirectUris: string[];
	allowedScopes: string[];
}

export interface User {
	id: string;
	username: string;
	[key: string]: unknown;
}

export interface CodeData {
	code_challenge?: string;
	code_challenge_method?: string;
}

export interface Code extends CodeData {
	code: string;
	expiresIn?: number;
}
