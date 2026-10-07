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
 * The two readings every admission stage takes of a value a caller or a
 * requirement handed in: an object is anything of type `object` but `null`,
 * and a string counts only when it is non-empty.
 */
export const nonEmptyString = (value) => typeof value === "string" && value.length > 0 ? value : undefined;
export const isObject = (value) => typeof value === "object" && value !== null;
