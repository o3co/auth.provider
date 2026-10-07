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
 * The one reading of "a control character" in text an operator configures —
 * an issuer, a label, a header: a C0 control character
 * (U+0000–U+001F), DEL (U+007F) or a C1 control character (U+0080–U+009F),
 * but those a rule allows. Such a character in a header splits it; in a log
 * line or a label it forges another.
 */
/** Whether `text` carries a C0 control character, DEL or a C1 control character, other than one `allowed`. */
export function hasControlCharacter(text, allowed = new Set()) {
    for (let index = 0; index < text.length; index++) {
        const code = text.charCodeAt(index);
        if ((code <= 0x1f || (code >= 0x7f && code <= 0x9f)) && !allowed.has(text.charAt(index))) {
            return true;
        }
    }
    return false;
}
