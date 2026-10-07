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
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { z } from "zod";
export const UserEntrySchema = z
    .object({
    password: z.string().min(1),
    id: z.string().optional(),
})
    .catchall(z.unknown());
export class InMemoryUserRepository {
    users;
    constructor(users) {
        this.users = users;
    }
    toUser(username, entry) {
        const { password: _, ...rest } = entry;
        return {
            id: entry.id ?? username,
            username,
            ...rest,
        };
    }
    async authenticate(username, password) {
        const entry = this.users.get(username);
        if (!entry)
            return null;
        const stored = entry.password;
        const isBcrypt = /^\$2[aby]\$/.test(stored);
        let match;
        if (isBcrypt) {
            match = await bcrypt.compare(password, stored);
        }
        else {
            const a = Buffer.from(password);
            const b = Buffer.from(stored);
            match = a.length === b.length && crypto.timingSafeEqual(a, b);
        }
        if (!match)
            return null;
        return this.toUser(username, entry);
    }
    async authenticateByToken(token) {
        for (const [username, entry] of this.users) {
            if (entry.token === token) {
                return this.toUser(username, entry);
            }
        }
        return null;
    }
}
