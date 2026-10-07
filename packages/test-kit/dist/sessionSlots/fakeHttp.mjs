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
/** The origin every fake request is served on. */
export const CONTRACT_ORIGIN = "https://idp.contract.test";
const CONTRACT_HOST = "idp.contract.test";
/** A request with an anonymous express session, as express-session hands every request one. */
export function fakeRequest(options = {}) {
    const record = { regenerated: 0, saved: 0, lastSaved: undefined };
    const headers = { host: CONTRACT_HOST };
    for (const [name, value] of Object.entries(options.headers ?? {})) {
        headers[name.toLowerCase()] = value;
    }
    const path = options.path ?? "/contract";
    let generation = 0;
    const req = {
        method: options.method ?? "POST",
        path,
        url: path,
        originalUrl: path,
        protocol: "https",
        secure: true,
        host: CONTRACT_HOST,
        hostname: CONTRACT_HOST,
        ip: "192.0.2.10",
        headers,
        body: { ...(options.body ?? {}) },
        query: {},
        /** Express's accessor, over the headers of the object it is called on — a copy's own, when a test copies the request. */
        get(name) {
            return this.headers[name.toLowerCase()];
        },
        sessionID: "contract-session-0",
        session: undefined,
    };
    const newSession = () => {
        const session = {};
        Object.defineProperties(session, {
            regenerate: {
                value: (done) => {
                    if (options.regenerateFails !== undefined) {
                        done(options.regenerateFails);
                        return;
                    }
                    generation++;
                    record.regenerated++;
                    req.sessionID = `contract-session-${generation}`;
                    req.session = newSession();
                    done();
                },
            },
            save: {
                value: (done) => {
                    if (options.saveFails !== undefined) {
                        done(options.saveFails);
                        return;
                    }
                    record.saved++;
                    record.lastSaved = Object.freeze({ ...session });
                    done();
                },
            },
        });
        return session;
    };
    req.session = newSession();
    return { req: req, session: record };
}
export function fakeResponse() {
    const record = {
        status: undefined,
        body: undefined,
        ended: false,
        headers: {},
        cookies: [],
        cleared: [],
    };
    /** Adds `value` to a header that may already carry some, comma-separated as Express appends. */
    const appendHeader = (name, value) => {
        const key = name.toLowerCase();
        const current = record.headers[key];
        record.headers[key] = current === undefined ? String(value) : `${current}, ${String(value)}`;
    };
    const res = {
        statusCode: 200,
        headersSent: false,
        locals: {},
        status(code) {
            record.status = code;
            res.statusCode = code;
            return res;
        },
        json(body) {
            record.body = body;
            record.ended = true;
            res.headersSent = true;
            return res;
        },
        send(body) {
            record.body = body;
            record.ended = true;
            res.headersSent = true;
            return res;
        },
        end() {
            record.ended = true;
            res.headersSent = true;
            return res;
        },
        set(name, value) {
            record.headers[name.toLowerCase()] = String(value);
            return res;
        },
        header(name, value) {
            return res.set(name, value);
        },
        setHeader(name, value) {
            record.headers[name.toLowerCase()] = String(value);
            return res;
        },
        get(name) {
            return record.headers[name.toLowerCase()];
        },
        getHeader(name) {
            return record.headers[name.toLowerCase()];
        },
        cookie(name, value, options) {
            record.cookies.push({
                name,
                value,
                options: options === undefined ? undefined : Object.freeze({ ...options }),
            });
            return res;
        },
        clearCookie(name, _options) {
            record.cleared.push(name);
            return res;
        },
        append(name, value) {
            appendHeader(name, value);
            return res;
        },
        vary(field) {
            appendHeader("vary", field);
            return res;
        },
        type(value) {
            record.headers["content-type"] = value;
            return res;
        },
        sendStatus(code) {
            res.status(code);
            return res.send(String(code));
        },
    };
    return { res: res, record };
}
/** Runs `middleware` over a request: whether it handed the request on, and what it answered. */
export async function runMiddleware(middleware, req) {
    const { res, record } = fakeResponse();
    let next = 0;
    let nextError;
    await new Promise((resolve, reject) => {
        const onNext = (err) => {
            next++;
            nextError = err;
            resolve();
        };
        try {
            const returned = middleware(req, res, onNext);
            // A middleware that answers ends the response; one that hands on calls
            // `next`. Settled once a promise it returned settles and one turn of
            // the event loop has passed — a middleware that did neither by then
            // is reported as it is, with no answer and no `next`.
            Promise.resolve(returned).then(() => setImmediate(resolve), reject);
        }
        catch (err) {
            reject(err);
        }
    });
    return { next, nextError, response: record };
}
