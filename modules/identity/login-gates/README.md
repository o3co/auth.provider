# login-gates

## Responsibilities
- Passes a confirmed login through the gates, then has `session` open it.
- Resumes a held login with the gates after the one that held it.
- Decides where a login may send the browser back to, for every way of logging in.

## Not here
- Authentication methods (the callers), opening a session (`session`) and each gate's decision (the gate).
- What an amr value means (whoever declares it).

## Offers
- `login(request, facts, done?, from?)`: opened with the session and cookies, held with the gate's name, answer and cookies, or refused with the gate's name and no cookies.
- `resume(request, facts, after, done?, from?)`: the same answer, from the gates after the one named `after`; expired, with no gate run, at or past `from`'s deadline.
- `achievable(amr)`: whether the declared amr, taken together, include every one given.
- `returnAllowed(target)`: whether a login may send the browser back to this target.
- Extension point `loginGates`: a named gate whose `hold` answers pass, held with an answer and optional cookies, or refused; a gate declared `rechecked` is asked again on resume.
- Extension point `amrSources`: the amr that a way of logging in or a gate can prove, under its name.
- Extension point `returnPaths`: a path on the public origin that its owner lets a login return to, or with `segment` the paths one name segment below it.
- Extension point `openedAfterHold`: a caller to tell, with its carry, when a held login it asked for opens.
- Operator section `return-targets`: https URLs (http only on a loopback host), checked by `url-setting`, that a login may return to (default none).

## Invariants
- Gates run one at a time, sorted by name in code units, and the first that holds or refuses stops the login.
- A resume first asks the `rechecked` gates before the one that held, in the same order, before any gate after it and before the session opens. There they may only pass or refuse: one that holds throws `TypeError`, with no session. A gate that held is not asked again.
- The session opens only after every gate passes, with the facts as the way of logging in gave them, its authentication time (or `unknown`) included; a gate that throws rejects the call with no session.
- A gate's answer and cookies, `done` and `from` are passed on unread.
- `resume` after a name no gate has, or a `from` naming no caller, throws `TypeError` before any gate runs.
- Only a `resume` that opens the session tells the caller that `from` names.
- If that caller's `opened` throws, the login still opens and only the caller's name and the error's kind are logged.
- A return path taking a segment is a path below the root that does not end in a slash; one at the root, or ending in a slash, refuses boot.
- A login returns only to a listed target exactly, or to a contributed path, or one name segment (letters, digits, `-` or `_`, up to 64) below a path contributed with `segment`, written as the public origin and that path exactly, with any query but no fragment, whitespace or control character: a spelling the URL parser rewrites (a dot segment, a backslash) is refused.
- A gate that passes writes nothing, and a gate that holds cleans up its own state. A gate that refuses writes nothing the login keeps.

## Depends on
- `kernel`, `http`, `url-setting`, `session`

## Vocabulary
- held: a gate stopped the login, kept `done` and `from`, and answers the client itself.
- refused: a gate ended the login: no session opens, and the caller answers with its own failure, as for wrong credentials.
- done: what the caller answers once the session opens, carried across gates.
- from: the caller to tell once a held login opens, a carry that only that caller reads, and an optional deadline on `kernel`'s clock.
