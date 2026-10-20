# url-setting

## Responsibilities
- Decides which configured URLs boot, for every module that takes one by `urlSetting`, and when a section's own check of the URLs it holds may read them.

## Not here
- What a module's URL means, and how it is compared (the module's).

## Offers
- `urlSetting`: a module's `UrlRules` → a schema part for a configured URL, read as a `ConfiguredUrl`: a string only url-setting makes, so whoever holds one holds an operator's URL. `./testing`: `configuredUrl`, one made for a test, refused as url-setting refuses it.
- `UrlRules`: the schemes, whether plain `http` is also taken, on a loopback host only (`loopbackHttp`, default no), whether a query may be part (default yes), whether a trailing `/` is kept (default) or refused, and whether only an origin is taken (`origin`: no path, not even `/`, and no query).
- `urlsChecked` (a check of a URL and its hosts → its refusal, the URLs that must parse first, the URL and hosts sent at each key) → a section's refinement: once every URL parses, each one sent is checked and what the check answers is put at its key; while one is no URL, nothing is asked. The check's words are its own.

## Invariants
- A configured URL is written `<scheme>://` in lower case.
- Its scheme is one of the schemes the module gives; with `loopbackHttp`, also `http`, on a loopback host only: `localhost`, an IPv4 address in 127.0.0.0/8 or `[::1]`, judged on the host as the parser writes it. Any other host over `http` is refused, `localhost.`, a subdomain of `localhost`, `0.0.0.0` and an IPv4-mapped address among them.
- It has a host.
- It holds no userinfo.
- It holds no fragment, not even a bare `#`.
- It holds no whitespace, control character or `\`.
- It holds a query only when the module allows one.
- It holds a trailing `/` unless the module refuses one.
- It is taken only in the form the URL parser writes it: lower-case host, no default port; an empty path may stay empty.
- A URL taken is kept exactly as written.
- A refusal names the key path and the kind, never any part of the value.
- The kinds of difference from the parser's form: a scheme not in lower case, whitespace or control characters, a backslash, host case, invisible or mapped characters, percent-encoding in the host, an IP address not in its shortest form, an empty port, a default port written, a leading zero in the port, dot segments, the path's ending (a last `.` or `..` segment), and characters the parser percent-encodes.
- Any other difference is named only as a difference from the parser's form.

## Depends on
- `zod`; nothing in the workspace.
