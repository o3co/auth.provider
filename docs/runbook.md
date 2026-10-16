# Operations runbook

How to run auth-provider 0.18: Redis, rotating keys, and upgrading. The settings named here are listed in the [configuration reference](configuration.md).

## Contents

- [Before you deploy](#before-you-deploy)
- [Redis](#redis)
- [Rotating the signing key](#rotating-the-signing-key)
- [Rotating the sealing key](#rotating-the-sealing-key)
- [Upgrading](#upgrading)
- [Stopping](#stopping)

## Before you deploy

The app relies on the deployment for these. Each is required, not advice.

1. **The proxy in front strips and sets forwarded headers.** It removes any `X-Forwarded-For`, forwarded scheme or client-certificate header a client sent, and sets its own. The app trusts them from `http.trusted-proxies` alone, so a proxy that passes a client's own lets the client choose its source address and certificate.
2. **Outbound through a proxy leaves address checks to the proxy.** With `outbound.proxy` set, the app checks a destination's name, and an address written in its URL, but never resolves a proxied name: the proxy must refuse private, loopback, link-local and metadata addresses itself. Boot warns of this.
3. **The proxy in front bounds slow requests and connections.** The app takes Node's default timeouts. Limit request time, upload rate, header size and connections per client in front of it.
4. **Host clocks are synchronized (NTP).** Sessions, codes, tokens, lockouts and key expiry are judged on each host's clock, and only federation grants allow for skew between hosts.
5. **`rate-limit.fail-mode = open` lets requests through uncounted while the store is down.** Keep the default `closed` unless an outage must not refuse requests.
6. **RP-initiated logout by GET closes the session without asking** when it carries an `id_token_hint` issued within the last 24 hours, as the specification allows. A relying party, or a page that can make the browser follow its link, can log the user out.

## Redis

### What the server must be

The `redis` module checks the server once, at boot, and refuses to start when any of these does not hold:

- Redis 7.0 or later, answering as a primary. Cluster mode is refused, and so is a proxy that splits keys across nodes.
- `maxmemory-policy noeviction`, where any composed module keeps data that must never be evicted (sessions, the token denylist, lockouts, DPoP proof ids).
- `appendonly yes` and `appendfsync always`, where any composed module keeps data that must survive a crash. RDB snapshots are not enough.
- With `redis.replication = replicas`: `min-replicas-to-write` and `min-replicas-max-lag` of at least 1.
- With `redis.replication = none`: no replica connected.

The check reads the server's settings with `CONFIG GET`. A managed Redis that blocks `CONFIG` cannot pass it.

Connect with `rediss://` for TLS. The password goes in the URL. The URL is never logged, and a refusal never quotes it.

### Choosing `replication`

- `replicas`: writes that must survive a failover wait until every replica has them. While no replica is seen, or replicas lag, those writes are unavailable and the requests that need them answer 503. The system denies rather than allows.
- `none`: you state there is no failover. A failover then loses even confirmed writes, and a replica seen at boot or at runtime is refused or unavailable.

Keeping a detached or lagging replica from being promoted is the operator's job, and so are the replicas' own disk settings. A `CONFIG SET` after boot is not seen.

### Outages

Nothing is queued or retried. A dropped connection fails at once, and the request that needed Redis answers 503 with `Cache-Control: no-store`; nothing ends the process. `/readyz` answers 503 while the `redis` probe (a `PING` on both connections) fails, and the gauge `auth_dependency_up{dependency="redis"}` shows which dependency is down.

Rate limits fail closed by default (`rate-limit.fail-mode = closed`), so an outage never lifts a limit. Attempt limits, such as login attempts, always answer 503 while they cannot count.

### Many instances

Set `kernel.deployment = multi` when more than one instance runs. Boot then refuses any module that keeps state in the process, such as the in-memory `store` and the logging-only `mail`. A pattern created with an in-memory store says in its README that it runs as one instance.

## Rotating the signing key

Tokens name the key that signed them (`kid`). An instance verifies a token by the key it names and publishes the public keys as its key set (the `jwks_uri` its metadata names), which verifiers may cache for 300 seconds.

`keys.signing` signs, `keys.next` is published but never signs, and each `keys.previous` entry is published until its `expires-at`. The ring is read at boot, so every step ends with restarting every instance.

1. **Publish the new key.** Write the new key in `keys.next`, then restart every instance. Tokens are still signed with the current key.
2. **Wait for caches.** Wait at least 300 seconds after the last instance restarted, so every verifier that cached the key set has the new key.
3. **Sign with the new key.**
   - Move the new key from `keys.next` to `keys.signing`.
   - Move the old key to `keys.previous`, with an `expires-at` later than now plus the longest token lifetime. The access-token lifetime is 3600 seconds by default; count refresh and ID tokens if they are verified by this key.
   - Restart every instance. During a rolling restart, the instances not yet restarted already publish and verify the new key, because of step 1.
4. **Retire the old key.** After its `expires-at`, remove it from `keys.previous` at the next restart. Tokens it signed are refused with `kid_expired` from that time.

An HS256 secret is not published and has no `previous` or `next` form: changing it refuses every token signed with the old secret at once.

## Rotating the sealing key

`seal` encrypts stored secrets with AES-256-GCM under a key ring: `seal.current` seals new values; `seal.next` opens but never seals; `seal.previous` keys only open. Each sealed value names the key that sealed it.

1. **Add the new key as `next`** and restart every instance.
2. **Make sure every instance runs with it** before going on: each now opens values the new key seals, before any instance seals with it.
3. **Move it up.** Make it `current`, put the old `current` first in `previous`, and restart every instance. New values are sealed with the new key. A value read and written anyway (a renewed upstream token, a proved MFA factor) is sealed again with it as it is written.
4. **Make sure every instance runs with the new `current`** before going on: an instance still sealing with the old key writes values a walk started meanwhile would miss.
5. **Seal the rest again.** Run `pnpm run reseal` in the app, with its configuration. It builds the app without serving anything, walks every holder of long-lived sealed values (`federation-tokens`, `federation-grants`, `mfa`), seals again what a `previous` key sealed, and prints each holder's counts, never an id or a value. It exits 0 when done, 1 when a holder failed (run it again; it goes on safely), and 2 when values no key opens remain. Running it while traffic flows is safe: each value is written only over what was read.
   - On 2, do not go on: a value sealed with a key no longer in the ring remains, left by an earlier rotation (or damaged). Put back the key you retired last as `previous`, restart every instance, and run `reseal` again until it exits 0.
6. **Retire the old key.** Wait out short-lived values first: transactions and held logins sealed with the old key end within an hour (the longest `transaction-seconds`). Then remove it from `previous` and restart every instance. A value it still sealed becomes unavailable (503, not refused), and putting the key back opens it again.

Only a value a `previous` key sealed is sealed again; one `next` sealed is newer than `current` and is left as it is, so values never move back while a rollout is under way.

## Upgrading

> **A rolling upgrade under `kernel.deployment = multi` makes sessions unavailable while old and new instances run together.** An instance cannot read a session record that a newer instance wrote: it lets nobody in on it and answers a login or logout on that cookie with 503. The cookie stays, and the session works again once every instance runs the new version. Upgrade all instances together, or expect 503s on session routes until the rollout ends.

- Stored records keep their names within a version. A new version that changes a record's shape reads the old one for the record's lifetime.
- Changing `redis.prefix` starts from empty state: every key, sessions, refresh tokens, the denylist, lockouts and MFA factors included, lives under the prefix.
- `create-app` never writes into a non-empty directory. To add a feature to an existing app, generate again (`create-app <target> --add <feature>`) and carry your configuration over.
- A boot that refuses exits with status 78 and prints each refusal on stderr, by setting path and never by value. Fix every refusal it lists; they are reported together.

## Stopping

On SIGTERM or SIGINT the app stops taking new connections, lets requests in flight finish, and runs each module's stop hook, all within `kernel.stop-deadline` (default `30s`). Give your orchestrator a longer grace period than that.

Audit events still being delivered at stop are awaited until the same deadline. Any still under way then are lost and counted: watch `auth_audit_events_lost_total`, by `receiver`, and the warning `audit receiver losing events` with `failure: stopped`.
