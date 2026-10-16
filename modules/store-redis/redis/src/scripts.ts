/**
 * Shared prelude: store time, versions, expiry and idempotency. Every input has been checked at
 * the store contract boundary, so nothing below fails after the first write.
 *
 * A version is "<server>.<epoch>.<n>". <server> joins the run id (new on every restart) and the
 * replication id (new when a replica is promoted), so a counter rolled back by a restart or a
 * failover never hands out a version seen before; <epoch> is the store time when the counter
 * was created, so a counter that expired and came back starts afresh too. The counter lives a
 * day past its last use. Numbers go out as strings, since cjson keeps only 14 digits.
 */
const prelude = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local function num(x) return string.format('%.0f', x) end
local run_id = string.match(redis.call('INFO', 'server'), 'run_id:(%w+)')
-- Every answer names the server it was computed on, so a confirmation is checked against it.
local function out(answer) return run_id .. '\\n' .. answer end
-- An entry is gone at its very expiry time by this script's clock; Redis would still hold it.
for _, key in ipairs(KEYS) do
  local expires = redis.call('PEXPIRETIME', key)
  if expires >= 0 and expires <= now then redis.call('DEL', key) end
end
local function next_version(vkey)
  local server = string.sub(run_id, 1, 12)
    .. string.sub(string.match(redis.call('INFO', 'replication'), 'master_replid:(%w+)'), 1, 12)
  local epoch = redis.call('HGET', vkey, 'epoch')
  if not epoch then
    epoch = t[1] .. string.format('%06d', tonumber(t[2]))
    redis.call('HSET', vkey, 'epoch', epoch)
  end
  local n = redis.call('HINCRBY', vkey, 'n', 1)
  redis.call('PEXPIRE', vkey, 86400000)
  return server .. '.' .. epoch .. '.' .. num(n)
end
local function expiry(kind, arg, current)
  if kind == 'after' then return now + tonumber(arg) end
  if kind == 'at' then return tonumber(arg) end
  if kind == 'never' then return nil end
  if kind == 'keep' then
    if current < 0 then return nil end
    return current
  end
  -- extend: never shorter than it was, and a key that never ends stays so.
  if current == -1 then return nil end
  return math.max(current, now + tonumber(arg))
end
local function store_value(key, vkey, value, expires)
  local v = next_version(vkey)
  redis.call('DEL', key)
  redis.call('HSET', key, 'v', value, 'ver', v)
  if expires ~= nil then redis.call('PEXPIREAT', key, expires) end
  return v
end
local function guard(ikey, digest, deadline)
  if ikey ~= '' then
    local seen = redis.call('GET', ikey)
    if seen then
      local record = cjson.decode(seen)
      if record.d == digest then return record.a end
      return cjson.encode({kind = 'reused'})
    end
  end
  if deadline ~= '' and now > tonumber(deadline) then return cjson.encode({kind = 'late'}) end
  return nil
end
-- A mark is kept a second past its deadline, or five minutes and a second without one, as store says.
local mark_without_deadline_ms = 300000
local mark_past_deadline_ms = 1000
local function remember(ikey, digest, answer, deadline)
  if ikey ~= '' then
    local base = deadline ~= '' and tonumber(deadline) or now + mark_without_deadline_ms
    redis.call('SET', ikey, cjson.encode({d = digest, a = answer}), 'PXAT', base + mark_past_deadline_ms)
  end
  return answer
end
local function entry(key)
  local held = redis.call('HMGET', key, 'v', 'ver')
  if not held[1] then return false end
  local expires = redis.call('PEXPIRETIME', key)
  return {value = held[1], version = held[2], expiresAt = expires >= 0 and num(expires) or cjson.null}
end
`;

/** KEYS: key, version key, mark key. ARGV: mode, value, expected, kind, arg, deadline, digest, has mark. */
export const write = `${prelude}
local key, vkey, ikey = KEYS[1], KEYS[2], ARGV[8] == '1' and KEYS[3] or ''
local seen = guard(ikey, ARGV[7], ARGV[6])
if seen then return out(seen) end
local mode = ARGV[1]
local exists = redis.call('EXISTS', key) == 1
local answer
if mode == 'putIfAbsent' and exists then
  local ttl = redis.call('PTTL', key)
  answer = cjson.encode({kind = 'exists', remainingMs = ttl >= 0 and num(ttl) or cjson.null})
elseif mode == 'replaceIf' and not exists then
  answer = cjson.encode({kind = 'missing'})
elseif mode == 'replaceIf' and redis.call('HGET', key, 'ver') ~= ARGV[3] then
  answer = cjson.encode({kind = 'conflict'})
else
  local expires = expiry(ARGV[4], ARGV[5], redis.call('PEXPIRETIME', key))
  answer = cjson.encode({kind = 'written', version = store_value(key, vkey, ARGV[2], expires)})
end
return out(remember(ikey, ARGV[7], answer, ARGV[6]))
`;

/** KEYS: key, mark key. ARGV: by ('version'|'value'), expected, deadline, digest, has mark. */
export const removeIf = `${prelude}
local key, ikey = KEYS[1], ARGV[5] == '1' and KEYS[2] or ''
local seen = guard(ikey, ARGV[4], ARGV[3])
if seen then return out(seen) end
local held = entry(KEYS[1])
local answer
if not held then
  answer = cjson.encode({kind = 'missing'})
elseif (ARGV[1] == 'version' and held.version ~= ARGV[2]) or (ARGV[1] == 'value' and held.value ~= ARGV[2]) then
  answer = cjson.encode({kind = 'conflict'})
else
  redis.call('DEL', key)
  answer = cjson.encode({kind = 'removed', old = held})
end
return out(remember(ikey, ARGV[4], answer, ARGV[3]))
`;

/** KEYS: the keys to read. */
export const read = `${prelude}
local entries = {}
for i, key in ipairs(KEYS) do entries[i] = entry(key) end
return out(cjson.encode({now = num(now), entries = entries, n = #KEYS}))
`;

/** KEYS: key, mark key. ARGV: deadline, digest, has mark. */
export const take = `${prelude}
local ikey = ARGV[3] == '1' and KEYS[2] or ''
local seen = guard(ikey, ARGV[2], ARGV[1])
if seen then return out(seen) end
local held = entry(KEYS[1])
local answer
if not held then
  answer = cjson.encode({kind = 'missing'})
else
  redis.call('DEL', KEYS[1])
  answer = cjson.encode({kind = 'taken', entry = held})
end
return out(remember(ikey, ARGV[2], answer, ARGV[1]))
`;

/**
 * KEYS: the batch keys, then the version key, then the mark key.
 * ARGV: spec JSON {conditions = [{i, version|absent}], writes = [{i, put, kind, arg}|{i, remove}]},
 * deadline, digest, has mark.
 */
export const batch = `${prelude}
local spec = cjson.decode(ARGV[1])
local n = #KEYS
local vkey = KEYS[n - 1]
local ikey = ARGV[4] == '1' and KEYS[n] or ''
local seen = guard(ikey, ARGV[3], ARGV[2])
if seen then return out(seen) end
for index, c in ipairs(spec.conditions) do
  local ver = redis.call('HGET', KEYS[c.i], 'ver')
  local holds
  if c.absent then holds = not ver else holds = ver == c.version end
  if not holds then return out(remember(ikey, ARGV[3], cjson.encode({kind = 'conflict', index = index - 1}), ARGV[2])) end
end
local expiries = {}
for index, w in ipairs(spec.writes) do
  if not w.remove then expiries[index] = expiry(w.kind, w.arg, redis.call('PEXPIRETIME', KEYS[w.i])) end
end
local versions = {}
for index, w in ipairs(spec.writes) do
  if w.remove then
    redis.call('DEL', KEYS[w.i])
    versions[index] = cjson.null
  else
    versions[index] = store_value(KEYS[w.i], vkey, w.put, expiries[index])
  end
end
return out(remember(ikey, ARGV[3], cjson.encode({kind = 'committed', versions = versions, n = #spec.writes}), ARGV[2]))
`;

/** No keys. ARGV: deadline. An empty batch still honours its deadline. */
export const deadlineOnly = `${prelude}
if ARGV[1] ~= '' and now > tonumber(ARGV[1]) then return out(cjson.encode({kind = 'late'})) end
return out(cjson.encode({kind = 'committed', versions = {}, n = 0}))
`;

/** KEYS: counter key, mark key. ARGV: window ms, limit, deadline, digest, has mark. Not versioned: it is hit hard. */
export const count = `${prelude}
local ikey = ARGV[5] == '1' and KEYS[2] or ''
local seen = guard(ikey, ARGV[4], ARGV[3])
if seen then return out(seen) end
local ms, limit = tonumber(ARGV[1]), tonumber(ARGV[2])
local current = redis.call('GET', KEYS[1])
local answer
if not current then
  if limit < 1 then
    answer = cjson.encode({kind = 'limited', resetAt = num(now + ms)})
  else
    redis.call('SET', KEYS[1], 1, 'PX', ms)
    answer = cjson.encode({kind = 'counted', count = 1, resetAt = num(now + ms)})
  end
else
  local reset = num(now + redis.call('PTTL', KEYS[1]))
  if tonumber(current) >= limit then
    answer = cjson.encode({kind = 'limited', resetAt = reset})
  else
    answer = cjson.encode({kind = 'counted', count = redis.call('INCR', KEYS[1]), resetAt = reset})
  end
end
return out(remember(ikey, ARGV[4], answer, ARGV[3]))
`;

/** KEYS: set key. ARGV: member, score, cap, kind, arg. A set's expiry never shrinks. */
export const setAdd = `${prelude}
local key = KEYS[1]
redis.call('ZREMRANGEBYSCORE', key, '-inf', num(now))
local fresh = redis.call('EXISTS', key) == 0
local current = redis.call('PEXPIRETIME', key)
local proposed = expiry(ARGV[4], ARGV[5], fresh and -2 or current)
local final
if fresh then final = proposed
elseif current == -1 or proposed == nil then final = nil
else final = math.max(current, proposed) end
redis.call('ZADD', key, 'GT', ARGV[2], ARGV[1])
local evicted = {}
local over = redis.call('ZCARD', key) - tonumber(ARGV[3])
if over > 0 then
  local popped = redis.call('ZPOPMIN', key, over)
  for i = 1, #popped, 2 do table.insert(evicted, popped[i]) end
end
if redis.call('EXISTS', key) == 1 then
  if final == nil then redis.call('PERSIST', key) else redis.call('PEXPIREAT', key, final) end
end
return out(cjson.encode({evicted = evicted, n = #evicted}))
`;

/** KEYS: set key. */
export const setMembers = `${prelude}
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', num(now))
return out(cjson.encode({now = num(now), members = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')}))
`;

/** KEYS: set key. ARGV: member. */
export const setRemove = `${prelude}
redis.call('ZREM', KEYS[1], ARGV[1])
return out(cjson.encode({kind = 'written'}))
`;

/** The store clock's present time. */
export const now = `${prelude}
return out(cjson.encode({now = num(now)}))
`;
