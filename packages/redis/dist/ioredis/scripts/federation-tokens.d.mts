/**
 * `ft_generation(raw)`: the generation the stored value carries, or `nil` when
 * it carries none (or is no JSON object). `ft_late(deadline)`: whether the
 * server's clock is at or after `deadline`, in epoch milliseconds.
 * `ft_keep(replay, answer, untilMs)`: `answer` kept under the replay key
 * until `untilMs` (epoch ms), for a copy of the write that arrives before then.
 * Exported for the tests that pin these helpers on a real Redis.
 */
export declare const FT_PRELUDE = "\nlocal function ft_generation(raw)\n  local ok, rec = pcall(cjson.decode, raw)\n  if not ok or type(rec) ~= 'table' then return nil end\n  local g = rec['g']\n  if type(g) ~= 'string' then return nil end\n  return g\nend\nlocal function ft_late(deadline)\n  local t = redis.call('TIME')\n  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) >= tonumber(deadline)\nend\nlocal function ft_keep(replay, answer, untilMs)\n  redis.call('SET', replay, answer, 'PXAT', untilMs)\n  return answer\nend\n";
export declare const FT_ATTACH: import("./define.mjs").CachedScript;
export declare const FT_READ_VERSIONED: import("./define.mjs").CachedScript;
export declare const FT_REPLACE_IF: import("./define.mjs").CachedScript;
export declare const FT_REMOVE_IF: import("./define.mjs").CachedScript;
//# sourceMappingURL=federation-tokens.d.mts.map