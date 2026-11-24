//! Server-side Lua scripts. Each state change is one script, which Redis runs atomically:
//! no other command interleaves with it, so a check and the write it guards can never be
//! separated by another worker's write.
//!
//! Every script takes the namespace prefix (`{ns}:`) as `ARGV[1]` and builds its key names
//! from it. All keys share the `{ns}` hash tag, so they live in one hash slot. Scripts never
//! return before a write they depend on: Redis does not roll a script back on error, so all
//! validation that can fail comes first.

use std::sync::LazyLock;

use redis::Script;

/// Session hash fields returned per record by `resolve` and read by `snapshot`, in order.
pub(crate) const RECORD_FIELDS: [&str; 11] = [
    "inc", "rev", "exp", "state", "route", "kid", "keyref", "mode", "b1", "b2", "b3",
];

/// Largest timestamp (and sorted-set score) written: 2^53 - 1, the largest integer a Lua 5.1
/// number (an IEEE double) holds exactly. Redis compares scores and the scripts compare
/// timestamps as doubles, so anything larger would round. Far beyond any real TTL (year
/// ~287 000); larger expiries are clamped to it.
pub(crate) const MAX_EXACT_MILLIS: u64 = (1 << 53) - 1;

/// Helpers shared by the writing scripts. `fmt` prints a number as a plain integer
/// (`tostring` switches to exponent notation above 14 digits).
const PRELUDE: &str = r"
local P = ARGV[1]
local function fmt(n) return string.format('%.0f', n) end
local function count_up(key, which) redis.call('HINCRBY', key, which, 1) end
local function count_down(key, which)
  if redis.call('HINCRBY', key, which, -1) < 0 then redis.call('HSET', key, which, 0) end
  local c = tonumber(redis.call('HGET', key, 'consumed') or '0')
  local e = tonumber(redis.call('HGET', key, 'expired') or '0')
  if c <= 0 and e <= 0 then redis.call('DEL', key) end
end
local function leave_pending(id, route, kid, which, purge_at)
  redis.call('ZREM', P .. 'pr:' .. route, id)
  redis.call('ZREM', P .. 'pending', id)
  count_up(P .. 'tr:' .. route, which)
  if kid then
    redis.call('ZREM', P .. 'pk:' .. kid, id)
    count_up(P .. 'trk:' .. route .. ':' .. kid, which)
  end
  redis.call('ZADD', P .. 'purge', purge_at, id)
end
local function expire_due(now)
  local refs = {}
  for _, id in ipairs(redis.call('ZRANGEBYSCORE', P .. 'pending', '-inf', now)) do
    local s = P .. 's:' .. id
    local f = redis.call('HMGET', s, 'state', 'route', 'kid', 'keyref')
    if f[1] == 'pending' then
      redis.call('HSET', s, 'state', 'expired')
      redis.call('HINCRBY', s, 'rev', 1)
      leave_pending(id, f[2], f[3], 'expired', 0)
      refs[#refs + 1] = f[4]
    else
      redis.call('ZREM', P .. 'pending', id)
    end
  end
  return refs
end
local function append(out, list)
  for _, v in ipairs(list) do out[#out + 1] = v end
  return out
end
";

/// `ARGV`: prefix, id, now, expires_at, route, kid (`''` = none), key ref, unique route
/// (`1`/`0`), max pending, mode, binding fields b1..b3.
/// Returns `{status, ...}`: `ok, incarnation, refs...` / `capacity, refs...` /
/// `duplicate_session` / `duplicate_route`. `refs` are key references the lazy expiry moved.
const INSERT: &str = r"
local id, now, exp, route = ARGV[2], ARGV[3], ARGV[4], ARGV[5]
local kid = ARGV[6]
if kid == '' then kid = false end
local s = P .. 's:' .. id
if redis.call('EXISTS', s) == 1 then return {'duplicate_session'} end
if ARGV[8] == '1' and (redis.call('EXISTS', P .. 'pr:' .. route) == 1
    or redis.call('EXISTS', P .. 'tr:' .. route) == 1) then
  return {'duplicate_route'}
end
local max = tonumber(ARGV[9])
local refs = {}
if redis.call('ZCARD', P .. 'pending') >= max then
  refs = expire_due(now)
  if redis.call('ZCARD', P .. 'pending') >= max then return append({'capacity'}, refs) end
end
local inc = redis.call('INCR', P .. 'incarnation')
redis.call('HSET', s, 'inc', inc, 'rev', 0, 'exp', exp, 'state', 'pending', 'route', route,
  'keyref', ARGV[7], 'mode', ARGV[10], 'b1', ARGV[11], 'b2', ARGV[12], 'b3', ARGV[13])
if kid then
  redis.call('HSET', s, 'kid', kid)
  redis.call('ZADD', P .. 'pk:' .. kid, inc, id)
end
redis.call('ZADD', P .. 'pr:' .. route, inc, id)
redis.call('ZADD', P .. 'pending', exp, id)
return append({'ok', tostring(inc)}, refs)
";

/// Read-only. `ARGV`: prefix, index key suffix (`pr:<route>` / `pk:<kid>`), terminal counts
/// key suffix. Returns `consumed, expired`, then per pending id in insertion order the id and
/// its [`RECORD_FIELDS`].
const RESOLVE: &str = r"#!lua flags=no-writes
local P = ARGV[1]
local counts = redis.call('HMGET', P .. ARGV[3], 'consumed', 'expired')
local out = {counts[1] or '0', counts[2] or '0'}
for _, id in ipairs(redis.call('ZRANGE', P .. ARGV[2], 0, -1)) do
  local f = redis.call('HMGET', P .. 's:' .. id, FIELDS)
  out[#out + 1] = id
  for i = 1, NFIELDS do out[#out + 1] = f[i] end
end
return out
";

/// The atomic compare-and-set. `ARGV`: prefix, id, incarnation, revision, digest, serialized
/// result, now, consumed retention (ms). Precedence as in `MemoryRegistry::claim`. Returns
/// `unknown` / `replay, same(1|0)` / `expired[, ref]` / `mismatch, actual` /
/// `ok, revision, ref, route`.
const CLAIM: &str = r"
local id = ARGV[2]
local s = P .. 's:' .. id
local f = redis.call('HMGET', s, 'inc', 'rev', 'exp', 'state', 'route', 'kid', 'keyref', 'digest')
if not f[1] or f[1] ~= ARGV[3] then return {'unknown'} end
if f[4] == 'consumed' then
  if f[8] == ARGV[5] then return {'replay', '1'} end
  return {'replay', '0'}
end
if f[4] == 'expired' then return {'expired'} end
if f[4] ~= 'pending' then return redis.error_reply('session record corrupt') end
local now, exp = tonumber(ARGV[7]), tonumber(f[3])
if now >= exp then
  redis.call('HSET', s, 'state', 'expired')
  redis.call('HINCRBY', s, 'rev', 1)
  leave_pending(id, f[5], f[6], 'expired', 0)
  return {'expired', f[7]}
end
if f[2] ~= ARGV[4] then return {'mismatch', f[2]} end
local purge_at = math.min(exp + tonumber(ARGV[8]), MAX_EXACT)
redis.call('HSET', s, 'state', 'consumed', 'digest', ARGV[5], 'result', ARGV[6])
local rev = redis.call('HINCRBY', s, 'rev', 1)
leave_pending(id, f[5], f[6], 'consumed', fmt(purge_at))
return {'ok', tostring(rev), f[7], f[5]}
";

/// `ARGV`: prefix, now. Returns the key references of the sessions it expired.
const EXPIRE_DUE: &str = r"
return expire_due(ARGV[2])
";

/// `ARGV`: prefix, now. Deletes `Expired` records and `Consumed` ones past retention; returns
/// their key references.
const PURGE: &str = r"
local refs = {}
for _, id in ipairs(redis.call('ZRANGEBYSCORE', P .. 'purge', '-inf', ARGV[2])) do
  local s = P .. 's:' .. id
  local f = redis.call('HMGET', s, 'state', 'route', 'kid', 'keyref')
  redis.call('ZREM', P .. 'purge', id)
  if f[1] == 'consumed' or f[1] == 'expired' then
    count_down(P .. 'tr:' .. f[2], f[1])
    if f[3] then count_down(P .. 'trk:' .. f[2] .. ':' .. f[3], f[1]) end
    redis.call('DEL', s)
    refs[#refs + 1] = f[4]
  end
end
return refs
";

/// The loaded scripts. `Script` sends `EVALSHA` and reloads the source on `NOSCRIPT`, which
/// means the script did not run, so the retry cannot execute anything twice.
pub(crate) struct Scripts {
    pub(crate) insert: Script,
    pub(crate) resolve: Script,
    pub(crate) claim: Script,
    pub(crate) expire_due: Script,
    pub(crate) purge: Script,
}

fn writer(body: &str) -> Script {
    let source = format!("{PRELUDE}{body}").replace("MAX_EXACT", &MAX_EXACT_MILLIS.to_string());
    Script::new(&source)
}

pub(crate) static SCRIPTS: LazyLock<Scripts> = LazyLock::new(|| {
    let fields = RECORD_FIELDS.map(|f| format!("'{f}'")).join(", ");
    let resolve = RESOLVE
        .replace("NFIELDS", &RECORD_FIELDS.len().to_string())
        .replace("FIELDS", &fields);
    Scripts {
        insert: writer(INSERT),
        resolve: Script::new(&resolve),
        claim: writer(CLAIM),
        expire_due: writer(EXPIRE_DUE),
        purge: writer(PURGE),
    }
});
