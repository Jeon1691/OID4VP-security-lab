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
pub(crate) const RECORD_FIELDS: [&str; 12] = [
    "inc", "rev", "exp", "state", "route", "kid", "keyref", "mode", "b1", "b2", "b3", "b4",
];

/// Largest timestamp (and sorted-set score) written: 2^53 - 1, the largest integer a Lua 5.1
/// number (an IEEE double) holds exactly. Redis compares scores and the scripts compare
/// timestamps as doubles, so anything larger would round. Far beyond any real TTL (year
/// ~287 000); larger expiries are clamped to it.
pub(crate) const MAX_EXACT_MILLIS: u64 = (1 << 53) - 1;

/// The current time in milliseconds for every script. An empty argument means "the Redis
/// server's clock": `TIME` is read inside the script, so the instant a decision is judged at is
/// the instant it is made, however long the call spent in transit, and every worker is judged
/// by the same clock. A number is an injected test/lab clock (see `TimeSource::Injected`).
/// `TIME` is allowed in `no-writes` scripts, and with effects replication (the only mode in
/// Redis 7+ / Valkey) replicas receive the resulting writes, not the call, so its
/// non-determinism is harmless. `fmt` prints a number as a plain integer (`tostring` switches
/// to exponent notation above 14 digits).
const CLOCK: &str = r"
local function fmt(n) return string.format('%.0f', n) end
local function clock_ms(arg)
  if arg ~= '' then return tonumber(arg) end
  local t = redis.call('TIME')
  return math.min(tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000), MAX_EXACT)
end
";

/// Helpers shared by the writing scripts.
const PRELUDE: &str = r"
local P = ARGV[1]
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
  for _, id in ipairs(redis.call('ZRANGEBYSCORE', P .. 'pending', '-inf', fmt(now))) do
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

/// `ARGV`: prefix, id, now (`''` = server time), TTL (ms), route, kid (`''` = none), key ref,
/// unique route (`1`/`0`), max pending, mode, binding fields b1..b4. `expires_at` is computed
/// here, on the same clock that later judges expiry.
/// Returns `{status, ...}`: `ok, incarnation, expires_at, refs...` / `capacity, refs...` /
/// `zero_ttl` / `duplicate_session` / `duplicate_route`. `refs` are key references the lazy
/// expiry moved.
const INSERT: &str = r"
local id, route = ARGV[2], ARGV[5]
local now = clock_ms(ARGV[3])
local exp = math.min(now + tonumber(ARGV[4]), MAX_EXACT)
if exp <= now then return {'zero_ttl'} end
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
redis.call('HSET', s, 'inc', fmt(inc), 'rev', 0, 'exp', fmt(exp), 'state', 'pending', 'route', route,
  'keyref', ARGV[7], 'mode', ARGV[10], 'b1', ARGV[11], 'b2', ARGV[12], 'b3', ARGV[13],
  'b4', ARGV[14])
if kid then
  redis.call('HSET', s, 'kid', kid)
  redis.call('ZADD', P .. 'pk:' .. kid, inc, id)
end
redis.call('ZADD', P .. 'pr:' .. route, inc, id)
redis.call('ZADD', P .. 'pending', fmt(exp), id)
return append({'ok', fmt(inc), fmt(exp)}, refs)
";

/// Read-only. `ARGV`: prefix, index kind (`pr` route / `pk` kid), index value, terminal counts
/// key suffix, now (`''` = server time), limit, due route (`''` = any), kid filter (`''` =
/// none).
///
/// Walks the index in insertion order. Every entry must name a pending record whose route
/// (`pr`) or kid (`pk`) is the indexed value, otherwise the script fails (a corrupt or tampered
/// index is never resolved around). Records past their TTL are skipped and only noted (when
/// they match the due route and kid filter). Live records matching the kid filter are counted;
/// only the first `limit` are returned. The walk visits at most the `pending` index, which
/// `insert` caps at `max_pending`, so it is bounded; the reply is bounded by `limit`.
///
/// Returns `consumed, expired, saw_due (1|0), live, now`, then per returned record its id and
/// [`RECORD_FIELDS`]. The shebang line and [`CLOCK`] are prepended when the script is built.
const RESOLVE: &str = r"
local P, kind, value = ARGV[1], ARGV[2], ARGV[3]
local now, limit = clock_ms(ARGV[5]), tonumber(ARGV[6])
local due_route, filter_kid = ARGV[7], ARGV[8]
local counts = redis.call('HMGET', P .. ARGV[4], 'consumed', 'expired')
local saw_due, live, records = '0', 0, {}
for _, id in ipairs(redis.call('ZRANGE', P .. kind .. ':' .. value, 0, -1)) do
  local f = redis.call('HMGET', P .. 's:' .. id, FIELDS)
  if f[4] ~= 'pending' then return redis.error_reply('index names a record that is not pending') end
  if kind == 'pr' and f[5] ~= value then return redis.error_reply('route index mismatch') end
  if kind == 'pk' and f[6] ~= value then return redis.error_reply('kid index mismatch') end
  local kid_ok = filter_kid == '' or f[6] == filter_kid
  if now >= tonumber(f[3]) then
    if kid_ok and (due_route == '' or f[5] == due_route) then saw_due = '1' end
  elseif kid_ok then
    live = live + 1
    if live <= limit then
      records[#records + 1] = id
      for i = 1, NFIELDS do records[#records + 1] = f[i] end
    end
  end
end
local out = {counts[1] or '0', counts[2] or '0', saw_due, fmt(live), fmt(now)}
for i = 1, #records do out[#out + 1] = records[i] end
return out
";

/// The atomic compare-and-set. `ARGV`: prefix, id, incarnation, revision, digest, serialized
/// result, now (`''` = server time), consumed retention (ms), origin (the record's key
/// reference the candidate was issued for). The origin is checked first: a candidate issued by
/// another namespace or registry is unknown here even if id, incarnation and revision
/// coincide. Then precedence as in `MemoryRegistry::claim`. Returns
/// `unknown` / `replay, same(1|0)` / `expired[, ref]` / `mismatch, actual` /
/// `ok, revision, ref, route`.
const CLAIM: &str = r"
local id = ARGV[2]
local s = P .. 's:' .. id
local f = redis.call('HMGET', s, 'inc', 'rev', 'exp', 'state', 'route', 'kid', 'keyref', 'digest')
if not f[1] or f[7] ~= ARGV[9] or f[1] ~= ARGV[3] then return {'unknown'} end
if f[4] == 'consumed' then
  if f[8] == ARGV[5] then return {'replay', '1'} end
  return {'replay', '0'}
end
if f[4] == 'expired' then return {'expired'} end
if f[4] ~= 'pending' then return redis.error_reply('session record corrupt') end
local now, exp = clock_ms(ARGV[7]), tonumber(f[3])
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
return {'ok', fmt(rev), f[7], f[5]}
";

/// `ARGV`: prefix, now (`''` = server time). Returns the key references of the sessions it
/// expired.
const EXPIRE_DUE: &str = r"
return expire_due(clock_ms(ARGV[2]))
";

/// `ARGV`: prefix, now (`''` = server time). Deletes `Expired` records and `Consumed` ones past retention; returns
/// their key references.
const PURGE: &str = r"
local refs = {}
for _, id in ipairs(redis.call('ZRANGEBYSCORE', P .. 'purge', '-inf', fmt(clock_ms(ARGV[2])))) do
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

fn with_max(source: &str) -> String {
    source.replace("MAX_EXACT", &MAX_EXACT_MILLIS.to_string())
}

fn writer(body: &str) -> Script {
    Script::new(&with_max(&format!("{CLOCK}{PRELUDE}{body}")))
}

pub(crate) static SCRIPTS: LazyLock<Scripts> = LazyLock::new(|| {
    let fields = RECORD_FIELDS.map(|f| format!("'{f}'")).join(", ");
    // The shebang must be the first line; it marks the script read-only.
    let resolve = with_max(&format!("#!lua flags=no-writes\n{CLOCK}{RESOLVE}"))
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
