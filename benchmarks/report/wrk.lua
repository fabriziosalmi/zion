-- wrk script for the release report.
--
-- Environment (set by run.py):
--   PATHS_FILE   one request path per line, most popular first. With one line, every
--                request is that path; with several, a Zipf(s=1) draw picks one.
--   CLOSE=1      send "Connection: close": every request pays a new TLS handshake.
--   POST_BODY    send a POST with this body (application/json).
--
-- Determinism: each thread seeds Lua's PRNG with 1000 + its id, so the sequence of
-- paths a thread asks for is the same on every run. wrk's own scheduling still decides
-- how the threads interleave, which is why the report has trials and an interval.
--
-- done() prints one machine-readable line, "ZRES {json}", with the percentiles wrk
-- itself does not print (p99.9) and the error counters that make a trial invalid.

local counter = 0
local threads = {}

function setup(thread)
  counter = counter + 1
  thread:set("id", counter)
  table.insert(threads, thread)
end

local paths, cum, total = {}, {}, 0

function init(args)
  math.randomseed(1000 + id)
  for line in io.lines(os.getenv("PATHS_FILE")) do
    if #line > 0 then table.insert(paths, line) end
  end
  for i = 1, #paths do
    total = total + 1 / i
    cum[i] = total
  end
  if os.getenv("CLOSE") == "1" then wrk.headers["Connection"] = "close" end
  local body = os.getenv("POST_BODY")
  if body then
    wrk.method = "POST"
    wrk.body = body
    wrk.headers["Content-Type"] = "application/json"
  end
end

function request()
  if #paths == 1 then return wrk.format(nil, paths[1]) end
  local r = math.random() * total
  local lo, hi = 1, #paths
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    if cum[mid] < r then lo = mid + 1 else hi = mid end
  end
  return wrk.format(nil, paths[lo])
end

function done(summary, latency, requests)
  local e = summary.errors
  io.write(string.format(
    'ZRES {"requests":%d,"duration_us":%d,"bytes":%d,' ..
    '"errors":{"connect":%d,"read":%d,"write":%d,"status":%d,"timeout":%d},' ..
    '"lat_us":{"mean":%.1f,"stdev":%.1f,"p50":%d,"p90":%d,"p99":%d,"p999":%d,"max":%d}}\n',
    summary.requests, summary.duration, summary.bytes,
    e.connect, e.read, e.write, e.status, e.timeout,
    latency.mean, latency.stdev,
    latency:percentile(50), latency:percentile(90), latency:percentile(99),
    latency:percentile(99.9), latency.max))
end
