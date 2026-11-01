# Real resolvers against the prediction

Clock x1, 6 instances of each resolver, loopback only. *Inside* counts failed lookups
(SERVFAIL and timeouts) that fell inside the fetch model's predicted window, and *without timers*
the same when the simulator ignores how long resolvers remember a failure. *Recovery* is how many
real seconds after the zone became valid again the last failure was seen.

| Scenario | Resolver | Validating | Predicted (conservative / fetch) | Observed in fetch window | Lookups | Failures | Inside conservative | Inside fetch | Inside fetch, without timers | Recovery | EDE |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| ksk-realtime-bad | Unbound 1.26.2 | yes | 0.0h / 0.0h | 0.0h | 14,808 | 950 | 950/950 | 950/950 | 950/950 | -11 s | {'6': 950} |
| ksk-realtime-bad | BIND 9.16.50 | yes | 0.0h / 0.0h | 0.0h | 14,808 | 960 | 960/960 | 960/960 | 930/960 | 10 s | - |
| ttl-trap-realtime-bad | Unbound 1.26.2 | yes | 0.0h / 0.0h | 0.0h | 14,734 | 1,664 | 1,664/1,664 | 1,664/1,664 | 1,468/1,664 | 27 s | {'9': 1664} |
| ttl-trap-realtime-bad | BIND 9.16.50 | yes | 0.0h / 0.0h | 0.0h | 14,733 | 996 | 996/996 | 996/996 | 996/996 | -3 s | - |
