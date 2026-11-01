# Real resolvers against the prediction

Clock x1, 6 instances of each resolver, loopback only. *Inside* counts failed lookups
(SERVFAIL and timeouts) that fell inside the fetch model's predicted window, and *without timers*
the same when the simulator ignores how long resolvers remember a failure. *Recovery* is how many
real seconds after the zone became valid again the last failure was seen.

| Scenario | Resolver | Validating | Predicted (conservative / fetch) | Observed in fetch window | Lookups | Failures | Inside conservative | Inside fetch | Inside fetch, without timers | Recovery | EDE |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| ksk-realtime-bad | Unbound 1.26.2 | yes | 0.0h / 0.0h | 0.0h | 14,809 | 952 | 952/952 | 952/952 | 952/952 | -10 s | {'6': 952} |
| ksk-realtime-bad | BIND 9.16.50 | yes | 0.0h / 0.0h | 0.0h | 14,806 | 960 | 960/960 | 960/960 | 927/960 | 10 s | - |
| ttl-trap-realtime-bad | Unbound 1.26.2 | yes | 0.0h / 0.0h | 0.0h | 14,739 | 1,189 | 1,189/1,189 | 1,189/1,189 | 1,088/1,189 | 28 s | {'9': 1189} |
| ttl-trap-realtime-bad | BIND 9.16.50 | yes | 0.0h / 0.0h | 0.0h | 14,733 | 996 | 996/996 | 996/996 | 996/996 | -2 s | - |
