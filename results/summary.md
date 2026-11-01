# Real resolvers against the prediction

Clock x600, 3 instances of each resolver, loopback only. *Inside* counts failed lookups
(SERVFAIL and timeouts) that fell inside the fetch model's predicted window, and *without timers*
the same when the simulator ignores how long resolvers remember a failure. *Recovery* is how many
real seconds after the zone became valid again the last failure was seen.

| Scenario | Resolver | Validating | Predicted (conservative / fetch) | Observed in fetch window | Lookups | Failures | Inside conservative | Inside fetch | Inside fetch, without timers | Recovery | EDE |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| algorithm-rollover-bad | Unbound 1.26.2 | yes | 22.1h / 22.0h | 20.3h | 4,034 | 1,184 | 1,184/1,184 | 1,184/1,184 | 1,184/1,184 | -4 s | {'6': 1184} |
| algorithm-rollover-bad | BIND 9.16.50 | yes | 22.1h / 22.0h | 20.0h | 4,029 | 952 | 952/952 | 952/952 | 952/952 | -6 s | - |
| algorithm-rollover-good | Unbound 1.26.2 | yes | 0 / 0 | 0 | 4,657 | 0 | 0 | 0 | 0 | - | - |
| algorithm-rollover-good | BIND 9.16.50 | yes | 0 / 0 | 0 | 4,658 | 0 | 0 | 0 | 0 | - | - |
| go-insecure-bad | Unbound 1.26.2 | yes | 25.0h / 25.0h | 30.5h | 4,034 | 1,427 | 1,427/1,427 | 1,427/1,427 | 1,281/1,427 | 39 s | {'9': 1427} |
| go-insecure-bad | BIND 9.16.50 | yes | 25.0h / 25.0h | 23.2h | 4,030 | 1,069 | 1,069/1,069 | 1,069/1,069 | 1,069/1,069 | -6 s | - |
| go-insecure-good | Unbound 1.26.2 | yes | 0 / 0 | 0 | 4,272 | 0 | 0 | 0 | 0 | - | - |
| go-insecure-good | BIND 9.16.50 | yes | 0 / 0 | 0 | 4,272 | 0 | 0 | 0 | 0 | - | - |
| go-secure-bad | Unbound 1.26.2 | yes | 0.9h / 0 | 0 | 2,191 | 0 | 0 | 0 | 0 | - | - |
| go-secure-bad | BIND 9.16.50 | yes | 0.9h / 0 | 0 | 2,191 | 0 | 0 | 0 | 0 | - | - |
| go-secure-good | Unbound 1.26.2 | yes | 0 / 0 | 0 | 2,344 | 0 | 0 | 0 | 0 | - | - |
| go-secure-good | BIND 9.16.50 | yes | 0 / 0 | 0 | 2,344 | 0 | 0 | 0 | 0 | - | - |
| ksk-double-ds-bad | Unbound 1.26.2 | yes | 23.0h / 23.0h | 30.0h | 4,343 | 1,424 | 1,424/1,424 | 1,424/1,424 | 1,242/1,424 | 48 s | {'6': 1424} |
| ksk-double-ds-bad | BIND 9.16.50 | yes | 23.0h / 23.0h | 25.0h | 4,335 | 1,068 | 1,068/1,068 | 1,068/1,068 | 1,005/1,068 | 18 s | - |
| ksk-double-ds-good | Unbound 1.26.2 | yes | 0 / 0 | 0 | 6,198 | 0 | 0 | 0 | 0 | - | - |
| ksk-double-ds-good | BIND 9.16.50 | yes | 0 / 0 | 0 | 6,198 | 0 | 0 | 0 | 0 | - | - |
| ttl-trap-bad | Unbound 1.26.2 | yes | 23.1h / 23.1h | 14.1h | 3,961 | 482 | 482/482 | 482/482 | 482/482 | -48 s | {'9': 482} |
| ttl-trap-bad | BIND 9.16.50 | yes | 23.1h / 23.1h | 22.0h | 3,958 | 997 | 997/997 | 997/997 | 997/997 | -1 s | - |
| ttl-trap-good | Unbound 1.26.2 | yes | 0 / 0 | 0 | 4,278 | 0 | 0 | 0 | 0 | - | - |
| ttl-trap-good | BIND 9.16.50 | yes | 0 / 0 | 0 | 4,278 | 0 | 0 | 0 | 0 | - | - |
| zsk-prepublish-bad | Unbound 1.26.2 | yes | 23.2h / 1.1h | 0.2h | 7,896 | 4 | 4/4 | 4/4 | 4/4 | 0 s | {'9': 4} |
| zsk-prepublish-bad | BIND 9.16.50 | yes | 23.2h / 1.1h | 0 | 7,894 | 0 | 0 | 0 | 0 | - | - |
| zsk-prepublish-good | Unbound 1.26.2 | yes | 0 / 0 | 0 | 8,658 | 0 | 0 | 0 | 0 | - | - |
| zsk-prepublish-good | BIND 9.16.50 | yes | 0 / 0 | 0 | 8,658 | 0 | 0 | 0 | 0 | - | - |
