# G6 benchmark summary — run `20261125T000721Z-72a14df51eca`

Evidence, not pass/fail: numbers are from one machine (see `manifest.json`) and are not comparable across machines. Latencies in µs, `p50 / p95 / p99`. Full rows: `results.csv` / `results.json`.

## HTTP (sequential, loopback)

| strategy | N | case | HPKE attempts (min–max) | e2e latency | server trial time | invariant |
| --- | ---: | --- | --- | --- | --- | --- |
| unique_uri | 1 | valid_last | 1–1 | 810.5 / 923.6 / 1010.2 | 586.2 / 635.4 / 664.6 | pass |
| unique_uri | 1 | invalid_ciphertext | 1–1 | 464.4 / 633.9 / 973.3 | 267.0 / 300.0 / 308.7 | pass |
| unique_uri | 2 | valid_last | 1–1 | 815.6 / 1034.2 / 1138.7 | 584.2 / 645.1 / 662.0 | pass |
| unique_uri | 2 | invalid_ciphertext | 1–1 | 464.1 / 535.0 / 722.9 | 265.5 / 292.4 / 299.3 | pass |
| unique_uri | 8 | valid_last | 1–1 | 791.0 / 993.3 / 1152.0 | 577.5 / 625.2 / 641.0 | pass |
| unique_uri | 8 | invalid_ciphertext | 1–1 | 456.4 / 554.5 / 733.2 | 267.5 / 300.8 / 310.0 | pass |
| unique_uri | 32 | valid_last | 1–1 | 795.6 / 995.8 / 1407.0 | 575.0 / 626.7 / 659.5 | pass |
| unique_uri | 32 | invalid_ciphertext | 1–1 | 461.1 / 546.8 / 656.4 | 263.9 / 289.5 / 301.1 | pass |
| unique_uri | 64 | valid_last | 1–1 | 1160.2 / 3528.7 / 3964.9 | 620.0 / 730.1 / 946.2 | pass |
| unique_uri | 64 | invalid_ciphertext | 1–1 | 954.9 / 3110.9 / 4057.1 | 287.0 / 369.4 / 635.4 | pass |
| unique_uri | 128 | valid_last | 1–1 | 875.5 / 1276.9 / 1471.5 | 597.5 / 695.3 / 810.0 | pass |
| unique_uri | 128 | invalid_ciphertext | 1–1 | 473.3 / 677.9 / 953.3 | 264.7 / 298.2 / 314.6 | pass |
| unique_kid | 1 | valid_last | 1–1 | 912.9 / 1186.8 / 1410.0 | 598.5 / 684.5 / 796.7 | pass |
| unique_kid | 1 | invalid_ciphertext | 1–1 | 501.5 / 651.8 / 745.5 | 268.5 / 318.7 / 411.9 | pass |
| unique_kid | 2 | valid_last | 1–1 | 875.0 / 1044.5 / 1234.9 | 596.0 / 646.1 / 663.0 | pass |
| unique_kid | 2 | invalid_ciphertext | 1–1 | 519.9 / 683.0 / 778.2 | 273.7 / 327.9 / 353.0 | pass |
| unique_kid | 8 | valid_last | 1–1 | 853.5 / 1073.2 / 1144.8 | 593.4 / 677.4 / 708.6 | pass |
| unique_kid | 8 | invalid_ciphertext | 1–1 | 550.9 / 929.8 / 970.2 | 275.2 / 331.5 / 510.5 | pass |
| unique_kid | 32 | valid_last | 1–1 | 944.1 / 1288.2 / 1711.1 | 604.7 / 730.6 / 896.5 | pass |
| unique_kid | 32 | invalid_ciphertext | 1–1 | 549.4 / 709.6 / 881.7 | 269.8 / 312.8 / 327.9 | pass |
| unique_kid | 64 | valid_last | 1–1 | 975.9 / 1388.5 / 1844.2 | 630.3 / 792.1 / 900.6 | pass |
| unique_kid | 64 | invalid_ciphertext | 1–1 | 588.8 / 866.8 / 1207.3 | 284.7 / 341.2 / 369.4 | pass |
| unique_kid | 128 | valid_last | 1–1 | 1330.2 / 3805.2 / 7036.9 | 661.0 / 1032.7 / 1176.6 | pass |
| unique_kid | 128 | invalid_ciphertext | 1–1 | 833.0 / 2785.3 / 4341.8 | 305.9 / 342.5 / 459.5 | pass |
| bounded_trial | 1 | valid_last | 1–1 | 1208.3 / 3659.8 / 6107.1 | 666.1 / 860.2 / 1212.4 | pass |
| bounded_trial | 1 | invalid_ciphertext | 1–1 | 1250.3 / 5279.7 / 7008.3 | 312.1 / 524.0 / 1407.0 | pass |
| bounded_trial | 2 | valid_last | 2–2 | 1219.6 / 1476.6 / 1669.1 | 927.2 / 1026.6 / 1097.7 | pass |
| bounded_trial | 2 | invalid_ciphertext | 2–2 | 885.2 / 1143.8 / 1473.5 | 578.0 / 673.3 / 737.8 | pass |
| bounded_trial | 8 | valid_last | 8–8 | 2865.2 / 3211.3 / 5140.5 | 2523.1 / 2838.5 / 3311.6 | pass |
| bounded_trial | 8 | invalid_ciphertext | 8–8 | 2496.5 / 2738.2 / 2992.1 | 2215.9 / 2402.3 / 2439.2 | pass |
| bounded_trial | 32 | valid_last | 32–32 | 10297.3 / 13066.2 / 19300.4 | 9797.6 / 11526.1 / 14196.7 | pass |
| bounded_trial | 32 | invalid_ciphertext | 32–32 | 11804.7 / 20971.5 / 27459.6 | 9953.3 / 18038.8 / 24166.4 | pass |
| bounded_trial | 64 | valid_last | 64–64 | 19349.5 / 24035.3 / 30474.2 | 18825.2 / 21479.4 / 30031.9 | pass |
| bounded_trial | 64 | invalid_ciphertext | 64–64 | 20119.6 / 25182.2 / 30785.5 | 19169.3 / 23445.5 / 29147.1 | pass |
| bounded_trial | 128 | valid_last | 128–128 | 36962.3 / 39878.7 / 40534.0 | 36536.3 / 39157.8 / 39649.3 | pass |
| bounded_trial | 128 | invalid_ciphertext | 128–128 | 36405.2 / 39321.6 / 44105.7 | 36012.0 / 38371.3 / 43024.4 | pass |

## Over budget (bounded trial, N > budget)

| N | budget | HPKE attempts (max) | e2e latency | invariant |
| ---: | ---: | ---: | --- | --- |
| 32 | 8 | 0 | 258.8 / 1223.7 / 1765.4 | pass |
| 64 | 8 | 0 | 306.4 / 983.6 / 1928.2 | pass |
| 128 | 8 | 0 | 194.9 / 683.5 / 1036.8 | pass |

## Burst (concurrent valid POSTs, limits on vs off)

| strategy | N | limits | requests | 503 | rejection ratio | throughput (req/s) | e2e latency | invariant |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |
| unique_uri | 64 | on | 640 | 559 | 0.8734 | 18564.4 | 697.3 / 2424.8 / 3278.8 | pass |
| unique_uri | 64 | off | 640 | 0 | 0.0000 | 10559.9 | 5161.0 / 7106.6 / 7610.4 | pass |
| bounded_trial | 64 | on | 640 | 560 | 0.8750 | 869.5 | 701.4 / 54132.7 / 73203.7 | pass |
| bounded_trial | 64 | off | 640 | 0 | 0.0000 | 746.0 | 63569.9 / 84672.5 / 87162.9 | pass |

## In-flight cap (controlled admission: cap requests held, one more sent)

| cap | probes | 503 | probe latency | invariant |
| ---: | ---: | ---: | --- | --- |
| 8 | 10 | 10 | 190.3 / 299.3 / 299.3 | pass |

## Session store (no HTTP): memory vs Redis

| backend | operation | requests | latency | invariant |
| --- | --- | ---: | --- | --- |
| memory | insert | 1000 | 0.2 / 0.4 / 0.6 | pass |
| memory | resolve_unique_uri | 1000 | 0.2 / 0.2 / 0.3 | pass |
| memory | claim | 1000 | 0.4 / 0.5 / 0.8 | pass |
| redis | insert | 1000 | 256.1 / 399.1 / 486.7 | pass |
| redis | resolve_unique_uri | 1000 | 247.9 / 386.6 / 546.8 | pass |
| redis | claim | 1000 | 247.3 / 401.9 / 555.0 | pass |
| redis | ping | 1000 | 218.0 / 337.4 / 464.6 | pass |

## Invariants

All 132 checked rows hold their invariants.
