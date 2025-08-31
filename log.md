
## veth6
```bash
# 10.0.0.1(de:ad:be:ef:0:1) -> 10.0.0.10(de:ad:be:ef:0:10)
<...>-11157   [003] ..s2.  5230.136134: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-11157   [003] ..s2.  5230.136180: bpf_trace_printk: Received Source IP: 0xa000001

           <...>-11157   [003] ..s2.  5230.136181: bpf_trace_printk: Received Destination IP: 0xa00000a

           <...>-11157   [003] ..s2.  5230.136183: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1

           <...>-11157   [003] ..s2.  5230.136184: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
```bash

```
           <...>-11157   [003] ..s2.  5230.136272: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-11157   [003] ..s2.  5230.136273: bpf_trace_printk: Received Source IP: 0xa000001

           <...>-11157   [003] ..s2.  5230.136273: bpf_trace_printk: Received Destination IP: 0xa00000a

           <...>-11157   [003] ..s2.  5230.136275: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1

           <...>-11157   [003] ..s2.  5230.136275: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
```bash

```
            curl-11157   [003] ..s2.  5230.136523: bpf_trace_printk: xdp loadbalancer received packet!
            curl-11157   [003] ..s2.  5230.136554: bpf_trace_printk: Received Source IP: 0xa000001

            curl-11157   [003] ..s2.  5230.136554: bpf_trace_printk: Received Destination IP: 0xa00000a

            curl-11157   [003] ..s2.  5230.136555: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1

            curl-11157   [003] ..s2.  5230.136556: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
```bash

```
           <...>-11158   [001] ..s2.  5230.137812: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-11158   [001] ..s2.  5230.137849: bpf_trace_printk: Received Source IP: 0xa000001

           <...>-11158   [001] ..s2.  5230.137850: bpf_trace_printk: Received Destination IP: 0xa00000a

           <...>-11158   [001] ..s2.  5230.137852: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1

           <...>-11158   [001] ..s2.  5230.137853: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
```bash

```
           <...>-11158   [001] ..s2.  5230.137915: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-11158   [001] ..s2.  5230.137916: bpf_trace_printk: Received Source IP: 0xa000001

           <...>-11158   [001] ..s2.  5230.137917: bpf_trace_printk: Received Destination IP: 0xa00000a

           <...>-11158   [001] ..s2.  5230.137918: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1

           <...>-11158   [001] ..s2.  5230.137918: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
```bash

```bash
            curl-11157   [003] ..s2.  5230.138171: bpf_trace_printk: xdp loadbalancer received packet!
            curl-11157   [003] ..s2.  5230.138192: bpf_trace_printk: Received Source IP: 0xa000001

            curl-11157   [003] ..s2.  5230.138193: bpf_trace_printk: Received Destination IP: 0xa00000a

            curl-11157   [003] ..s2.  5230.138194: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1

            curl-11157   [003] ..s2.  5230.138195: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
```

## veth7 
```bash
           <...>-8445    [001] ..s2.  1626.021502: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-8445    [001] ..s2.  1626.021540: bpf_trace_printk: Received Source IP: 0xa00000a

           <...>-8445    [001] ..s2.  1626.021541: bpf_trace_printk: Received Destination IP: 0xa000001

           <...>-8445    [001] ..s2.  1626.021542: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

           <...>-8445    [001] ..s2.  1626.021544: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```

```bash
           <...>-8445    [001] ..s2.  1626.021682: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-8445    [001] ..s2.  1626.021683: bpf_trace_printk: Received Source IP: 0xa00000a

           <...>-8445    [001] ..s2.  1626.021684: bpf_trace_printk: Received Destination IP: 0xa000001

           <...>-8445    [001] ..s2.  1626.021685: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

           <...>-8445    [001] ..s2.  1626.021686: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```

```bash
           <...>-8446    [003] ..s2.  1626.023088: bpf_trace_printk: xdp loadbalancer received packet!
           <...>-8446    [003] ..s2.  1626.023133: bpf_trace_printk: Received Source IP: 0xa00000a

           <...>-8446    [003] ..s2.  1626.023134: bpf_trace_printk: Received Destination IP: 0xa000001

           <...>-8446    [003] ..s2.  1626.023136: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

           <...>-8446    [003] ..s2.  1626.023137: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```

```bash
         python3-8446    [003] ..s2.  1626.023219: bpf_trace_printk: xdp loadbalancer received packet!
         python3-8446    [003] ..s2.  1626.023248: bpf_trace_printk: Received Source IP: 0xa00000a

         python3-8446    [003] ..s2.  1626.023248: bpf_trace_printk: Received Destination IP: 0xa000001

         python3-8446    [003] ..s2.  1626.023249: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

         python3-8446    [003] ..s2.  1626.023250: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```

```bash
         python3-8446    [003] ..s2.  1626.023255: bpf_trace_printk: xdp loadbalancer received packet!
         python3-8446    [003] ..s2.  1626.023256: bpf_trace_printk: Received Source IP: 0xa00000a

         python3-8446    [003] ..s2.  1626.023256: bpf_trace_printk: Received Destination IP: 0xa000001

         python3-8446    [003] ..s2.  1626.023257: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

         python3-8446    [003] ..s2.  1626.023258: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```

```bash
         python3-8446    [003] ..s2.  1626.023360: bpf_trace_printk: xdp loadbalancer received packet!
         python3-8446    [003] ..s2.  1626.023385: bpf_trace_printk: Received Source IP: 0xa00000a

         python3-8446    [003] ..s2.  1626.023385: bpf_trace_printk: Received Destination IP: 0xa000001

         python3-8446    [003] ..s2.  1626.023386: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

         python3-8446    [003] ..s2.  1626.023387: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```

```bash
            curl-8445    [000] ..s2.  1626.023561: bpf_trace_printk: xdp loadbalancer received packet!
            curl-8445    [000] ..s2.  1626.023580: bpf_trace_printk: Received Source IP: 0xa00000a

            curl-8445    [000] ..s2.  1626.023580: bpf_trace_printk: Received Destination IP: 0xa000001

            curl-8445    [000] ..s2.  1626.023581: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:10

            curl-8445    [000] ..s2.  1626.023582: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:1
```