
14:37:21.693720 IP (tos 0x0, ttl 64, id 57555, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [S], cksum 0xa3e3 (correct), seq 2430505455, win 64240, options [mss 1460,sackOK,TS val 1700155629 ecr 0,nop,wscale 7], length 0

14:37:21.693778 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.0.2.8000 > 10.0.0.10.40142: Flags [S.], cksum 0x143a (incorrect -> 0x7a4c), seq 4114852806, ack 2430505456, win 65160, options [mss 1460,sackOK,TS val 3496064129 ecr 1700155629,nop,wscale 7], length 0

14:37:21.693989 IP (tos 0x0, ttl 64, id 57556, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [.], cksum 0xa5aa (correct), seq 1, ack 1, win 502, options [nop,nop,TS val 1700155630 ecr 3496064129], length 0

14:37:21.694345 IP (tos 0x0, ttl 64, id 57557, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x67fe (incorrect -> 0x5dfe), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700155630 ecr 3496064129], length 77

14:37:21.899960 IP (tos 0x0, ttl 64, id 57558, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x6730 (incorrect -> 0x5d30), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700155836 ecr 3496064129], length 77

14:37:22.113098 IP (tos 0x0, ttl 64, id 57559, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x665b (incorrect -> 0x5c5b), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700156049 ecr 3496064129], length 77

14:37:22.517472 IP (tos 0x0, ttl 64, id 57560, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x64c7 (incorrect -> 0x5ac7), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700156453 ecr 3496064129], length 77

14:37:23.375321 IP (tos 0x0, ttl 64, id 57561, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x616d (incorrect -> 0x576d), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700157311 ecr 3496064129], length 77

14:37:25.041003 IP (tos 0x0, ttl 64, id 57562, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x5aeb (incorrect -> 0x50eb), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700158977 ecr 3496064129], length 77

14:37:28.300400 IP (tos 0x0, ttl 64, id 57563, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x4e30 (incorrect -> 0x4430), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700162236 ecr 3496064129], length 77

14:37:35.021863 IP (tos 0x0, ttl 64, id 57564, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0x33ef (incorrect -> 0x29ef), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700168957 ecr 3496064129], length 77

14:37:48.335424 IP (tos 0x0, ttl 64, id 57565, offset 0, flags [DF], proto TCP (6), length 129)
    10.0.0.10.40142 > 10.0.0.2.8000: Flags [P.], cksum 0xffec (incorrect -> 0xf5ec), seq 1:78, ack 1, win 502, options [nop,nop,TS val 1700182271 ecr 3496064129], length 77



    ---
12 packets captured
12 packets received by filter
0 packets dropped by kernel
➜  ~ sudo ip netns exec h2 tcpdump -i veth2 -n -vv tcp port 8000
tcpdump: listening on veth2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C14:43:33.982953 IP (tos 0x0, ttl 64, id 45025, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [S], cksum 0x1431 (incorrect -> 0xb0e8), seq 1241477557, win 64240, options [mss 1460,sackOK,TS val 1362863107 ecr 0,nop,wscale 7], length 0
14:43:33.982991 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.0.2.8000 > 10.0.0.1.47088: Flags [S.], cksum 0x1431 (incorrect -> 0x2a3a), seq 369537025, ack 1241477558, win 65160, options [mss 1460,sackOK,TS val 2048344806 ecr 1362863107,nop,wscale 7], length 0
14:43:33.983043 IP (tos 0x0, ttl 64, id 45026, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [.], cksum 0x1429 (incorrect -> 0x5599), seq 1, ack 1, win 502, options [nop,nop,TS val 1362863107 ecr 2048344806], length 0
14:43:33.983255 IP (tos 0x0, ttl 64, id 45027, offset 0, flags [DF], proto TCP (6), length 128)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [P.], cksum 0x1475 (incorrect -> 0xd753), seq 1:77, ack 1, win 502, options [nop,nop,TS val 1362863107 ecr 2048344806], length 76
14:43:33.983265 IP (tos 0x0, ttl 64, id 9883, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.2.8000 > 10.0.0.1.47088: Flags [.], cksum 0x1429 (incorrect -> 0x5546), seq 1, ack 77, win 509, options [nop,nop,TS val 2048344806 ecr 1362863107], length 0
14:43:33.991615 IP (tos 0x0, ttl 64, id 9884, offset 0, flags [DF], proto TCP (6), length 208)
    10.0.0.2.8000 > 10.0.0.1.47088: Flags [P.], cksum 0x14c5 (incorrect -> 0x4b07), seq 1:157, ack 77, win 509, options [nop,nop,TS val 2048344814 ecr 1362863107], length 156
14:43:33.991667 IP (tos 0x0, ttl 64, id 45028, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [.], cksum 0x1429 (incorrect -> 0x54a2), seq 77, ack 157, win 501, options [nop,nop,TS val 1362863115 ecr 2048344814], length 0
14:43:33.991801 IP (tos 0x0, ttl 64, id 9885, offset 0, flags [DF], proto TCP (6), length 1602)
    10.0.0.2.8000 > 10.0.0.1.47088: Flags [P.], cksum 0x1a37 (incorrect -> 0xddbf), seq 157:1707, ack 77, win 509, options [nop,nop,TS val 2048344815 ecr 1362863115], length 1550
14:43:33.991813 IP (tos 0x0, ttl 64, id 45029, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [.], cksum 0x1429 (incorrect -> 0x4e79), seq 77, ack 1707, win 526, options [nop,nop,TS val 1362863116 ecr 2048344815], length 0
14:43:33.991959 IP (tos 0x0, ttl 64, id 9887, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.2.8000 > 10.0.0.1.47088: Flags [F.], cksum 0x1429 (incorrect -> 0x4e89), seq 1707, ack 77, win 509, options [nop,nop,TS val 2048344815 ecr 1362863116], length 0
14:43:33.991979 IP (tos 0x0, ttl 64, id 45030, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [F.], cksum 0x1429 (incorrect -> 0x4e78), seq 77, ack 1707, win 526, options [nop,nop,TS val 1362863116 ecr 2048344815], length 0
14:43:33.991988 IP (tos 0x0, ttl 64, id 9888, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.2.8000 > 10.0.0.1.47088: Flags [.], cksum 0x1429 (incorrect -> 0x4e88), seq 1708, ack 78, win 509, options [nop,nop,TS val 2048344815 ecr 1362863116], length 0
14:43:33.992003 IP (tos 0x0, ttl 64, id 45031, offset 0, flags [DF], proto TCP (6), length 52)
    10.0.0.1.47088 > 10.0.0.2.8000: Flags [.], cksum 0x1429 (incorrect -> 0x4e77), seq 78, ack 1708, win 526, options [nop,nop,TS val 1362863116 ecr 2048344815], length 0