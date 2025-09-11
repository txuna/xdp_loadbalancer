### 필요 커맨드

```bash
# lb namespace에 포함된 link 주소 출력
sudo ip netns exec lb ip link

# lb namespace에 포함된 ip 주소 출력
sudo ip netns exec lb ip addr

# lb network namespace에서 다음 명령어 실행
sudo ip netns exec lb python3 -m http.server
```

```bash
# bpf_printk 출력 위치
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

```bash
sudo ip netns exec lb  ./xdpdump -i veth6 -x

sudo ./xdpdump -D

sudo ip netns exec lb ./xdpdump --rx-capture entry,exit -i veth6 -x -v -w packet.pcap
```

```bash
scp -F ./ssh-config lima-default:/home/tuuna.linux/xdp_loadbalancer/xdp-tools/xdp-dump/packet.pcap .
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
