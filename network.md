

https://www.44bits.io/ko/post/container-network-2-ip-command-and-network-namespace

```bash
ip link
```

```bash
# 가상 인터페이스를 veth쌍 생성
ip link add veth0 type veth peer name veth1

ip -br link
```

네트워크 네임스페이스는 ip 명령어의 netns 서버 커맨드로 제어할 수 있다. add는 네임스페이스를 생성하고 list는 네임스페이스 목록을 보여준다. 
> ip netns를 사용하면 /var/run/netns/ 아래에 네트워크 네임스페이스가 영속화된다. 네트워크 네임스페이별 설정은 /etc/netns 아래에 저장한다.
```bash
ip netns add direct_netns
ip netns list

# direct_netns 네임스페이스에서 ip --br link 명령어 실행
# 현재는 loopback interface만 보인다.
ip netns exec direct_netns ip --br link

# direct_netns 네트워크 네임스페이스의 loopback 인터페이스 동작
ip netns exec direct_netns ip link set dev lo up

# chroot를 사용하지 않는다는것은 디폴트 네트워크 네임스페이스와 direct_netns 네트워크 네임스페이스와 파일 시스템 공유
ip netns exec direct_netns python3 -m http.server
```

앞서 만든 veth0/veth1쌍이 현재 default network namespace에 있는데 veth1를 direct_netns 네임스페이스로 옮긴다. 
```bash
ip link set veth1 netns direct_netns

ip a add 10.200.0.2/24 dev veth0
ip netns exec direct_netns ip a add 10.200.0.3/24 dev veth1

ip link set dev veth0 up
ip netns exec direct_netns ip link set dev veth1 up

ip -br addr
ip netns exec direct_netns ip -br addr
```

netns1, netns2만들고 veth2, veth3을 만들어서 서로 통신
ip할당은 10.200.0.4, 10.200.0.5로
```bash
# netns1, netns2 network namespace 생성
ip netns add netns1
ip netns add netns2 

# netns1, netns2 network namespace에서 loopback interface UP
ip netns exec netns1 ip link set dev lo up
ip netns exec netns2 ip link set dev lo up

# netns1 namespace 기준으로 veth2/veth3 쌍 생성
ip netns exec netns1 ip link add veth2 type veth peer name veth3

# veth3을 netns2 namespace로 이동
ip netns exec netns1 ip link set veth3 netns netns2

# veth2, veth3 ip 가상의 고정 IP 부여
ip netns exec netns1 ip a add 10.200.0.4/24 dev veth2
ip netns exec netns2 ip a add 10.200.0.5/24 dev veth3

# veth2, veth3 활성화
ip netns exec netns1 ip link set dev veth2 up
ip netns exec netns2 ip link set dev veth3 up

# 정리 - network namespace날리면 veth쌍도 날라감
ip netns delete netns1
ip netns delete netns2

# 정리2 
ip link delete veth2 type veth
```

브리지 네트워크(L2), ip 명령어로 veth 가상 인터페이스 뿐만 아니라 가상 브리지를 만드는 것도 가능하다. 브리지를 통해 네트워크 네임스페이스(컨테이너)들을 연결한다. 
> 하나의 bridge가 있고 netns4, netns5가 bridge에 연결된 상황
```bash
# br0이라는 이름을 가진 bridge 생성 및 활성화
ip link add br0 type bridge
ip link set br0 up

# brid4, veth4 쌍으로된 가상 인터페이스 생성 그리고 veth4를 netns4로 옮긴다. 
ip netns add netns4
ip link add brid4 type veth peer name veth4
ip link set veth4 netns netns4

# netns4 namespace에 존재하는 veth4 인터페이스에 ip를 부여하고 활성화 시킨다. 
ip netns exec netns4 ip a add 10.201.0.4/24 dev veth4 
ip netns exec netns4 ip link set dev lo up 
ip netns exec netns4 ip link set dev veth4 up

# 디폴트 네임스페이스에 있는 brid4 가상 인터페이스를 br0에 연결한다.
ip link set brid4 master br0
# brid4 인터페이스를 활성화한다.
ip link set dev brid4 up

# netns5에 대해서도 진행한다.
ip netns add netns5
ip link add brid5 type veth peer name veth5
ip link set veth5 netns netns5

ip netns exec netns5 ip a add 10.201.0.5/24 dev veth5
ip netns exec netns5 ip link set dev lo up
ip netns exec netns5 ip link set dev veth5 up

ip link set brid5 master br0
ip link set dev brid5 up
```

```bash
# forwoard 정책 확인
iptables -L | grep FORWARD

# 만약 DROP이라면
iptables --policy FORWARD ACCEPT
```

default network namespace에서 netns4 ip로 ping이 안가는 경우 br0에 ip와 브로드캐스트 IP를 부여한다.
```bash
route
ip addr add 10.201.0.1/24 brd 10.201.0.255 dev br0
ip a shot br0

# 10.201.0.0/24 IP대역이 br0에 연결된것을 확인 가능
route
```

현재 위 구성의 br0 브리지에 연결된 netns4, netns5가 외부 인터넷에 연결할 수 없다. 
> default는 따로 라우팅 규칙을 적용 받지 않을 때 나머지 모든 ip에 대한 라우트 처리를 한다. 컨테이너 네트워크 네임스페이스에 default 규칙을 추가한다. 
```bash
# 10.201.0.1으로 트래픽으 전송될 수 있도록 설정
ip netns exec netns4 ip route add default via 10.201.0.1
ip netns exec netns5 ip route add default via 10.201.0.1

# nat 셋업을 위해 리눅스의 IP 포워드 기능을 활성화 한다.
sysctl -w net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -s 10.201.0.0/24 -j MASQUERADE

# 이제 IP는 접근이 되지만 DNS는 접근이 안됨. 이는 네트워크 네임스페이스별로 DNS설정을 별도로 해야함.  
# /etc/netns/<NETNS> 디렉터리 아래 resolv.conf를 만들어야 가능

mkdir -p /etc/netns/netns4/
echo 'nameserver 8.8.8.8' > /etc/netns/netns4/resolv.conf

mkdir -p /etc/netns/netns5/
echo 'nameserver 8.8.8.8' > /etc/netns/netns5/resolv.conf
```

### 정리 
```bash
ip link delete brid4
ip link delete brid5
ip link delete br0 
ip netns delete netns4
ip netns delete netns5
```

### 셋업
> XDP LoadBalancer 할 때 veth4. veth5 mac 같으면 br_forward에서 리턴박음(동일 맥이라서 그런듯)
```bash
# 브릿지 생성 및 셋업
ip link add br0 type bridge
ip link set br0 up
ip link set br0 address DE:AD:BE:EF:00:01 # 나중에 세팅되나?
ip addr add 10.201.0.1/24 brd 10.201.0.255 dev br0
iptables --policy FORWARD ACCEPT

# container4 네트워크 네임스페이스 셋업
ip netns add container4
ip link add brid4 type veth peer name veth4
ip link set veth4 netns container4
ip netns exec container4 ip a add 10.201.0.4/24 dev veth4

ip netns exec container4 ip link set veth4 address DE:AD:BE:EF:00:04 

ip netns exec container4 ip link set dev lo up
ip netns exec container4 ip link set dev veth4 up
ip link set brid4 master br0
ip link set dev brid4 up
ip netns exec container4 ip route add default via 10.201.0.1

# container5 네트워크 네임스페이스 셋업
ip netns add container5
ip link add brid5 type veth peer name veth5
ip link set veth5 netns container5
ip netns exec container5 ip a add 10.201.0.5/24 dev veth5

ip netns exec container5 ip link set veth5 address DE:AD:BE:EF:00:05

ip netns exec container5 ip link set dev lo up
ip netns exec container5 ip link set dev veth5 up
ip link set brid5 master br0
ip link set dev brid5 up
ip netns exec container5 ip route add default via 10.201.0.1

# container6 네트워크 네임스페이스 셋업
ip netns add container6
ip link add brid6 type veth peer name veth6
ip link set veth6 netns container6
ip netns exec container6 ip a add 10.201.0.6/24 dev veth6

ip netns exec container6 ip link set veth6 address DE:AD:BE:EF:00:06

ip netns exec container6 ip link set dev lo up
ip netns exec container6 ip link set dev veth6 up
ip link set brid6 master br0
ip link set dev brid6 up
ip netns exec container6 ip route add default via 10.201.0.1

# NAT 및 DNS 셋업
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.201.0.0/24 -j MASQUERADE

mkdir -p /etc/netns/container4/
echo 'nameserver 8.8.8.8' > /etc/netns/container4/resolv.conf

mkdir -p /etc/netns/container5/
echo 'nameserver 8.8.8.8' > /etc/netns/container5/resolv.conf

mkdir -p /etc/netns/container6/
echo 'nameserver 8.8.8.8' > /etc/netns/container6/resolv.conf
```

### clean
```bash
ip netns delete container4
ip netns delete container5
ip netns delete container6
ip link delete br0 
```

docker가 만든 network namespace를 ip route 제어 범위안에 포함시키기
```bash
sudo ln -s /var/run/docker/netns/89d7bd5d4bb6 /var/run/netns/89d7bd5d4bb6
```

오 docker가 만든 network namespace를 ip 명령어로도 제어하고 싶으면 아래처럼 심볼릭 링크 연결하며 되는군요
ex)
ls /var/run/docker/netns 
> 89d7bd5d4bb6 

sudo ln -s /var/run/docker/netns/89d7bd5d4bb6 /var/run/netns/89d7bd5d4bb6

ip netns exec 89d7bd5d4bb6 [command]


```bash
sudo iptables -t nat -vnL POSTROUTING
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
