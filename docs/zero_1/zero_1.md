# ZERO COPY의 미학 #1 (XDP LoadBalancer편)

## 소개
매우 간단한 서버를 구축한다고 했을 때 아래와 같이 생각할 수 있다. 
![alt text](image.png)

분산시스템 이론을 제외한채 서버의 트래픽을 분리하기 위해서는 추가적인 서버를 필요로하고 클라이언트의 요청을 특정 서버로 포워딩 시키기 위해서는 앞단에 로드밸런서를 둘 수 있다. 로드밸런서를 뒀던 목적이 트래픽분리로 속도의 이점을 챙기려했지만 패킷이 이동하는 경로에 물리적인(또는 가상의) 네트워크 홉이 추가되었기에 이전 로드밸런서가 없던(베이스라인)시기보다 느리게된다.

일반적인 로드밸런서의 종류로는 유저스페이스 또는 커널스페이스에서 동작하는 구조로 나뉜다. 유저스페이스 로드밸런서의 경우 네트워크 인터페이스에서 패킷을 처리하고 커널스페이스로, 커널스페이스에서 유저스페이스로의 패킷 메모리 복사가 발생하여 속도측면에서 손실이 발생한다. 더군다나 서버가 아닌 패킷을 포워딩해야하는 로드밸런서 입장에서는 불필요한 오버헤드라고 볼 수 있다. 커널스페이스단에서 동작하는 로드밸런서의 경우 앞서 언급된 유저스페이스로의 메모리 카피등의 오버헤드는 줄일 수 있지만 네트워크스택(TCP/IP)을 거친다는 입장에서 그리고 핵심적인 NIC에서 수신한 패킷을 sk_buff 구조체를 할당하는 메모리 카피 부분이 발생한다.

![alt text](image-2.png)
[출처: https://en.wikipedia.org/wiki/Iptables]

앞서 말했듯이 이러한 부분은 포워딩하는 입장에서는 불필요한 오버헤드로 판단될 수 있다. 이번 글은 위의 문제점을 해결하는 리눅스 커널의 네트워크 TCP/IP 스택을 거치지 않고 sk_buff 구조체 할당을 진행하지 않는 zero copy를 할 수 있도록 도와주는 eBPF의 한종류인 XDP에 대해서 알아보고자 한다. 그리고 XDP LoadBalancer에 대해서 자세히 알아보고자 한다. 마지막으로는 실제 만든 XDP 로드밸런서 프로그램이 userspace에서 동작하는 로드밸런서와 비교했을 때 어느정도의 속도적 이점이 존재하는지 제시하고자 한다.

다만 이글은 리눅스 네트워크 스택이 어떤식으로 구성하는지는 다루지않는다. 다만 eBPF/XDP와 로드밸런서를 다루며 어떻게 패킷을 고속으로 처리할지 또 관련 디버깅 도구 소개가 주 목적이다. 

## eBPF?   
eBPF/XDP와 관련해서 설명하기전에 BPF라는 것이 무엇인지 간략하게 설명하는것부터 시작한다.
![alt text](image-1.png)
[출처: https://ebpf.io/what-is-ebpf/]  
> 본 내용은 XDP를 설명하기위한 과정이므로 eBPF Virtual Machine, Verifier의 동작은 설명하지 않으며 언급만하고 넘어간다.

eBPF는 BPF(Berkeley Packet Filter)의 약자이지만 extend BPF는 패킷필터 이상의 기능(관찰가능성, 트레이싱, ,,,)을 수행하기 때문에 이제는 어떤 의미도 없는 독릭적인 용어다. eBPF 프로그램은 이벤트 기반이며 커널이나 애플리케이션이 특정 훅 지점을 통과할 때 실행된다. 후크의 종류로는 syscall, kernel or user tracing, network event, function entry/exit가 존재한다. 이러한 eBPF 프로그램은 커널스페이스에서 동작하기 때문에 엄격한 Verifier(검증기)를 통해 동작에 이상이 없음을 확인하고 JIT Compiler로부터 동작된다. 엄격한 검증기때문에 몇몇 함수 사용이 제한되기 때문에 eBPF는 특수한 형태의 커널 헬퍼 함수를 사용할 수 있다. 
> 엄격한 검사의 예로는 패킷 포인터 접근시 경계를 넘어갈 가능성이 있는지등이 존재한다.

즉, eBPF는 크게 BPF MAP, Virtual Machine, Verifier 3가지의 구성요소가 존재한다.

## XDP(eXpress Data Path)
XDP(eXpress Data Path)는 프로그래밍 가능한 패킷 처리 기술이다. 이전에 존재한 DPDK는 커널을 우회했기 때문에 보안과 안정성은 보장할 수 없었다. XDP 프로그램은 앞서 말한것과 같이 eBPF 프로그램은 검증기와 JIT을 통해 커널공간에서 안전하게 실행된다. 또한, XDP는 리눅스 커널의 일부분으로 구현되어 있어 리눅스 네트워크 스택과 완전히 통합된다. 그렇기에 프로그래머는 커널과 사용자 공간사이의 컨텍스트 전환없이 장치 드라이버(NIC)에서 직접 코드 실행이 가능하기에 하드웨어에서 패킷 수신 직후 해당 패킷의 처리를 결정 또는 조작등 여러가지 구현이 가능하다.

만든 XDP 프로그램의 반환값으로 Action이라는 정수 반환값을 필요로 하며 지원가능한 값은 다음과 같다. `XDP_DROP`, `XDP_PASS`, `XDP_REDIRECT`, `XDP_TX`

- `XDP_ABORTED`: 패킷을 DROP함과 동시에 예외를 추가로 일으킨다.
- `XDP_DROP` : 패킷을 DROP한다.  
- `XDP_PASS` : 패킷을 다음 처리기로 이동을 허용한다.
- `XDP_REDIRECT` : 도착한 패킷을 다른 NIC로 전달하거나, 추가처리를 위한 다른 CPU로 전달허간, 사용자 공간으로 전달한다.
- `XDP_TX` : 패킷을 수신했던 NIC로 다시 주입한다. 
> XDP_REDIRECT의 경우 나머지 3개의 Action과 달리 bpf helper함수를 필요로한다.

XDP가 무엇인지는 대략적으로 감을 잡았더라도 어디서 어떻게 동작하는지 와닫지 않았을것이다. 실제로 XDP Program이 어떠한 과정으로 실행되는지 짧게 살펴본다. 사용되는 시스템은 실제 호스트가 아닌 가상머신과 가상이더넷을 기반으로 진행예정이므로 리눅스 커널의 virtio와 veth를 중심으로 살펴본다. 그리고 실제 XDP프로그램이 veth에 attach 예정인데 veth에 XDP 프로그램이 붙었는가에 따라 동작이 상이해진다. 이러한 부분 또한 집중적으로 살펴보겠다. 그리고 XDP는 Native와 Generic 모드가 존재하는데 Generic 모드는 간단하게 살펴보고 실제 구현과 동작은 Native 모드를 기준으로 진행한다.

### XDP INSTALL & ATTACH
> 본 소스코드는 Linux Kernel의 v6.11과 v6.17을 기준으로 합니다.
```C
/* drivers/net/veth.c */
static const struct net_device_ops veth_netdev_ops = {
	.ndo_init           = veth_dev_init,
	.ndo_start_xmit     = veth_xmit,
	.ndo_bpf		    = veth_xdp,
	.ndo_xdp_xmit		= veth_ndo_xdp_xmit,
	.ndo_get_peer_dev	= veth_peer_dev,
};

/* drivers/net/virtio_net.c */
static const struct net_device_ops virtnet_netdev = {
	.ndo_open            = virtnet_open,
	.ndo_stop   	     = virtnet_close,
	.ndo_start_xmit      = start_xmit,
	.ndo_bpf		     = virtnet_xdp,
};

/* net/core/dev.c */
static int dev_xdp_attach(struct net_device *dev, struct netlink_ext_ack *extack,
			  struct bpf_xdp_link *link, struct bpf_prog *new_prog,
			  struct bpf_prog *old_prog, u32 flags)
{
    enum bpf_xdp_mode mode;
    [...]
    /* Generic or Native */
    mode = dev_xdp_mode(dev, flags);
    [...]
    /* get xdp installation function */
    bpf_op = dev_xdp_bpf_op(dev, mode);
    [...]
    /* install xdp hook */
    err = dev_xdp_install(dev, mode, bpf_op, extack, flags, new_prog);
}

/* net/core/dev.c */
static bpf_op_t dev_xdp_bpf_op(struct net_device *dev, enum bpf_xdp_mode mode)
{
	switch (mode) {
	case XDP_MODE_SKB:
		return generic_xdp_install;
	case XDP_MODE_DRV:
	case XDP_MODE_HW:
		return dev->netdev_ops->ndo_bpf;
	default:
		return NULL;
	}
}
```
XDP 프로그램을 설치하게되면 `dev_xdp_attach` 함수를 호출하여 xdp를 붙일 때 `dev_xdp_mode`함수를 통해 XDP 동작 모드를 Generic 또는 Native중 하나 선택한다. `dev_xdp_install`함수 내에서 `Generic`의 경우 `generic_xdp_install`함수를 호출하여 generic_xdp_needed_key 값을 세팅한다. `Generic`의 경우 해당 값이 세팅되면 `__netif_receive_skb_core` -> `do_xdp_generic` 함수를 호출하여 XDP 프로그램을 실행한다. 함수에서 볼 수 있듯이 `sk_buff` 할당 이후에 실행되기에 일반적으로 알려진 `sk_buff`할당 이전에 실행되는 `Native` 모드와 차이가 있으며 성능 또한 떨어진다. 다만 모든 드라이버에 지원이 가능하며 테스트환경으로 진행은 가능하다.  

그 외의 경우 `ndo_bpf`에 연결된 함수 포인터를 호출하게 된다. `virtio_net`의 경우 `virtnet_xdp`, `veth`의 경우 `veth_xdp` 함수 이다. 실제 로드밸런서 구현에서 XDP 프로그램이 실행되는 곳은 `veth`이므로 해당 구간을 살펴본다. [`NAPI`](https://docs.kernel.org/networking/napi.html)의 경우 해당 링크를 참고하기를 바란다.

```C
/* drivers/net/veth.c */
static int veth_enable_xdp_range(struct net_device *dev, int start, int end,
				 bool napi_already_on)
{
[...]
    if (!napi_already_on)
        netif_napi_add(dev, &rq->xdp_napi, veth_poll);
[...]
	return err;
}
```
`veth_xdp`함수를 시작으로 타고 들어가면 `veth_enable_xdp_range`라는 함수를 확인할 수 있다. 해당 구간을 통해 napi의 poll함수 포인터에 `veth_poll`함수를 등록한다. NAPI를 활성화하고 polling함수로 `veth_poll`을 사용함을 의미한다. `NAPI`에대한 글이아닌 XDP 설치 및 실행에 관한것이기에 자세한것은 넘어간다. `bpftrace`를 사용해서 설명한 구간까지 실행되는지를 확인할 수 있다.

```bash
$ sudo bpftrace -e 'kprobe:veth_enable_xdp_range { print(kstack); }'
Attaching 1 probe...

veth_enable_xdp_range+0
veth_xdp_set+312
veth_xdp+40
dev_xdp_install+116
dev_xdp_attach+512
bpf_xdp_link_attach+512
link_create+548
__sys_bpf+788
```
`kprobe`를 사용해서 `veth_enable_xdp_range` 함수가 호출되는 시점에 kernel stack을 출력하는 `print(kstack)`를 실행한다. 이또한 `eBPF`를 사용해서 커널코드를 트레이싱하는 도구로 여기서도 `eBPF`의 편리함과 강력함을 알 수 있다.

여기까지가 XDP프로그램을 attach했을 때의 로직이다. `NAPI`관련해서는 보여야할 내용이 매우 많기 때문에 기회가 된다면 다른 챕터를 통해서 소개하고 싶다.

#### 번외) veth가 Native XDP를 지원하나요?
2018년 커널 패치중 veth에 generic이 아닌 native XDP를 지원하는 패치가 등장했다. 관련된 내용은 아래 패치를 참고하기를 바란다.  [Merge branch 'bpf-veth-xdp-support'](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=60afdf066a35317efd5d1d7ae7c7f4ef2b32601f)


### XDP EXECUTION
설치된 XDP 프로그램이 실행되는 구간을 살펴볼 필요가 있다. 패킷처리 과정에서 XDP Program을 실행시키는데 공통적으로 `bpf_prog_run_xdp`함수를 호출하면서 동작한다. `veth`를 기준으로 해당 함수가 실행되기까지를 조금 설명하자면 다음과 같다. 그리고 실제 동작을 확인하기 위해 아래와 같이 was라는 `network namespace`를 만들고 `veth`를 배정한다.

```bash
# was라는 network namespace를 만든다.
$ sudo ip netns add was

# veth0, veth1쌍을 생성한다. 
$ sudo ip link add veth0 type veth peer name veth1

# veth1를 was network namespace에 배정한다.
$ sudo ip link set veth1 netns was
# 배정 확인
$ sudo ip netns exec was ip link

# veth0에 10.10.0.2 IP 주소를 부여한다. veth1에도 10.10.0.3을 부여한다.
$ sudo ip a add 10.10.0.2/24 dev veth0
$ sudo ip netns exec was ip a add 10.10.0.3/24 dev veth1

# veth0, veth1 up으로 변경한다.
$ sudo ip link set dev veth0 up
$ sudo ip netns exec was ip link set dev veth1 up

# 삭제
$ ip netns del was
```

```bash
### 1
$ sudo ip link
13: veth0@if12       UP             0a:31:b3:03:2a:a9 <BROADCAST,MULTICAST,UP,LOWER_UP>

### 2
$ sudo ip netns exec was ip link
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
12: veth1@if13       UP             fe:2d:16:44:5c:c4 <BROADCAST,MULTICAST,UP,LOWER_UP>
```

`ifindex`값이 각 각 `13`, `12`가 출력된다. 이상태에서 `was` 네임스페이스에서 웹서버를 실행한다. 
```bash
$ sudo ip netns exec was python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
그리고 다른 한쪽은 `bpftrace`를 사용해서 트레이싱을 진행한다.

```bash
sudo bpftrace -e 'kfunc:dev_hard_start_xmit
{
  if(args->dev->ifindex==2 || args->dev->ifindex==1) {
    return;
  }
  printf("ifindex=%d\n", args->dev->ifindex);
  print(kstack);
}'

Attaching 1 probe...

ifindex=13
dev_hard_start_xmit+8
[...]
__tcp_transmit_skb+1156
tcp_connect+1168
tcp_v4_connect+964
```
패킷을 전송하게 되면 커널 스택에서 볼 수 있는것처럼 기본적으로 상위 레이어부터 `dev_hard_start_xmit` -> `xmit_one` -> `netdev_start_xmit` -> `__netdev_start_xmit` -> `ndo_start_xmit` 로직을 수행한다. `ndo_start_xmit`함수포인터는 위에서 설명했듯이 `veth_xmit`과 연결된다. 

```C
/* drivers/net/veth.c */
static netdev_tx_t veth_xmit(struct sk_buff *skb, struct net_device *dev)
{
    [...]
    ret = veth_forward_skb(rcv, skb, rq, use_napi); // if xdp attached, use_napi=true
    [...]
}

static int veth_forward_skb(struct net_device *dev, struct sk_buff *skb,
			    struct veth_rq *rq, bool xdp)
{
	return __dev_forward_skb(dev, skb) ?: xdp ?
		veth_xdp_rx(rq, skb) :
		__netif_rx(skb);
}
```
`veth_xmit`과 연결된 `veth_forward_skb`에서 xdp가 true라면 `veth_xdp_rx`함수를 호춯한다. 해당 함수는 ptr ring buffer queue에 데이터를 주입한다.
> __dev_forward_skb 함수는 상대 peer로 패킷 주입이 가능한지 다른 네트워크 네임스페이스로 넘어가는 패킷의 경우 관련 정보를 scrub 해야할지등을 결정한다. 
> __dev_forward_skb가 아닌 dev_forward_skb는 내부적으로 __dev_forward_skb 후 netif_rx_internal를 호출한다. 

```C
/* drivers/net/veth.c */
static int veth_xdp_rx(struct veth_rq *rq, struct sk_buff *skb)
{
	if (unlikely(ptr_ring_produce(&rq->xdp_ring, skb)))
		return NETDEV_TX_BUSY; /* signal qdisc layer */

	return NET_RX_SUCCESS; /* same as NETDEV_TX_OK */
}
```
주입은 `ptr_ring_produce`함수를 통해 진행된다. 생산자를 통해 삽입된 데이터는 NAPI Polling을 통해서 호출되는 `veth_poll` 함수를 통해 소비된다.

```C
/* drivers/net/veth.c */
static int veth_poll(struct napi_struct *napi, int budget)
{
[...]
	done = veth_xdp_rcv(rq, budget, &bq, &stats);
[...]
}

static int veth_xdp_rcv(struct veth_rq *rq, int budget,
			struct veth_xdp_tx_bq *bq,
			struct veth_stats *stats)
{
	for (i = 0; i < budget; i++) {
		void *ptr = __ptr_ring_consume(&rq->xdp_ring);

		if (veth_is_xdp_frame(ptr)) {
			/* ndo_xdp_xmit */
[...]
			frame = veth_xdp_rcv_one(rq, frame, bq, stats);
[...]
		} else {
			/* ndo_start_xmit */
			struct sk_buff *skb = ptr;
[...]
			skb = veth_xdp_rcv_skb(rq, skb, bq, stats);
            if (skb) {
				netif_receive_skb(skb);
			}
[...]
		}
		done++;
	}
[...]
}
```
`veth_xdp_rcv`함수에서 `__ptr_ring_consume`함수를 통해 `xdp_ring`에서 데이터를 소비한다. 소비된 데이터는 `veth_xdp_rcv_one`이나 `veth_xdp_rcv_skb`함수를 호출한다. 2개의 함수 모두 내부적으로 `bpf_prog_run_xdp` 함수를 호출하여 실제 `XDP 프로그램`을 실행한다. 해당 함수는 앞서 언급한 `Action`을 반환할 수 있고 `XDP_PASS`의 경우 `netif_receive_skb` 함수를 호출하여 네트워크 스택처리를 진행한다. `XDP_TX`를 반환하게 되면 아래 로직을 수행한다.
```C
/* drivers/net/veth.c */
static struct sk_buff *veth_xdp_rcv_skb(struct veth_rq *rq,
					struct sk_buff *skb,
					struct veth_xdp_tx_bq *bq,
					struct veth_stats *stats)
{
[...]
	act = bpf_prog_run_xdp(xdp_prog, xdp);
[...]
	switch (act) {
[...]
	case XDP_TX:
        veth_xdp_tx(rq, xdp, bq);
    }
}

static int veth_poll(struct napi_struct *napi, int budget)
{
[...]
	done = veth_xdp_rcv(rq, budget, &bq, &stats);
[...]
	if (stats.xdp_tx > 0)
		veth_xdp_flush(rq, &bq);
[...]
}
```
`XDP_TX`를 반환하게 되면 `veth_xdp_tx`함수를 호출하여 처리했던 패킷을 frame으로 변환하여 queue에 넣는다. 다시 `veth_poll`로 돌아와서 `stats.xdp_tx`값이 0이상이 되기 때문에 `veth_xdp_flush`함수를 호출한다. 

```C
/* drivers/net/veth.c */
static int veth_xdp_xmit(struct net_device *dev, int n,
			 struct xdp_frame **frames,
			 u32 flags, bool ndo_xmit)
{
[...]
	for (i = 0; i < n; i++) {
		struct xdp_frame *frame = frames[i];
		void *ptr = veth_xdp_to_ptr(frame);

		__ptr_ring_produce(&rq->xdp_ring, ptr);
	}
[...]
}

static void veth_xdp_flush_bq(struct veth_rq *rq, struct veth_xdp_tx_bq *bq)
{
[...]
	sent = veth_xdp_xmit(rq->dev, bq->count, bq->q, 0, false);
[...]
}

static void veth_xdp_flush(struct veth_rq *rq, struct veth_xdp_tx_bq *bq)
{
[...]
	veth_xdp_flush_bq(rq, bq);
[...]
	__veth_xdp_flush(rcv_rq);
}
```
`veth_xdp_xmit`함수는 이전에 `veth_xdp_tx`함수에서 bulk queue에 넣었던 frame을 `__ptr_ring_produce`를 통해 `xdp_ring`에 주입한다. 해당 함수 구간으로 통해 처음 말했던 `XDP_TX`가 어떻게 수신했던 `NIC`로 패킷을 되돌리는지 알 수 있다. 

여기까지가 `XDP 프로그램`를 설치하고 `XDP_PASS`, `XDP_TX`일 때의 간략한 동작 과정이다. 앞서 언급한것과 같이 커널을 우회하는 여러 기술보다 `XDP`의 경우 커널내부 소스와 통합되어있기 때문에 커널의 안정성기반으로 동작할 수 있다. 다만, 드라이버마다 `Native`모드 지원은 상이하기 때문에 지원되지 않는 드라이버는 `Generic`을 사용하게 된다.

해당 설명이 목적이 아니기에 실제 네트워크 구조의 설명은 많은 부분이 생략됐으며 그 과정에서 예상치 못한 잘못된 내용이 존재할 수 있지만 대략적인 구조로 생각했으면 한다.

### 로드밸런서
지금까지 XDP에 대해서 간략하게 알아보았다. 다음은 이 글의 목적인 XDP 로드밸런서를 구현하고 이를 테스트하는 시간을 가진다. XDP로드밸런서를 구현하기 위해서는 2가지의 방식이 존재한다. 

가장 구현난이도가 낮은 방식이나 성능적인 측면에서 다음에 나올 `DSR(Direct Server Return)` 방식보다는 좋지못하다. 
![alt text](image-3.png)

위 사진은 XDP 로드밸런서를 구현할 때 가장 베이스가 되는 모델이라고 생각한다. XDP는 NIC에서 패킷 수신 후 리눅스 네트워크 스택을 태우기전에 실행되는 구간이므로 ethernet frame과 ip, tcp header 및 option 처리가 필요하다. XDP 프로그램에서 트리거된 패킷을 살펴보면 목적지가 로드밸런서쪽으로 되어 있기 때문에 해당 값을 원하는 서버 목적지 정보 입력이 필요하다. 또한 패킷의 IP Header와 TCP Header 정보가 수정되었기 때문에 각 각 Checksum 재계산이 필요하다. 그리고 로드밸런서쪽에서 클라이언트와 서버관 커넥션을 어떻게 유지할것인가도 중요하다.

#### 코드 구조
위에서 언급한 구조를 기반으로 `Cilium eBPF`를 사용해서 코드 레벨에서의 설명을 하고자 한다. 


### 테스트 및 퍼포먼스

### 참고문헌
- https://www.cs.cornell.edu/~ragarwal/pubs/network-stack.pdf
- https://d2.naver.com/helloworld/47667
- The eXpress data path: fast programmable packet processing in the operating system kernel
- https://guanjunjian.github.io/2018/01/05/study-18-dev_forward_skb-source-analysis/
- https://blog.csdn.net/qq_45090200/article/details/147226000
- https://lpc.events/event/7/contributions/676/attachments/512/1000/paper.pdf