Flamingo - Peer-to-Peer VPN
---------------------------

**Flamingo** is a high performance peer-to-peer mesh VPN over UDP supporting strong encryption, NAT traversal and a simple configuration. It establishes a fully-meshed self-healing VPN network in a peer-to-peer manner with strong end-to-end encryption based on elliptic curve keys and AES-256. Flamingo creates a virtual network interface on the host and forwards all received data via UDP to the destination. It can work on TUN devices (IP based) and TAP devices (Ethernet based).

```sh
$> flamingo -c REMOTE_HOST:PORT -p 'mypassword' --ip 10.0.0.1/24
```

or as config file:

```yaml
crypto:
  password: mysecret
ip: 10.0.0.1
peers:
  - REMOTE_HOST:PORT
```

### Project Status
This project is still [under development](CHANGELOG.md) but has reached a
somewhat stable state. Flamingo features the following functionality:

* Automatic peer-to-peer meshing, no central servers
* Automatic reconnecting when connections are lost
* Connecting hundreds of nodes with the VPN
* High throughput and low additional latency
* Creating virtual network interfaces based on Ethernet (TAP) and IP (TUN)
* Strong end-to-end encryption using Curve25519 key pairs and AES methods
* Support for different forwarding/routing behaviors (Hub, Switch, Router)
* NAT and firewall traversal using hole punching
* Automatic port forwarding via UPnP
* Websocket proxy mode for restrictive environments
* Support for tunneled VLans (TAP devices)
* Support for statsd monitoring
* Low memory footprint
* Single binary, no dependencies, no kernel module

### Installing

#### Compiling from source
Prerequisites: Git, [Cargo](https://www.rust-lang.org/install.html), asciidoctor

The checked-out code can be compiled with ``cargo build`` or ``cargo build --release`` (release version). The binary could then be found in `target/release/flamingo`.

The tests can be run via ``cargo test``.


#### Cross-Compiling & packaging
Please see the [builder folder](builder).