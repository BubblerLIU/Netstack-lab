#set document(title: "Lab 1: Link Layer")

= Lab 1: Link Layer

== WT1

The filter is `eth.src == 6a:15:0a:ba:9b:7c`.

+ There are *827* frames in the filtered results.
+ The destination MAC address of the third filtered frame is
  `ff:ff:ff:ff:ff:ff`. This is the Ethernet broadcast address, addressing
  all hosts in the same broadcast domain.
+ The byte at zero-based offset 71 is *`0x15`*.

== Code arrangement

- *PT1:* `src/device.c` implements device enumeration, registration,
  lookup, and cleanup. `src/include/device.h` declares the interfaces.
- *PT2:* `src/packetio.c` implements Ethernet II frame transmission,
  reception, and callback registration. `src/include/packetio.h`
  declares the interfaces.
- `src/apps/lab1_demo.c` provides the `list`, `send`, and `recv`
  commands used for CP1 and CP2.

== CP1

Running `lab1_demo list` produces the output below.
The program detects the host interface
`enp3s0`, loopback `lo`, and other capture devices through libpcap.

#figure(
  image("../checkpoints/list_devices.png", width: 100%),
  caption: [Network interface enumeration.],
)

#pagebreak()
== CP2

Two network namespaces, `l1ns1` and `l1ns2`, are connected by a veth
pair: `l1veth1-2` and `l1veth2-1`. The sender injects a frame in
`l1ns1`; the custom receiver and tcpdump capture it in `l1ns2`.
The commands and their output are shown below.

#figure(
  image("../checkpoints/terminal-C-sender.png", width: 100%),
  caption: [Sending a frame with the custom program.],
)

#figure(
  image("../checkpoints/terminal-A-receiver.png", width: 100%),
  caption: [The custom receiver captures and prints the frame.],
)

#figure(
  image("../checkpoints/terminal-B-monitor.png", width: 100%),
  caption: [tcpdump independently captures the same frame.],
)

Both captures show a 60-byte frame with destination
`ff:ff:ff:ff:ff:ff`, source `16:05:27:4c:93:c9`, EtherType `0x88b5`,
and payload `hello from lab1`. The 14-byte Ethernet header and
14-byte payload are followed by 32 zero-padding bytes.
