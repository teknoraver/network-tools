# network-tools
tools to measure network throughput and latency

## xdperf
xdperf is a tiny, fast, traffic generator for Linux. It uses AF\_XDP to achieve maximum performances.  
Only simple traffic patterns are supported, UDP, ICMP ping or raw ethernet frames.

## bptraf
bptraf shows per protocol counters about received packet. It uses XDP to count the packet, so it's faster than AF\_PACKET based implementations.  
Optonally, it can drop all the received traffic instead of passing it to the networking stack.

## weed
weed is an end-to-end delay calculator. It sends packets to an interface, and measures how much time elapses until the packet can be received on another interface

## shtraf
shtraf is a shell script which shows tx and rx throughput and packets per seconds which are flowing through an interface

## utraf
like shtraf, but written in C and more precise ;)
