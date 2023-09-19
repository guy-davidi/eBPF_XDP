#  eBPF SYN Packet Limiter

This eBPF program limits the number of incoming SYN packets from the same client IP address.

## Usage

1. Clone the repository:

```
   git clone https://github.com/your-username/ebpf-syn-limiter.git
```
1. Compile the eBPF program:

```
clang -O2 -target bpf -c syn_limiter.c -o syn_limiter.o
```
2. Load the eBPF program into the kernel for a network interface (replace `eth0` with your interface name):

```
ip link set dev eth0 xdp obj syn_limiter.o
```
Limitations
- This program is set to allow a maximum of 10 SYN packets per client IP address.
- You can adjust this limit by modifying the MAX_SYN_PER_CLIENT constant in syn_limiter.c.
- Make sure you have the necessary permissions to load XDP programs.

## License
This project is licensed under the MIT License. 
