# writeup for "Somethings Off" task in SpaceHeroes CTF

### description:

>While tracking for the rebel alliance an imperial fleet noticed that they would periodically come across the following network traffic. 
>They think it may have something to do with the rebel alliance, what do you think?
>
>Flag format: every word seperated with _ ex: shctf{abc_def_ghi}

### hint:

>I have a bad feeling about this Commander, something is off about this conversation. I think it may lead us straight to the rebels! I wonder where those rebel scum are >hiding now?


So, basically, we have to find where those rebels are hiding.

We are given with `Challenge.pcap` dump presumably with some conversation hidden there. Let's examine it with wireshark:

![image](https://user-images.githubusercontent.com/102946319/161515949-75fc655f-6f15-47d7-b7b8-90f9ee679b20.png)

Upon closer inspection we can notice that `code` field of first fiew icmp packets always stays as readable ASCII character.
Writing them one by one will give something like that: 

> [49:52]BRAVE? y

Feels like we are on right tracks, let's filter icmp packets with source ip `10.11.10.12`. To make it easear, we'll write small python script with pyshark:

```python
import pyshark

with pyshark.FileCapture('Challenge.pcap', display_filter="icmp && ip.addr == 10.11.10.12") as cap:
		array = bytearray()
		for c in cap:
			array.append(int(c.icmp.code))
		print(bytes(array))
```

>\>python solve.py
>
>b'[49:52]BRAVE? you have to be kidding no matter how many bases they make, they will always be scum[anonE1]'

Seems like we found one line of conversation. Other lines can be found in different packets. For example `Sequence number` of `tcp` packets
from and for ip `18.44.117.9` works the same way.

this is my code to find full conversation:

```python
import pyshark

def icmp_code(p):
	return int(p.icmp.code)

def tcp_sequence_num(p):
	return int(p.tcp.seq_raw)

def icmp_sequence_num(p):
	return int(p.icmp.seq)

def udp_dest_port(p):
	return int(p.udp.dstport)

def udp_src_port(p):
	return int(p.udp.srcport)

def capture(filter, data_func, reverse=False):
	with pyshark.FileCapture('Challenge.pcap', display_filter=filter) as cap:
		array = bytearray()
		for c in cap:
			array.append(data_func(c))
		return (bytes(array) if not reverse else bytes(array[::-1])).decode()

print(capture("tcp && ip.addr == 18.44.117.9", tcp_sequence_num))
print(capture("tcp && ip.src == 107.45.121.24", tcp_sequence_num))
print(capture("icmp && ip.addr == 10.11.10.12", icmp_code))
print(capture("udp && ip.addr == 10.13.103.14", udp_dest_port))
print(capture("icmp && ip.addr == 18.15.102.18", icmp_sequence_num, True))
```

>\>python solve.py
>
>[00:02]News lately suggest the rebels have made a new base[anonR1]
>
>[03:04]I dont support the rebels, but they sure are brave to keep on going[anonB1]
>
>[49:52]BRAVE? you have to be kidding no matter how many bases they make, they will always be scum[anonE1]
>
>[35:38]Hey man, theres no reason to be so hotheaded relax[anonL1]
>
>[34:39]What? I doubt that, there is'nt a planet left they could hide in[anonE2]


*Hint* given to us suggests that flag is hidden inside this conversation. If we take a look at the each speakers nikname we will find cappital letters 
`R B E L E` which is anagramm to `REBEL` hence we have an order of the sentences. 

Two numbers in a brackets at the start of each sentence, on the other hand, looks wery simular to python's lists slices. So if we run the following:

```python
print("News lately suggest the rebels have made a new base[anonR1]"[0:2+1])
print("BRAVE? you have to be kidding no matter how many bases they make, they will always be scum[anonE1]"[49:52+1])
print("I dont support the rebels, but they sure are brave to keep on going[anonB1]"[3:4+1])
print("What? I doubt that, there is'nt a planet left they could hide in[anonE2]"[34:39+1])
print("Hey man, theres no reason to be so hotheaded relax[anonL1]"[35:38+1])
```
we will get:

>New
>
>base
>
>on
>
>planet
>
>hoth

looks like exact thing we are looking for. Replacing spaces with `_` and wraping all in `shctf{}` as stated in task description, we will get the flag:

**shctf{New_base_on_planet_hoth}**
