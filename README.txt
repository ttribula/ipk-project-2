Aplikace ipk-sniffer slouží jako sniffer paketů, pro odchycení a filtrování paketů na daném rozhraní. Sniffer filtruje a vypisuje pakety protokolu TCP, UDP, ICMP a IGMP z rodiny TCP/IP na standardní výstup.

Kompilace:
	make

Spuštění:
	./ipk-sniffer -i rozhrani [-p port] [--tcp|-t] [--udp|-u] [--icmp] [--igmp] [--icmp-only] [--igmp-only] [-n num] [--help]
	kde:
		-i 	    - rozhraní, na kterém se odchytávají pakety
		-p 	    - port, na kterém se odchytávají pakety
		-t/--tcp    - filtrace TCP paketů
		-u/--udp    - filtrace UDP paketů
		--icmp	    - filtrace ICMP paketů
		--icmp-only - filtrace pouze ICMP paketů
		--igmp	    - filtrace IGMP paketů		
		--igmp-only - filtrace pouze IGMP paketů
		--help      - vypis napovedy

