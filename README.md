tcp_flow_spy
============
    Version: 0.2
    Author: Soheil Hassas Yeganeh <soheil@cs.toronto.edu>
                based on tcp_probe by Stephen Hemminger <shemminger@osdl.org>

Introduction
------------
This is a kernel module similar to tcp_probe which collects flow level
statistics.

Installation
------------
```
    # make all
    # make install
```

Papers
------
This kernel module is the major functionality used in OpenTCP:

[Monia Ghobadi, Soheil Hassas Yeganeh, Yashar Ganjali, "Rethinking End-to-end Congestion Control in Software-defined Networks"](http://dl.acm.org/citation.cfm?id=2390242)

