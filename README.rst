pcap-toolset
============

Swiss army knife for useful scripts dealing with RAN and Core
Network problems. These scripts were created to identify packet
issues on GPRS-NS and then more scripts were added to it.

The most useful might be the flatten_sctp.py that will split
an ethernet frame with multiple SCTP data chunks into having
one chunk per ethernet frame. This will make it more easy to
filter for a specific IMSI/GT.

INSTALL
=======

The scripts require python2.7 and the wonderful scapy library.
It can be easily installed with:

.. code-block:: bash

    pip install -r requirements.txt


flatten_sctp.py
===============

Filtering in wireshark for a MSISDN/GT/IMSI but spending too
much time in expanding all to actually find the TCAP/MAP section
you actually want to see? This script allows you to split separate
SCTP data chunks into single SCTP packages. This way your wireshark
filter will only show a single message. The script doesn't create
SACKs and as such wireshark will report packet loss, don't be mislead
by that.

.. code-block:: bash

    python flatten_sctp.py input.pcap output.pcap


License
=======

Based on pcap-diff of ISGINF, Bastian Ballmann

Copyright 2013 ETH Zurich, ISGINF, Bastian Ballmann
E-Mail: bastian.ballmann@inf.ethz.ch
Web: http://www.isg.inf.ethz.ch

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

It is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License.
If not, see <http://www.gnu.org/licenses/>.
