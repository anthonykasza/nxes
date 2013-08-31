Nxes
====

This is a Bro module that logs statistics about dns queries which result in NXDomain responses. 
For information on why these network events would be interesting, see ['How & Why DGA's Evade Your Corporate Security Controls' by Stephen Newman of Damballa](http://www.prodevmedia.com/FSISAC/2012/fall/21_StephenNewman_Stopping_the_New_Wave.pdf).

Currently, statistics about queried domains include 
- the unique connection ID that resulted in an NXDomain response
- the domain queried
- the length of the query string
- the number of unique characters in the query string
- the top level domain of the domain queried for
- the subdomains of the query
- ngram analysis of domain (user defined size of gram)
- randomness of domain being queried
- some other stuff

Components
----------
* public_suffix_puller.sh is shell script that builds the public_suffix.bro file. 
The public_suffix.bro file is a data file with a set of strings containing all TLDs. It is imported by nxes.bro during execution and is used to identify top level domains within queries.
* The alexa_top_x_puller.sh is a shell script that builds the alexa_top_x.bro file.
The alexa_top_x.bro file is a data file with a set of strings containing popular domains. It is imported by nxes.bro during initialization and is used to determine if queried domains are misspellings/typo of popular domains.
* The tld_blacklist.bro file is a data file with a set of strings containing top level domains the Nxes module should not analyze.

Example Usage
-------------

	chmod +x ./public_suffix_puller.sh
	./public_suffix_puller.sh
	chmod +x ./alexa_top_x_puller.sh
	./alexa_top_xpuller.sh
	bro -i eth0 nxes.bro
	dig @8.8.8.8 garbage.asdasdasd

or try running Bro against the provided sample pcap with
	bro -C -r hacky_query_generators/dns_queries.pcap



Using this module, I recently found that the [Chrome browser](http://code.google.com/p/chromium/issues/detail?id=47262&can=1&q=random%20host%20names&colspec=ID%20Stars%20Pri%20Area%20Feature%20Type%20Status%20Summary%20Modified%20Owner%20Mstone%20OS) tries to determine if your DNS provider lies about NXDomains by generating random requests (this is done either when Chrome starts or when you DHCP request).
