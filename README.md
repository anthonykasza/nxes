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
- ngram analysis of domain (user defined size of gram)
- randomness of domain being queried

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
	%BRO_PREFIX%/bro -r hacky_query_generators/dns_queries.pcap
