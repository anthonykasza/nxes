# This module takes a closer look at NXDomain responses

# be sure to run publix_suffix_puller.sh and alexa_top_x.sh before running this script so that the files being loaded below exist
@load public_suffix
@load alexa_top_x
@load tld_blacklist

# ignore all checksum (makes for nicer VM testing)
redef ignore_checksums = T;

module Nxes;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
                # the Bro unique connection ID string
		# this string can be used to find more info in the conn.log and dns.log files
		uid:       	string &log;
		# the domain being queried in string format
	        query:       	string &log;
		# the query type in decimal form
		qtype: 		count &log;
		# the query type's name (not decimal value) e.g. A, AAAA, NS, SOA, TXT, etc.
		qtype_name:	string &log;
		# the length of the query e.g. bro.org = 7
		qlen:		count &log;
		# the unique character count e.g. bro.org = 5
		# this can also be considered the queried domain's unigram or 1-gram
		qchar_c:	count &log;
		# the number of hieracrchical levels in a domain name (measured by counting periods)
		levels: 	count &log;
		# the top level domain of the query
		tld:		string &log;
		# the number of unique n-grams in the domain being queried
		grams_c:	count &log;
		# the set of n-grams in the domain name being queried
		grams:		set[string] &log;
		# the following values (entropy, chi_square, mean, monte_carlo_pi, and serial_correlation) measure how random a string seems to be
		# the measurements are calculated with the bif find_entropy - more info can be found here http://www.fourmilab.ch/random/
		entropy:	double &log;
		chi_square:	double &log;
		mean: 		double &log;
		monte_carlo_pi:	double &log;
		serial_correlation:	double &log;
	};
	
	# logging event for the nxes module
	global log_nxes: event(rec: Info);

	# this variable is used to define the lengths of n-gram held in the grams string set in Nxes::Info types
	global gram_size: count = 3 &redef;

	# string metric threshold for determining misspelled domains
	global misspelling_threshold: count = 3 &redef;
}

# determine the top level domain of a domain name according to the public suffix list
function tldr(s: string): string
{
	if ( (/\./ !in s) || (s in suffixes) )
	{
		return s;
	}

	local iter = split(s, /\./);
	local levels: count = |iter|;
	local tld: string = s;

	for ( i in iter )
	{
		if ( (tld in suffixes) || (levels == 1) )
		{
			return tld;
		}	
		--levels;
		
		tld = split1(tld, /\./)[2];
	}
}

# return a set of unique gsize chunks of s 
# can this be rewritten in C++ core?
function gramer(s: string, gsize: count): set[string]
{
        local index: count = 0;
        local ssize: count = |s|;
        local grams: set[string];
        
        for (i in s)
        {
                if (index + gsize <= ssize)
                {
                        local gram_split: string_vec = str_split( s, vector(index, index + gsize) );
                        if (index == 0)
                        {
                                add grams[ gram_split[1] ];
                        } else
                        {
                                add grams[ gram_split[2] ];
                        }
                }
                ++index;
        }
        return grams;
}

event bro_init()
{
	Log::create_stream(Nxes::LOG, [$columns=Info, $ev=log_nxes]);
}

# check to see if a query is interesting enough to log
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) 
{
	# cehck to see if the connection contain a DNS query that resulted in an NXDomain response
	if ( (c?$dns) && (c$dns?$query) && (msg$rcode == 3) ) 
	{
		local tld: string = tldr(c$dns$query);
		
		# check to see if the TLD of the domain is interesting or not
		if (tld !in tld_blacklist)
		{
			local is_this_a_typo: bool = F;
		
			# is the query a typo of a legitimate popular domain?
			for (d in alexa_top_x)
			{
		                # levenshtein_distance will be called once for each string in alex_top_x
	        	       	# this function has potential to make this module run slow (so don't make alexa_top_x too big)
	                	# can we, the royal I, optimize these lookups with bloom filters?
	
				# check that the levenshtein_distance is within an acceptable threshold
				local n: count = levenshtein_distance(c$dns$query, d);
				if (n <= misspelling_threshold)
				{
					is_this_a_typo = T;
					break;
				}
			}
	
			# if the query wasn't a typo, build an Nxes::Info records and log stuff
			if (!is_this_a_typo)
			{
				local uniq_chars: set[string] = gramer(c$dns$query, 1);
				local grams: set[string] = gramer(c$dns$query, gram_size);
				local e: entropy_test_result = find_entropy(c$dns$query);
	
				Log::write(Nxes::LOG, [$uid = c$uid,
						       $query = c$dns$query,
						       $qtype = c$dns$qtype,
						       $qtype_name = c$dns$qtype_name,
						       $qlen = |c$dns$query|,
						       $qchar_c = |uniq_chars|,
						       $levels = |split(c$dns$query, /\./)|,
						       $tld = tld,
						       $grams_c = |grams|,
						       $grams = grams,
						       $entropy =  e$entropy,
						       $chi_square = e$chi_square,
						       $mean = e$mean,
						       $monte_carlo_pi = e$monte_carlo_pi,
						       $serial_correlation = e$serial_correlation]
				);
			}
		}
	}
}
