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
		uid:       		string &log;
		# the domain being queried in string format
	        query:       		string &log;
		# the query type in decimal form
		qtype: 			count &log;
		# the query type's name (not decimal value) e.g. A, AAAA, NS, SOA, TXT, etc.
		qtype_name:		string &log;
		# the length of the query e.g. bro.org = 7
		qlen:			count &log;
		# the number of hieracrchical levels in a domain name
		levels: 		count &log;
		# the top level domain of the query
		tld:			string &log;
		# the unique character set of the domain (1-grams)
		domain_qchar_c:		count &log;
		# the domain of the query. this is optional as query of '.com' is possible
		domain:			string &log &optional;
		# the number of unique n-grams in the domain being queried
		domain_grams_c:		count &log;
		# the set of n-grams in the domain name being queried
		domain_grams:			set[string] &log;
		# the entropy of the domain
		domain_entropy:		double &log;
	};
	
	# logging event for the nxes module
	global log_nxes: event(rec: Info);

	# this variable is used to define the lengths of n-gram held in the grams string set in Nxes::Info types
	global gram_size: count = 3 &redef;

	# string metric threshold for determining misspelled domains
	global misspelling_threshold: count = 3 &redef;
}

# breaks a domain into a table of count of strings.
# the tld of a domain has the highest index
function tldr(s: string): table[count] of string
{
        if ( (/\./ !in s) || (s in suffixes) )
        {
                local vs: table[count] of string;
                 vs[0] = s;
                return vs;
        }

        local iter = split(s, /\./);
        local levels: count = |iter|;
        local tld: string = s;

        for ( i in iter )
        {
                if ( (tld in suffixes) || (levels == 1) )
                {
                        break;
                }
                --levels;

                tld = split1(tld, /\./)[2];
        }

        local subdomains: string = sub_bytes( s, 0, (|s| - |tld|) );
        local tmp: table[count]of string = split(subdomains, /\./);
        tmp[|tmp|] = tld;

        return tmp;
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
		local tld: table[count] of string = tldr(c$dns$query);
		
		# check to see if the TLD of the domain is interesting or not
		if (tld[|tld|-1] !in tld_blacklist)
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
				local domain: string = tld[ |tld| - 2 ];
				local domain_uniq_chars: set[string] = gramer(domain, 1);
				local domain_grams: set[string] = gramer(domain, gram_size);
				local domain_entropy: entropy_test_result = find_entropy(domain);
	
				Log::write(Nxes::LOG, [$uid = c$uid,
						       $query = c$dns$query,
						       $qtype = c$dns$qtype,
						       $qtype_name = c$dns$qtype_name,
						       $qlen = |c$dns$query|,
						       $levels = |tld|,
						       $tld = tld[|tld| - 1],
						       $domain = domain,
						       $domain_qchar_c = |domain|,
						       $domain_grams_c = |domain_grams|,
						       $domain_grams = domain_grams,
						       $domain_entropy =  domain_entropy$entropy]
				);
			}
		}
	}
}
