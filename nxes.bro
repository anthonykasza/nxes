# This module takes a closer look at NXDomain responses

# be sure to run publix_suffix_puller.sh and alexa_top_x.sh before running this script so that the files being loaded below exist
@load public_suffix
@load alexa_top_x
@load tld_blacklist

module Nxes;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
        	# the epoch from the original DNS query
		ts: 			time &log;
	        # the Bro unique connection ID string
		uid:       		string &log;
		# the domain being queried
	        query:       		string &log;
		# the query type in decimal form
		qtype: 			count &log;
		# the query type's name (not decimal value) e.g. A, AAAA, NS, SOA, TXT, etc.
		qtype_name:		string &log;
		# the length of the query e.g. bro.org = 7
		qlen:			count &log;
		# the top level domain of the query
		tld:			string &log;
		# the length of the tld
		tld_len:		count &log;
		# the subdomains of the query. the fqdn type specifies a table[count] of strings for this value but Bro cannot log that data type.
		subs: 			set[string] &log &optional;
		# the number of subdomains
		subs_c:			count &log &optional;
		# the length of all the subdomains
		subs_len:		count &log &optional;
		# the domain of the query. this is optional as query of '.com' is possible
		domain:			string &log &optional;
		# the length of the domain
		domain_len: 		count &log &optional;
		# the unique characters in a the domain
		domain_uchars:		set[string] &log &optional;
		# the number of unique characters in the domain
		domain_uchars_c:	count &log &optional;
		# the number of unique n-grams in the domain being queried
		domain_grams_c:		count &log &optional;
		# the set of n-grams in the domain name being queried
		domain_grams:		set[string] &log &optional;
		# the entropy of the domain
		domain_entropy:		double &log &optional;
	};
	
	# logging event for the nxes module
	global log_nxes: event(rec: Info);

	# this variable is used to define the lengths of n-gram held in the grams string set in Nxes::Info types
	global gram_size: count = 3 &redef;

	# string metric threshold for determining misspelled domains
	global misspelling_threshold: count = 3 &redef;

	# fully qualified domain name type
	type fqdn: record {
		# subdomains following a domain, indexed by their left to right order
	        subs: table[count] of string &optional;
		# the domain immediately below the tld
		domain: string &optional;
		# the top level domain according to the suffixes table
	        tld: string;
	};
}

# breaks a domain into a fqdn record
function tldr(s: string): fqdn
{
        local vs: fqdn;

        if ( (/\./ !in s) || (s in suffixes) )
        {
                vs$tld = s;
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

	# drop the tld and the period between the tld and the domain from the query string
        local subs_domain: string = sub( sub_bytes( s, 0, (|s| - |tld|)) , /\.$/, "");
	# split the string by periods
        local tmp: table[count] of string = split(subs_domain, /\./);

        vs$tld = tld;
	# the domain has the highest key value
        vs$domain = tmp[ |tmp| ];
	# delete the domain from the table, all that remains are subdomains
        delete tmp[ |tmp| ];
        vs$subs = tmp;

        return vs;
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
		local tmp_fqdn: fqdn = tldr(c$dns$query);

		# check to see if the TLD of the domain is interesting or not
		if (tmp_fqdn$tld !in tld_blacklist)
		{
			local is_this_a_typo: bool = F;
		
			# is the query a typo of a legitimate popular domain?
			for (d in alexa_top_x)
			{
		                # levenshtein_distance will be called once for each string in alex_top_x
	        	       	# this function has potential to make this module run slow (so don't make alexa_top_x too big)
	                	# can we, the royal I, optimize these lookups with bloom filters?
	
				# check that the levenshtein_distance is within an acceptable threshold
				local n: count = levenshtein_distance(string_cat(tmp_fqdn$domain, ".", tmp_fqdn$tld), d);
				if (n <= misspelling_threshold)
				{
					is_this_a_typo = T;
					break;
				}
			}
	
			# if the query wasn't a typo, build an Nxes::Info records and log stuff
			if (!is_this_a_typo)
			{
				# why can't I log table[count] of string types? i demand satisfaction.
				if (tmp_fqdn?$subs)
				{
					local tmp_subs: set[string];
					for (each in tmp_fqdn$subs)
					{
						add tmp_subs[ tmp_fqdn$subs[each] ];
					}
				}
				local domain_uniq_chars: set[string] = gramer(tmp_fqdn$domain, 1);
				local domain_grams: set[string] = gramer(tmp_fqdn$domain, gram_size);
				local domain_entropy: entropy_test_result = find_entropy(tmp_fqdn$domain);
				Log::write(Nxes::LOG, [$ts = c$dns$ts,
						       $uid = c$uid,
						       $query = c$dns$query,
						       $qtype = c$dns$qtype,
						       $qtype_name = c$dns$qtype_name,
						       $qlen = |c$dns$query|,
						       $tld = tmp_fqdn$tld,
						       $tld_len = |tmp_fqdn$tld|,
						       $subs = tmp_subs,
						       $subs_c = |tmp_fqdn$subs|,
						       $subs_len = |tmp_fqdn$subs|,
						       $domain = tmp_fqdn$domain,
						       $domain_len = |tmp_fqdn$domain|,
						       $domain_uchars = domain_uniq_chars,
						       $domain_uchars_c = |domain_uniq_chars|,
						       $domain_grams = domain_grams,
						       $domain_grams_c = |domain_grams|,
						       $domain_entropy =  domain_entropy$entropy]
				);
			}
		}
	}
}
