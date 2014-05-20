# This module takes a closer look at NXDomain responses

# be sure to run publix_suffix_puller.sh and alexa_top_x.sh before running this script so that the files being loaded below exist
@load public_suffix
@load alexa_top_x
@load tld_blacklist

module Nxes;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		#the query
		query:			string &log;
		# the query type in decimal form
		qtype: 			count &log;
		# the length of the query e.g. bro.org = 7
		qlen:			count &log;
		# the length of the tld
		tld_len:		count &log;
		# the number of subdomains
		subs_c:			count &log &optional;
		# the length of all the subdomains
		subs_len:		count &log &optional;
		# the length of the domain
		domain_len: 		count &log &optional;
		# the number of unique characters in the domain
		domain_uchars_c:	count &log &optional;
		# the number of unique n-grams in the domain being queried
		domain_grams_c:		count &log &optional;
		# the entropy of the domain
		domain_entropy:		double &log &optional;
	};
	
	# logging event for the nxes module
	global log_nxes: event(rec: Info);

	# this variable is used to define the lengths of n-gram held in the grams string set in Nxes::Info types
	global gram_size: count = 3 &redef;

	# string metric threshold for determining misspelled domains
	global misspelling_threshold: count = 3 &redef;

	# hook for Info creation
	global build_nxes: hook(c: connection, msg: dns_msg);

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

## Returns a set of n-grams (contiguous sequences of n letters) for a string.
##
## s: A string to sequence in to n-grams.
##
## n: The desired n-gram size.
##
## i: The starting index of *s* at which to begin sequencing.
##
## ss: A pre-existing set to aggregate n-grams in to.
##
## Returns: A set of n-grams of size *n* corresponding to *s*.
function str_grammer(s: string, n: count, i: count &default=0, ss: string_set &default=string_set()): string_set
{
	if ( n + i > |s| )
		return ss;

	add ss[s[i:i+n-1]];
	return str_grammer(s, n, ++i, ss);
}

function tldr(s: string): string
{
        if ( (/\./ !in s) || (s in suffixes) )
                return s;

        return tldr( split1(s, /\./)[2] );
}

function qualify_me(s: string): fqdn
{
        local return_me: fqdn;
        local tld: string = tldr(s);
        local subs_domain: string = sub( sub_bytes( s, 0, (|s| - |tld|)) , /\.$/, "");
        local tmp: table[count] of string = split(subs_domain, /\./);

        return_me$tld = tld;
        return_me$domain = tmp[ |tmp| ];
        delete tmp[ |tmp| ];
        return_me$subs = tmp;
        return return_me;
}

hook build_nxes(c: connection, msg: dns_msg) &priority=10
{
	if (! c?$dns) break;
	if (! c$dns?$query) break;
	if (msg$rcode != 3) break;
	
	local tmp_fqdn: fqdn = qualify_me(c$dns$query);

	if (tmp_fqdn$tld in tld_blacklist)
		break;

	local is_a_typo: bool = F;

	# this should eventually take advantage of bloomfilters
	for (d in alexa_top_x)
	{
		local n: count = levenshtein_distance( string_cat(tmp_fqdn$domain, ".", tmp_fqdn$tld), d );
		if (n <= misspelling_threshold)
		{
			is_a_typo = T;
			break;
		}
	}

	if (is_a_typo)
		break;

	# this is a hack to turn a table's values into a set
	# would be nice to have a function [table|vector]_to_set( [values|keys] );
	if (tmp_fqdn?$subs)
        {
                local tmp_subs: set[string];
                for (each in tmp_fqdn$subs)
                {
                	add tmp_subs[ tmp_fqdn$subs[each] ];
        	}
	}

	local domain_uniq_chars: set[string] = str_grammer(tmp_fqdn$domain, 1);
	local domain_grams: set[string] = str_grammer(tmp_fqdn$domain, gram_size);

	Log::write(Nxes::LOG, 
	[
		$query = c$dns$query,
                $qtype = c$dns$qtype,
                $qlen = |c$dns$query|,
                $tld_len = |tmp_fqdn$tld|,
		$subs_c = |tmp_fqdn$subs|,
                $subs_len = |tmp_fqdn$subs|,
                $domain_len = |tmp_fqdn$domain|,
                $domain_uchars_c = |domain_uniq_chars|,
                $domain_grams_c = |domain_grams|,
                $domain_entropy =  find_entropy(tmp_fqdn$domain)$entropy
	]);
}

event bro_init()
{
	Log::create_stream(Nxes::LOG, [$columns=Info, $ev=log_nxes]);
}

# check to see if a query is interesting enough to log
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) 
{
	# use this hook for metrics on number of NXDomains?
	#if ( hook build_nxes(c, msg) )
	#{
	#	print "interesting NXDomain logged";
	#}
	hook build_nxes(c, msg);
}
