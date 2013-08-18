#!/bin/bash
# script to pull public suffix list and build a Bro style table

ECHO_CMD="/bin/echo";
WGET_CMD="/usr/bin/wget";
GREP_CMD="/bin/grep";
SED_CMD="/bin/sed";

URL="http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1";

quote_me()
{
	while read LINE
	do ${ECHO_CMD} -e "\t\"${LINE}\",";
	done
}

${ECHO_CMD} "global suffixes: set[string] = {" > public_suffix.bro;
${WGET_CMD} -q ${URL} -O - | ${GREP_CMD} -v '//' | ${SED_CMD} 's/ //g' | ${SED_CMD} '/^$/d' | ${SED_CMD} 's/!//g' | ${SED_CMD} 's/\*\.//g' | quote_me >> public_suffix.bro;
${ECHO_CMD} "};" >> public_suffix.bro;
