#!/bin/sh
# script to pull alexa top 1 million websites and build a Bro style table

ECHO_CMD="/bin/echo";
WGET_CMD="/usr/bin/wget";
AWK_CMD="/usr/bin/awk";
SED_CMD="/bin/sed";
HEAD_CMD="/usr/bin/head";
GUNZIP_CMD="/bin/gunzip";

TOPX=10000;
URL="http://s3.amazonaws.com/alexa-static/top-1m.csv.zip";

quote_me()
{
        while read LINE
        do ${ECHO_CMD} -e "\t\"${LINE}\",";
        done
}

${ECHO_CMD} "global alexa_top_x: set[string] = {" > alexa_top_x.bro;
${WGET_CMD} -q ${URL} -O - | ${GUNZIP_CMD} -c | ${HEAD_CMD} -${TOPX} | ${SED_CMD} '/^$/d' | ${SED_CMD} 's/ //g' | ${AWK_CMD} -F',' '{print $2}' | quote_me >> alexa_top_x.bro;
${ECHO_CMD} "};" >> alexa_top_x.bro;

