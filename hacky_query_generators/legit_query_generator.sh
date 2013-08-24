DOMAIN_LIST="google.com facebook.com yahoo.com linkedin.com live.com WHATEVER.blogspot.com twitter.com amazon.com foo.123.yahoo.com bing.com ebay.com facebook.org google.co.uk 123.google.com ebay.in expedia.com att.com foxnews.com media.tumblr.com dropbox.com yahoo.com mediafire.com mozilla.org etsy.com 4shared.com google.com facebook.com media.tumblr.com bankofamerica.com github.io karadrapala.com force.com stackoverflow.com alex.hrck.net";

for DOMAIN in ${DOMAIN_LIST}
do
        dig @8.8.8.8 ${DOMAIN};
        sleep $(( ${RANDOM} % 25 ));
done
