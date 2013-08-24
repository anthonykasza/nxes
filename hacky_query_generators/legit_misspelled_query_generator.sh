DOMAIN_LIST="googel.com faecbok.com yahop.com linkein.con liv3.c0m WHATEVER.blhgspor.com twhter.com amzo.com foo.yaho.com bong.com eplay.com faceboo.og google.co.uk 123.gogle.com eay.in pedia.com at.om fonews.cobm media.tunblr.cm drobox.cm yah3oo.com mesiafire.com mozerlla.org etcsy.com 4sharbe.com googlde.com fafcebook.om media.tumlfr.om bankofadmerica.om giub.io karadrfapala.com fo2ce.com stackoveflow.com alex.hrc.1net";

for DOMAIN in ${DOMAIN_LIST}
do
        dig @8.8.8.8 ${DOMAIN};
        sleep $(( ${RANDOM} %  25 ));
done
