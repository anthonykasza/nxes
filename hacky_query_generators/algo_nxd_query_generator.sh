# hacky? OH YEAH!

for EACH in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
do
        DOMAIN="";
        EPOCH=$(date +%s);

        for EACH_D in 1 2 3 4 5 6 7 8 9 10 11 12
        do
                VAL=$(( EPOCH % ${EACH_D} ));

                if [ ${VAL} -eq 0 ]; then
                        DOMAIN=${DOMAIN}"a";
                elif [ ${VAL} -eq 1 ]; then
                        DOMAIN=${DOMAIN}"b";
                elif [ ${VAL} -eq 2 ]; then
                        DOMAIN=${DOMAIN}"c";
                elif [ ${VAL} -eq 3 ]; then
                        DOMAIN=${DOMAIN}"d";
                elif [ ${VAL} -eq 4 ]; then
                        DOMAIN=${DOMAIN}"e";
                elif [ ${VAL} -eq 5 ]; then
                        DOMAIN=${DOMAIN}"f";
                elif [ ${VAL} -eq 6 ]; then
                        DOMAIN=${DOMAIN}"g";
                else
                        DOMAIN=${DOMAIN}"h";
                fi
        done

        DOMAIN=${DOMAIN}".asdasd";

        dig @8.8.8.8 ${DOMAIN};
        sleep $(( ${RANDOM} % 25 ));
done
