DOMAIN_LIST="asdasd.asdasd asdasdert.asdasd asdasdqwe.asdasd asdasdfgh.rtyuryu oiuiu.oijoiji.uhsrgtwrg ouwhofjhwsf.kncs.poaef 3t3f.wef24r.2f2f.wdfwdfkjn aifjadfij.wgo.sdfsgojn oijafcjqwec.wfoinalskcm.odkmfadf 091208hg3g.2fojnrf.2ofi9j2ijf 0jiwfdijwf.wfwoijnti2.wrgojnfg w8j9wf.wfwgeheh wtwg.wgdgomn.eroij.woij.wocj90wjc oskfmgdf.tyjtyj.werqrqer.erdf.oujsac089jwef kjadsnc034t.werwef.wefdcwdf.32fd2fwdv werfq5346.oimpok oijdf0j.wd0ocimwed.weti0m 9eirj23lkrmnq.wioemdoqiejr.oijdfwdf -09kq2er.20mwodkmf oimwef09.wfe094ktp eq9jnmwer.98ndf098jw.woijf-wdfko sdf98jnwef.2fwdfokmsvc.sodfmnwoir";

for DOMAIN in ${DOMAIN_LIST}
do
        dig @8.8.8.8 ${DOMAIN};
        sleep $(( ${RANDOM} % 25 ));
done
