library(fpc)
library(cluster)
setwd("..")

# read in data and properly label
col_classes=c("double", "character", "character", "integer", "character", "integer", "character", "integer", "character", "integer", "integer", "character", "integer", "character", "integer", "integer", "character")
col_names=c("ts", "uid", "query", "qytype", "qtype_name", "qlen", "tld", "tld_len", "subs", "subs_c", "sub_len", "domain", "domain_len", "domain_uchars", "domain_uchars_c", "domain_grams_c", "domain_grams", "domain_entropy")
nxes<-read.table("nxes.log", sep="\t", col.names=col_names, na.strings="-", colClasses=col_classes, comment.char="#")

# create scaled data frame of measurable data
nx_dat<-scale(data.frame(nxes$qlen, nxes$tld_len, nxes$subs_c, nxes$sub_len, nxes$domain_len, nxes$domain_uchars_c, nxes$domain_grams_c, nxes$domain_entropy))

# identify variables that are highly coordinated
pairs(nx_dat)

# principal component analysis
nx_pca<-princomp(nx_dat, scores=T, cor=T)
plot(nx_pca)
biplot(nx_pca)

#nx_k_dat<-kmeans(nx_dat, centers=3)
#nxes$cluster<-nx_k_dat$cluster
#plotcluster(nx_dat, nxes$cluster)
