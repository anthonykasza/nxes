library(fpc)
library(cluster)

# gather and massage data
col_names=c("query", "qtype", "qlen", "tld_len", "subs_c", "sub_len", "domain_len", "domain_uchars_c", "domain_grams_c", "domain_entropy")
col_classes=c("character", "integer", "integer", "integer", "integer", "integer",  "integer", "integer", "integer", "double")
nxes<-read.table("nxes.log", sep="\t", col.names=col_names, na.strings="-", colClasses=col_classes, comment.char="#")
nxes<-unique(nxes)
row.names(nxes)<-nxes$query
data<-scale(data.frame(nxes[,3:length(nxes)]))

# explore data
pairs(data)
heatmap(data)
plot(rowMeans(data), pch=19)
plot(colMeans(data), pch=19)

svd1 <- svd(data)
plot(svd1$u[,1], pch=19)
plot(svd1$d, pch=19)

nx_pca<-princomp(data, scores=T, cor=T)
plot(nx_pca)
biplot(nx_pca)

nx_k_dat<-kmeans(data, centers=3)
nxes$cluster<-nx_k_dat$cluster
plotcluster(data, nxes$cluster)

clusplot(data, nx_k_dat$cluster, color=T, share=T, labels=2, lines=0)
