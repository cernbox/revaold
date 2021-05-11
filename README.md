# REVA

REVA code running in CERNBox production since June 2018.

New REVA code lives in github.com/cernbox/reva.


# How to distribute RPMs in CERN infrastructure

* Build with Dockerfile on repostiry root to have CC7 RPMS
* `scp *rpm lxplus.cern.ch:/eos/project/s/storage-ci/www/cernbox/tag/el-7/x86_64/`
* `ssh lxplus "createrepo --update /eos/project/s/storage-ci/www/cernbox/tag/el-7/x86_64/"`


