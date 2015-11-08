#!/bin/bash

RPMROOT=~/rpmbuild

if [ -z "$1" ];then
   echo "You didn't specify anything to build";
   exit 1;
fi

tar zcf $RPMROOT/SOURCES/${1}.tar.gz ${1};

# build the package
rpmbuild -bb ${1}.spec
