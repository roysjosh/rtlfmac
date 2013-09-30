make -C /usr/src/kernels/$(uname -r) SUBDIRS=$(pwd) CONFIG_RTLFMAC=m KCFLAGS=-Wno-packed-bitfield-compat
