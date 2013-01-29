obj-$(CONFIG_RTLFMAC) 		+= rtlfmac.o
#rtlfmac-objs	:=		\
#		rtlfmac.o

ccflags-y += -D__CHECK_ENDIAN__
