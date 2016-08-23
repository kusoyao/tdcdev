obj-m += tdc.o

all:
	make -C /nfsroot/lib/modules/3.18.0-linux4sam_5.0-alpha4-TDC-dirty/build M=$(PWD) modules
clean:
	make -C /nfsroot/lib/modules/3.18.0-linux4sam_5.0-alpha4-TDC-dirty/build M=$(PWD) clean
