obj-m += xt_tcpr.o
EXTRA_CFLAGS=-I$(PWD)/../include

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
