obj-m += xt_tcpr.o
xt_tcpr-objs := module.o tcpr.o
EXTRA_CFLAGS=-I$(PWD)/../include

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
