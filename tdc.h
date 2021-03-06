#ifndef _TDC_IOCTL_H
#define _TDC_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ioctl_cmd {
	unsigned long offset;
	unsigned long val;
};

#define IOC_MAGIC 't'

#define IOCTL_LED_ON _IO(IOC_MAGIC, 1)
#define IOCTL_LED_OFF _IO(IOC_MAGIC, 2)
#define IOCTL_SETREG _IOW(IOC_MAGIC, 1, struct ioctl_cmd)
#define IOCTL_GETREG _IOR(IOC_MAGIC, 2, struct ioctl_cmd)

#define DPSRAM_LENGTH 0x20000 // DP-SRAM 128kB
#define DPSRAM_ADDR 0x50000000
#define FLAG_ADDR 0x60000000
#define LED_ADDR_OFFSET 0x0 // temp test address

struct tdc_event {
	union {
		struct {
			unsigned long trigger;
			unsigned long channel[64];
		};
		unsigned long data[65];
	};
};

#endif

