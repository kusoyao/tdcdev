#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/timer.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include "tdc.h"

MODULE_AUTHOR("kusoyao");
MODULE_DESCRIPTION("E906 TDC Driver");
MODULE_LICENSE("Dual MIT/GPL");

static int tdc_devs = 1;        /* device count */
static struct cdev tdc_cdev;
static struct class *tdc_class = NULL;
static dev_t tdc_dev;
static __iomem unsigned long *reg = 0;
struct resource *res = NULL;

struct tdc_data {
	rwlock_t lock;
	unsigned char data[DPSRAM_LENGTH];
};

static struct kfifo ev_fifo;
static void *ev_fifo_buffer = 0;
static unsigned long ev_buff_size = SZ_1M;
module_param(ev_buff_size, ulong, 0444);

#define TDC_READOUT_PERIOD 5*HZ
static struct timer_list tdc_timer;
static void tdc_readout(unsigned long arg){
	unsigned long left = 0;
	left = kfifo_avail(&ev_fifo);
	printk(KERN_ALERT "buffer left %lu\n", left);
	if( left < DPSRAM_LENGTH){
		printk(KERN_ALERT "event buffer full.\n");
		goto out;
	}
	kfifo_in(&ev_fifo, reg, DPSRAM_LENGTH);
out:
	/* set next readout */
	mod_timer(&tdc_timer, jiffies + TDC_READOUT_PERIOD);
}

static long tdc_ioctl(struct file *filp,unsigned int cmd, unsigned long arg){
	struct tdc_data *tdc = filp->private_data;
	int retval = 0;
	struct ioctl_cmd data;

	memset(&data, 0, sizeof(data));

	switch (cmd) {
		case IOCTL_SETREG:
			if(!access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd))) {
				retval = -EFAULT;
				goto done;
			}
			if( copy_from_user(&data, (int __user *)arg, sizeof(struct ioctl_cmd)) ) {
				retval = -EFAULT;
				goto done;
			}
			if( data.offset > DPSRAM_LENGTH) {
				retval = -EFAULT;
				printk(KERN_ALERT "address too large!\n");
				goto done;
			}
			write_lock(&tdc->lock);
			/* iowrite32( data.val, reg+data.offset); */
			*(reg+data.offset) = data.val;
			write_unlock(&tdc->lock);
			break;

		case IOCTL_GETREG:
			/* if allow write, it also allow read! */
			if(!access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd))) {
				retval = -EFAULT;
				goto done;
			}
			if( copy_from_user(&data, (int __user *)arg, sizeof(struct ioctl_cmd)) ) {
				retval = -EFAULT;
				goto done;
			}
			if( data.offset > DPSRAM_LENGTH) {
				retval = -EFAULT;
				printk(KERN_ALERT "address too large!\n");
				goto done;
			}
			read_lock(&tdc->lock);
			/* data.val = ioread32(reg+data.offset); */
			data.val = *(reg+data.offset);
			read_unlock(&tdc->lock);
			
			if( copy_to_user((int __user *)arg, &data, sizeof(struct ioctl_cmd)) ) {
				retval = -EFAULT;
				goto done;
			}
			break;

		case IOCTL_LED_ON:
			write_lock(&tdc->lock);
			/* iowrite32( 0xF0E9060F, reg+LED_ADDR_OFFSET); */
			*(reg+LED_ADDR_OFFSET) = 0xF09060F;
			write_unlock(&tdc->lock);
			break;

		case IOCTL_LED_OFF:
			write_lock(&tdc->lock);
			/* iowrite32( 0x10E90601, reg+LED_ADDR_OFFSET); */
			*(reg+LED_ADDR_OFFSET) = 0x10E90601;
			write_unlock(&tdc->lock);
			break;

		default:
			retval = -ENOTTY;
			break;
	}

done:
	return retval;
}

static ssize_t tdc_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
	struct tdc_data *tdc = filp->private_data;
	int retval;
	int left_byte;
	int rep;
	
	if( count > DPSRAM_LENGTH ) count = DPSRAM_LENGTH;
	left_byte = count & 0x3;
	rep = count >> 2;
	
	if( left_byte != 0){
		printk(KERN_ALERT "not alignment reading! %d\n", count);
		rep+=1;
	}
	if(!access_ok(VERIFY_WRITE, buf, count) ) {
		return 0;
	}
	
	read_lock(&tdc->lock);
	ioread32_rep(reg, tdc->data, rep);
	/*for(i=0;i<rep;++i){
		((unsigned long*)tdc->data)[i] = *(reg+i);
	}*/
	read_unlock(&tdc->lock);
	
	if( copy_to_user(buf, tdc->data, count) ) {
		retval = -EFAULT;
		goto out;
	}
	retval = count;

out:
	return retval;
}

static int tdc_close(struct inode *inode, struct file *filp){
	struct tdc_data *tdc = filp->private_data;

	if (tdc) {
		kfree(tdc);
	}

	return 0;
}

static int tdc_open(struct inode *inode, struct file *filp){
	struct tdc_data *tdc;

	tdc = kmalloc(sizeof(struct tdc_data), GFP_KERNEL);
	if (tdc == NULL) {
		return -ENOMEM;
	}
	/* initialize members */
	memset(tdc, 0, sizeof(struct tdc_data));
	rwlock_init(&tdc->lock);

	filp->private_data = tdc;

	return 0;
}

static struct file_operations tdc_fops = {
	.owner = THIS_MODULE,
	.open = tdc_open,
	.release = tdc_close,
	.read = tdc_read,
	.unlocked_ioctl = tdc_ioctl,
};

static unsigned long rounded_down(unsigned long size){
	unsigned long order = SZ_2G;
	while(!(size & order)){
		order>>=1;
	}
	return order;
}

static int tdc_init(void){		
	/* init */
	int alloc_ret = 0;
	int cdev_err = 0;
	struct device *class_dev = NULL;
	int fifo_ret = 0;
	int tdc_major = 0;
	/* get major number, store to tdc_dev*/
	alloc_ret = alloc_chrdev_region(&tdc_dev, 0, tdc_devs, "tdc");
	if (alloc_ret)
		goto error;
	tdc_major = MAJOR(tdc_dev);
	/* register handler */
	cdev_init(&tdc_cdev, &tdc_fops);
	tdc_cdev.owner = THIS_MODULE;
	tdc_cdev.ops = &tdc_fops;
	/* register driver*/
	cdev_err = cdev_add(&tdc_cdev, tdc_dev, tdc_devs);
	if (cdev_err)
		goto error;

	/* register class ,support udev, /sys/class/tdc/xxx */
	tdc_class = class_create(THIS_MODULE, "tdc");
	if (IS_ERR(tdc_class)) {
		goto error;
	}
	class_dev = device_create( tdc_class, NULL, tdc_dev, NULL, "tdc");
	/* cat /proc/iomem */
	res = request_mem_region(DPSRAM_ADDR, DPSRAM_LENGTH, "TDC_DPSRAM");
	if(!res){
		printk(KERN_ALERT "request_mem_region error.\n");
		goto error;
	}
	/* memory mapping io */
	reg = ioremap_nocache(DPSRAM_ADDR, DPSRAM_LENGTH);
	if(!reg) {
		printk(KERN_ALERT "iomem mapping error.\n");
		goto error;
	}
	
	/* event buffer fifo */
	ev_buff_size = rounded_down(ev_buff_size);
	ev_fifo_buffer = kmalloc( ev_buff_size, GFP_KERNEL);
	fifo_ret = kfifo_init(&ev_fifo, ev_fifo_buffer, ev_buff_size);
	if(fifo_ret){
		printk(KERN_ALERT "tdc event fifo create fail.");
		goto error;
	}
	printk(KERN_ALERT "allocate tdc event fifo %lu bytes. addr=%p\n", ev_buff_size, ev_fifo_buffer);
	
	/* init timer */
	init_timer(&tdc_timer);
	tdc_timer.function = tdc_readout;
	tdc_timer.data = (unsigned long)reg;
	tdc_timer.expires = jiffies + TDC_READOUT_PERIOD;
	add_timer(&tdc_timer);
	
	/* for DEBUG
	printk(KERN_ALERT "MAJOR number %d\n", tdc_major);
	printk(KERN_ALERT "ev_fifo_buffer %p\n", ev_fifo_buffer);
	printk(KERN_ALERT "request_mem_region res %p\n", res);
	printk(KERN_ALERT "ioremap_nocache %p\n", reg);
	printk(KERN_ALERT "cdev_err %d\n", cdev_err);
	printk(KERN_ALERT "alloc_ret %d\n", alloc_ret);
	*/
	printk(KERN_ALERT "tdc driver loaded successful.\n");

	return 0;
	
error:
	if (ev_fifo_buffer) kfree(ev_fifo_buffer);
	if (res) release_mem_region(DPSRAM_ADDR, DPSRAM_LENGTH);
	if (reg) iounmap(reg);
	if (cdev_err == 0) cdev_del(&tdc_cdev);
	if (alloc_ret == 0) unregister_chrdev_region(tdc_dev, tdc_devs);
	printk(KERN_ALERT "tdc driver loaded fail. MAJOR number is %d\n", tdc_major);
	
	return -1;
}

static void tdc_exit(void){
	/* delete timer */
	del_timer_sync(&tdc_timer);
	
	/* release fifo buffer*/
	kfree(ev_fifo_buffer);
	
	iounmap((void *)reg);
	release_mem_region(DPSRAM_ADDR, DPSRAM_LENGTH);
	
	/* delete class*/
	device_destroy(tdc_class, tdc_dev);
	class_destroy(tdc_class);

	/* release driver */
	cdev_del(&tdc_cdev);
	/* release major number*/
	unregister_chrdev_region( tdc_dev, tdc_devs);

	printk(KERN_ALERT "tdc driver removed successful.\n");

}

module_init(tdc_init);
module_exit(tdc_exit);