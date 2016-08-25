#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include "tdc.h"

MODULE_AUTHOR("kusoyao");
MODULE_DESCRIPTION("E906 TDC Driver");
MODULE_LICENSE("Dual MIT/GPL");

#define TDC_DEVICES 1        /* device count */
#define TDC_READOUT_PERIOD 5*HZ

struct tdc_data {
	rwlock_t lock;
};

struct tdc_device {
	struct cdev tdc_cdev;
	struct class *tdc_class;
	dev_t tdc_dev;
	struct kfifo ev_fifo;
	void *ev_fifo_buffer;
	unsigned long ev_buff_size;
	spinlock_t lock;
	struct timer_list tdc_timer;	/* */
	atomic_t buffer_been_full;	/* buffer full counter*/
	wait_queue_head_t wait;
};

static struct tdc_device *dev = NULL;
static __iomem unsigned long *reg = 0;

static unsigned long ev_buff_size = SZ_4K;
module_param(ev_buff_size, ulong, 0444);

static void tdc_readout(unsigned long arg){
	unsigned long left = 0;
	left = kfifo_avail(&dev->ev_fifo);
	if( left < sizeof(struct tdc_event)){
		atomic_inc(&dev->buffer_been_full);
		printk(KERN_ALERT "event buffer full. %d\n", atomic_read(&dev->buffer_been_full));
		goto out;
	}
	kfifo_in(&dev->ev_fifo, reg, sizeof(struct tdc_event));
out:
	wake_up(&dev->wait);
	/* set next readout */
	mod_timer(&dev->tdc_timer, jiffies + TDC_READOUT_PERIOD);
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
	int copied;
	
	if(!access_ok(VERIFY_WRITE, buf, count) ) {
		return 0;
	}
	
	retval = wait_event_interruptible(dev->wait, kfifo_len(&dev->ev_fifo) );
	if(retval != 0) {
		/* wake up by signal! */
		return 0;
	}

	read_lock(&tdc->lock);
	retval = kfifo_to_user(&dev->ev_fifo, buf, count, &copied);
	read_unlock(&tdc->lock);
	
	if(retval){
		retval = -EFAULT;
		goto out;
	}
	retval = copied;

out:
	return retval;
}

static ssize_t tdc_write(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
	return -EFAULT;
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
	.write = tdc_write,
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
	int tdc_major = 0;
	struct resource *res = NULL;
	
	/* init device struct */
	dev = kmalloc( sizeof(struct tdc_device), GFP_KERNEL);
	spin_lock_init(&dev->lock);
	atomic_set(&dev->buffer_been_full, 0);
	init_waitqueue_head(&dev->wait);
	
	/* get major number, store to tdc_dev*/
	alloc_ret = alloc_chrdev_region(&dev->tdc_dev, 0, TDC_DEVICES, "tdc");
	if (alloc_ret)
		goto error;
	tdc_major = MAJOR(dev->tdc_dev);
	/* register handler */
	cdev_init(&dev->tdc_cdev, &tdc_fops);
	dev->tdc_cdev.owner = THIS_MODULE;
	dev->tdc_cdev.ops = &tdc_fops;
	/* register driver*/
	cdev_err = cdev_add(&dev->tdc_cdev, dev->tdc_dev, TDC_DEVICES);
	if (cdev_err)
		goto error;

	/* register class ,support udev, /sys/class/tdc/xxx */
	dev->tdc_class = class_create(THIS_MODULE, "tdc");
	if (IS_ERR(dev->tdc_class)) {
		goto error;
	}
	class_dev = device_create( dev->tdc_class, NULL, dev->tdc_dev, NULL, "tdc");
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
	dev->ev_fifo_buffer = kmalloc( ev_buff_size, GFP_KERNEL);
	if(!dev->ev_fifo_buffer){
		printk(KERN_ALERT "allocate tdc event fifo %lu bytes fail.\n", ev_buff_size);
		goto error;
	}
	dev->ev_buff_size = ev_buff_size;
	printk(KERN_ALERT "allocate tdc event fifo %lu bytes. addr=%p\n", dev->ev_buff_size, dev->ev_fifo_buffer); 
	if(kfifo_init(&dev->ev_fifo, dev->ev_fifo_buffer, dev->ev_buff_size)){
		printk(KERN_ALERT "tdc event fifo create fail.");
		goto error;
	}
	
	/* init timer */
	init_timer(&dev->tdc_timer);
	dev->tdc_timer.function = tdc_readout;
	dev->tdc_timer.data = (unsigned long)dev;
	dev->tdc_timer.expires = jiffies + TDC_READOUT_PERIOD;
	add_timer(&dev->tdc_timer);
	
	/* for DEBUG
	printk(KERN_ALERT "MAJOR number %d\n", tdc_major);
	printk(KERN_ALERT "dev->ev_fifo_buffer %p\n", dev->ev_fifo_buffer);
	printk(KERN_ALERT "request_mem_region res %p\n", res);
	printk(KERN_ALERT "ioremap_nocache %p\n", reg);
	printk(KERN_ALERT "cdev_err %d\n", cdev_err);
	printk(KERN_ALERT "alloc_ret %d\n", alloc_ret);
	*/
	printk(KERN_ALERT "tdc driver loaded successful.\n");

	return 0;
	
error:
	if (dev->ev_fifo_buffer) kfree(dev->ev_fifo_buffer);
	if (dev) kfree(dev);
	if (res) release_mem_region(DPSRAM_ADDR, DPSRAM_LENGTH);
	if (reg) iounmap(reg);
	if (cdev_err == 0) cdev_del(&dev->tdc_cdev);
	if (alloc_ret == 0) unregister_chrdev_region(dev->tdc_dev, TDC_DEVICES);
	printk(KERN_ALERT "tdc driver loaded fail. MAJOR number is %d\n", tdc_major);
	
	return -1;
}

static void tdc_exit(void){
	/* delete timer */
	del_timer_sync(&dev->tdc_timer);
	
	/* release fifo buffer*/
	kfree(dev->ev_fifo_buffer);
	
	iounmap((void *)reg);
	release_mem_region(DPSRAM_ADDR, DPSRAM_LENGTH);
	
	/* delete class*/
	device_destroy(dev->tdc_class, dev->tdc_dev);
	class_destroy(dev->tdc_class);

	/* release driver */
	cdev_del(&dev->tdc_cdev);
	/* release major number*/
	unregister_chrdev_region( dev->tdc_dev, TDC_DEVICES);

	/* release device struct*/
	kfree(dev);

	printk(KERN_ALERT "tdc driver removed successful.\n");

}

module_init(tdc_init);
module_exit(tdc_exit);