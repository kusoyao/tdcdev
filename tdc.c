#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include "tdc.h"

MODULE_LICENSE("Dual BSD/GPL");

static int tdc_devs = 1;        /* device count */
static int tdc_major = 0;       /* MAJOR: dynamic allocation */
static int tdc_minor = 0;       /* MINOR: static allocation */
static struct cdev tdc_cdev;
static struct class *tdc_class = NULL;
static dev_t tdc_dev;
static __iomem unsigned long *reg = 0;
struct resource *res = NULL;

struct tdc_data {
	rwlock_t lock;
	unsigned char data[DPSRAM_LENGTH];
};

long tdc_ioctl(struct file *filp,unsigned int cmd, unsigned long arg)
{
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
			//iowrite32( data.val, reg+data.offset);
			*(reg+data.offset) = data.val;
			write_unlock(&tdc->lock);
			break;

		case IOCTL_GETREG:
			//if allow write, it also allow read!
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
			//data.val = ioread32(reg+data.offset);
			data.val = *(reg+data.offset);
			read_unlock(&tdc->lock);
			
			if( copy_to_user((int __user *)arg, &data, sizeof(struct ioctl_cmd)) ) {
				retval = -EFAULT;
				goto done;
			}
			break;

		case IOCTL_LED_ON:
			write_lock(&tdc->lock);
			//iowrite32( 0xF0E9060F, reg+LED_ADDR_OFFSET);
			*(reg+LED_ADDR_OFFSET) = 0xF09060F;
			write_unlock(&tdc->lock);
			break;

		case IOCTL_LED_OFF:
			write_lock(&tdc->lock);
			//iowrite32( 0x10E90601, reg+LED_ADDR_OFFSET);
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

ssize_t tdc_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	struct tdc_data *tdc = filp->private_data;
	int retval;
	int left_byte;
	int rep;
	int i;
	
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
	//for(i=0;i<rep;++i){
	//	((unsigned long*)tdc->data)[i] = *(reg+i);
	//}
	read_unlock(&tdc->lock);
	
	if( copy_to_user(buf, tdc->data, count) ) {
		retval = -EFAULT;
		goto out;
	}
	retval = count;

out:
	return retval;
}

int tdc_close(struct inode *inode, struct file *filp)
{
	struct tdc_data *tdc = filp->private_data;

	if (tdc) {
		kfree(tdc);
	}

	return 0;
}

int tdc_open(struct inode *inode, struct file *filp)
{
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

struct file_operations tdc_fops = {
	.owner = THIS_MODULE,
	.open = tdc_open,
	.release = tdc_close,
	.read = tdc_read,
	.unlocked_ioctl = tdc_ioctl,
};

static int tdc_init(void)
{		
	/* init */
	dev_t tdc_dev = MKDEV(tdc_major, 0);
	int alloc_ret = 0;
	int cdev_err = 0;
	struct device *class_dev = NULL;

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
	class_dev = device_create( tdc_class, NULL, tdc_dev, NULL, "tdc%d", tdc_minor);
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
	
	printk(KERN_ALERT "tdc driver loaded successful. MAJOR number is %d\n", tdc_major);
	return 0;

error:
	if (res) release_mem_region(DPSRAM_ADDR, DPSRAM_LENGTH);
	if (reg) iounmap(reg);
	if (cdev_err == 0) cdev_del(&tdc_cdev);
	if (alloc_ret == 0) unregister_chrdev_region(tdc_dev, tdc_devs);
	printk(KERN_ALERT "tdc driver loaded fail. MAJOR number is %d\n", tdc_major);
	
	return -1;
}

static void tdc_exit(void)
{
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


