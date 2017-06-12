/*
 * Copyright (c) 2011-2013 Luc Verhaegen <libv@skynet.be>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sub license,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

// Updated as a 'fixer'

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <asm/ioctl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <linux/fb.h>

#define u32 uint32_t
#include "linux/mali_ioctl.h"

#include "version.h"
#include "compiler.h"
#include "formats.h"
#include "linux/ioctl.h"

static int fb_ioctl(int request, void *data);
static int mali_ioctl(int request, void *data);
static int ump_id_add(unsigned int id, unsigned int size, void *address);

static pthread_mutex_t serializer[1] = { PTHREAD_MUTEX_INITIALIZER };

static int fb_ump_id;
static int fb_ump_size;
static void *fb_ump_address;

static inline void
serialized_start(const char *func)
{
	pthread_mutex_lock(serializer);
}

static inline void
serialized_stop(void)
{
	pthread_mutex_unlock(serializer);
}

/*
 *
 * Basic log writing infrastructure.
 *
 */
static FILE *lima_wrap_log;
static int frame_count;

static void
lima_wrap_log_open(void)
{
	char *filename;
	char buffer[1024];

	if (lima_wrap_log)
		return;

	filename = getenv("LIMA_WRAP_LOG");
	if (!filename)
		filename = "/tmp/lima.wrap.log";

	snprintf(buffer, sizeof(buffer), "%s.%04d", filename, frame_count);

	lima_wrap_log = fopen(buffer, "w");
	if (!lima_wrap_log) {
		printf("Error: failed to open wrap log %s: %s\n", filename,
		       strerror(errno));
		lima_wrap_log = stderr;
	}
}

static int wrap_log(const char *format, ...) __attribute__((format(printf, 1, 2)));

static int
wrap_log(const char *format, ...)
{
	va_list args;
	int ret;

	lima_wrap_log_open();

	va_start(args, format);
#if 0
	ret = vfprintf(lima_wrap_log, format, args);
#elif 0
	ret = vfprintf(stderr, format, args);
#else
	ret = 0;
#endif
	va_end(args);

	return ret;
}

/*
 * Wrap around the libc calls that are crucial for capturing our
 * command stream, namely, open, ioctl, and mmap.
 */
static void *libc_dl;

static int
libc_dlopen(void)
{
	libc_dl = dlopen("libc.so.6", RTLD_LAZY);
	if (!libc_dl) {
		printf("Failed to dlopen %s: %s\n",
		       "libc.so", dlerror());
		exit(-1);
	}

	return 0;
}

static void *
libc_dlsym(const char *name)
{
	void *func;

	if (!libc_dl)
		libc_dlopen();

	func = dlsym(libc_dl, name);

	if (!func) {
		printf("Failed to find %s in %s: %s\n",
		       name, "libc.so", dlerror());
		exit(-1);
	}

	return func;
}

static int dev_mali_fd;
static int dev_ump_fd;
static int dev_fb_fd;

/*
 *
 */
static int (*orig_open)(const char* path, int mode, ...);

int
open(const char* path, int flags, ...)
{
	mode_t mode = 0;
	int ret;
	int mali = 0;
	int ump = 0;
	int fb = 0;
	//#define DEBUG
#ifdef DEBUG
	wrap_log("// open(\"%s\", 0x%08x); /*D*/\n", path, flags);
#endif

	if (!strcmp(path, "/dev/mali")) {
		mali = 1;
		serialized_start(__func__);
	} else if (!strcmp(path, "/dev/ump")) {
		ump = 1;
	    	serialized_start(__func__);
	} else if (!strncmp(path, "/dev/fb", 7)) {
		fb = 1;
	}

	if (!orig_open)
		orig_open = libc_dlsym(__func__);

	if (flags & O_CREAT) {
		va_list  args;


		va_start(args, flags);
		mode = (mode_t) va_arg(args, int);
		va_end(args);

		ret = orig_open(path, flags, mode);
	} else {
		ret = orig_open(path, flags);

		if (ret != -1) {
			if (mali)
				dev_mali_fd = ret;
			else if (ump)
				dev_ump_fd = ret;
			else if (fb)
				dev_fb_fd = ret;
		}
	}

	if (mali || ump)
		serialized_stop();

	return ret;
}

/*
 *
 */
static int (*orig_close)(int fd);

int
close(int fd)
{
	int ret;

#ifdef DEBUG
	wrap_log("// close(%d); /*D*/\n", fd);
#endif
	if (fd == dev_mali_fd)
	    	serialized_start(__func__);

	if (!orig_close)
		orig_close = libc_dlsym(__func__);

	if (fd == dev_mali_fd) {
		wrap_log("/* CLOSE */");
		dev_mali_fd = -1;
	}

	ret = orig_close(fd);

	if (fd == dev_mali_fd)
		serialized_stop();

	return ret;
}

/*
 * Bionic, go figure...
 */
#ifdef ANDROID
static int (*orig_ioctl)(int fd, int request, ...);
#else
static int (*orig_ioctl)(int fd, unsigned long request, ...);
#endif

int
#ifdef ANDROID
ioctl(int fd, int request, ...)
#else
ioctl(int fd, unsigned long request, ...)
#endif
{
	int ioc_size = _IOC_SIZE(request);
	int ret;
	int yield = 0;

#ifdef DEBUG
	wrap_log("// ioctl(%d, 0x%08lx); /*D: 0x%08lx:%ld*/\n", fd, request, _IOC_TYPE(request), _IOC_NR(request)); //0x82: CORE, 0x83: MEM, 0x84: PP_SUBSYSTEM
#endif
	serialized_start(__func__);

	if (!orig_ioctl)
		orig_ioctl = libc_dlsym(__func__);

	/* hack around badly defined fbdev ioctls */
	if (ioc_size || ((request & 0xFFC8) == 0x4600)) {
		va_list args;
		void *ptr;

		va_start(args, request);
		ptr = va_arg(args, void *);
		va_end(args);

		if (fd == dev_mali_fd) {
			if ((request == MALI_IOC_WAIT_FOR_NOTIFICATION) ||
			    (request == MALI_IOC_WAIT_FOR_NOTIFICATION_R3P1))
				yield = 1;

			ret = mali_ioctl(request, ptr);
		} else if (fd == dev_fb_fd)
			ret = fb_ioctl(request, ptr);
		else
			ret = orig_ioctl(fd, request, ptr);
	} else {
		if (fd == dev_mali_fd)
			ret = mali_ioctl(request, NULL);
		else if (fd == dev_fb_fd)
			ret = fb_ioctl(request, NULL);
		else
			ret = orig_ioctl(fd, request);
	}

	serialized_stop();

	if (yield)
		sched_yield();

	return ret;
}


/*
 * Parse FB ioctls.
 */
static int
fb_ioctl(int request, void *data)
{
	int ret;

#define DEF_DECODFBDEV
#ifdef DEF_DECODFBDEV
	{
	  const int ioc_type = _IOC_TYPE(request);
	  const int ioc_nr = _IOC_NR(request);

	  switch(request) { // include/uapi/linux/fb.h
	  case FBIOGET_VSCREENINFO: wrap_log("// ioctl(fbdev, FBIOGET_VSCREENINFO);\n"); break;
	  case FBIOGET_FSCREENINFO: wrap_log("// ioctl(fbdev, FBIOGET_FSCREENINFO);\n"); break;
	  case FBIOPAN_DISPLAY: wrap_log("// ioctl(fbdev, FBIOPAN_DISPLAY);\n"); break;
	  default: wrap_log("// ioctl(fbdev, 0x%08x); // %02x:%02x\n", request, ioc_type, ioc_nr);
	    break;
	  }
	}
#endif /*DEF_DECODFBDEV*/
	if (data)
		ret = orig_ioctl(dev_fb_fd, request, data);
	else
		ret = orig_ioctl(dev_fb_fd, request);

#define GET_UMP_SECURE_ID_BUF1   _IOWR('m', 311, unsigned int)

#ifdef DEF_DECODFBDEV
	{
	  switch(request) { // include/uapi/linux/fb.h
	  case FBIOGET_VSCREENINFO: case FBIOPAN_DISPLAY: {
	    struct fb_var_screeninfo *const p = data;
#if 1
	    p->yres_virtual = 1080*2; //FIXME; //hardpatch
	    //p->transp.offset = 24;
	    //p->transp.length = 8;
	    // p->transp.msb_right = 0;
	    //p->height = 211;
	    //p->width = 375;
	    //p->accel_flags = 0;
#endif
	    wrap_log("// struct fb_var_screeninfo f = { /*xres*/ %d, %d, %d, %d, /*xoffset*/ %d, %d, /*bits_per_pixel*/ %d, /*grayscale*/ %d, ",
		     p->xres, p->yres, p->xres_virtual, p->yres_virtual, p->xoffset, p->yoffset, p->bits_per_pixel, p->grayscale);
	    wrap_log("{ %d, %d, %d}, { %d, %d, %d}, { %d, %d, %d}, { %d, %d, %d},  \n", p->red.offset, p->red.length, p->red.msb_right, p->green.offset, p->green.length, p->green.msb_right, p->blue.offset, p->blue.length, p->blue.msb_right, p->transp.offset, p->transp.length, p->transp.msb_right);
	    wrap_log("// /*nonstd*/ %d, /*activate*/ %d, /*height mm*/ %d, /*width mm*/ %d, 0x%08x, ", p->nonstd, p->activate, p->height, p->width, p->accel_flags );
	    wrap_log("/*pixclock*/ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, /*reserved[4]*/ %d, %d, %d, %d }; //ret=%d\n", p->pixclock, p->left_margin,  p->right_margin, p->upper_margin, p->lower_margin, p->hsync_len, p->vsync_len, p->sync, p->vmode, p->rotate, p->colorspace, p->reserved[0], p->reserved[1], p->reserved[2], p->reserved[3], ret);
	  }
	    break;
	  case FBIOGET_FSCREENINFO: {
	    struct fb_fix_screeninfo *const p = data;
#if 0
	    p->smem_len = 16588800; /* hardpatch */
#endif
	    wrap_log("// struct fb_fix_screeninfo f = { \"%s\", /*smem_start*/ 0x%08lx, /*smem_len*/ 0x%08x, %d, %d, %d, /*xpanstep*/ %d,  /*ypanstep*/ %d, %d, /*line_length*/ %d, 0x%08lx, 0x%08x, 0x%08x, 0x%08x, /*reserved[2]*/ %d, %d }; //ret=%d\n",
		     p->id, p->smem_start, p->smem_len, p->type, p->type_aux, p->visual, p->xpanstep, p->ypanstep, p->ywrapstep, p->line_length, p->mmio_start, p->mmio_len, p->accel, p->capabilities, p->reserved[0], p->reserved[1], ret);
	  }
	    break;
	  }
	}
#endif /*DEF_DECODFBDEV*/

	if (request == FBIOGET_FSCREENINFO) {
		struct fb_fix_screeninfo *fix = data;

		fb_ump_size = fix->smem_len;
	} else if (request == GET_UMP_SECURE_ID_BUF1) {
		unsigned int *id = data;

		fb_ump_id = *id;

		ump_id_add(fb_ump_id, fb_ump_size, fb_ump_address);
	}

	return ret;
}


/*
 *
 * Now the mali specific ioctl parsing.
 *
 */
static char *
ioctl_dir_string(int request)
{
	switch (_IOC_DIR(request)) {
	default: /* cannot happen */
	case 0x00:
		return "_IO";
	case 0x01:
		return "_IOW";
	case 0x02:
		return "_IOR";
	case 0x03:
		return "_IOWR";
	}
}

static void
dev_mali_wait_for_notification_pre(void *data)
{
	wrap_log("/* IOCTL MALI_IOC_WAIT_FOR_NOTIFICATION IN */\n");

	wrap_log("#if 0 /* Notification */\n\n");

	wrap_log("_mali_uk_wait_for_notification_s mali_notification_in = {\n");
	wrap_log("};\n\n");

	wrap_log("#endif /* Notification */\n\n");

	/* some kernels wait forever otherwise */
	serialized_stop();
}

/*
 * At this point, we do not care about the performance counters.
 */
static void
dev_mali_wait_for_notification_post(void *data, int ret)
{
	/* to match the pre function */
	serialized_start(__func__);

	/* some post-processing */
}

static struct ioc_type {
	int type;
	char *name;
} ioc_types[] = {
	{MALI_IOC_CORE_BASE, "MALI_IOC_CORE_BASE"},
	{MALI_IOC_MEMORY_BASE, "MALI_IOC_MEMORY_BASE"},
	{MALI_IOC_PP_BASE, "MALI_IOC_PP_BASE"},
	{MALI_IOC_GP_BASE, "MALI_IOC_GP_BASE"},
	{0, NULL},
};

static char *
ioc_type_name(int type)
{
	int i;

	for (i = 0; ioc_types[i].name; i++)
		if (ioc_types[i].type == type)
			break;

	return ioc_types[i].name;
}

struct dev_mali_ioctl_table {
	int type;
	int nr;
	char *name;
	void (*pre)(void *data);
	void (*post)(void *data, int ret);
};

static struct dev_mali_ioctl_table
dev_mali_ioctls_r3p1[] = {
	{MALI_IOC_CORE_BASE, _MALI_UK_WAIT_FOR_NOTIFICATION_R3P1, "CORE, WAIT_FOR_NOTIFICATION",
	 dev_mali_wait_for_notification_pre, dev_mali_wait_for_notification_post},
	{ 0, 0, NULL, NULL, NULL}
};

struct dev_mali_ioctl_table *ioctl_table;

static int
mali_ioctl(int request, void *data)
{
	struct dev_mali_ioctl_table *ioctl = NULL;
	int ioc_type = _IOC_TYPE(request);
	int ioc_nr = _IOC_NR(request);
	char *ioc_string = ioctl_dir_string(request);
	int i;
	int ret;

	if (!ioctl_table) {
	  ioctl_table = dev_mali_ioctls_r3p1;
	}

	for (i = 0; ioctl_table[i].name; i++) {
		if ((ioctl_table[i].type == ioc_type) &&
		    (ioctl_table[i].nr == ioc_nr)) {
			ioctl = &ioctl_table[i];
			break;
		}
	}

	if (!ioctl) {
		char *name = ioc_type_name(ioc_type);

		if (name)
			wrap_log("/* Error: No mali ioctl wrapping implemented for %s:%02X */\n",
				 name, ioc_nr);
		else
			wrap_log("/* Error: No mali ioctl wrapping implemented for %02X:%02X */\n",
				 ioc_type, ioc_nr);

	}

	if (ioctl && ioctl->pre)
		ioctl->pre(data);

	if (data)
		ret = orig_ioctl(dev_mali_fd, request, data);
	else
		ret = orig_ioctl(dev_mali_fd, request);

	if (ret == -EPERM) {
		if ((ioc_type == MALI_IOC_CORE_BASE) &&
		    (ioc_nr == _MALI_UK_GET_API_VERSION))
			ioctl_table = dev_mali_ioctls_r3p1;
	}

	if (ioctl && !ioctl->pre && !ioctl->post) {
		if (data)
			wrap_log("/* IOCTL %s(%s) %p = %d */\n",
				 ioc_string, ioctl->name, data, ret);
		else
			wrap_log("/* IOCTL %s(%s) = %d */\n",
				 ioc_string, ioctl->name, ret);
	}

	if (ioctl && ioctl->post)
		ioctl->post(data, ret);

	return ret;
}

/*
 *
 * Memory dumper.
 *
 */
#define MALI_ADDRESSES 0x40



#define UMP_ADDRESSES 0x10

static struct ump_address {
	void *address; /* mapped address */
	unsigned int id;
	unsigned int size;
	unsigned int physical; /* actual address */
} ump_addresses[UMP_ADDRESSES];

static int
ump_id_add(unsigned int id, unsigned int size, void *address)
{
	int i;

	for (i = 0; i < UMP_ADDRESSES; i++)
		if (!ump_addresses[i].id) {
			ump_addresses[i].id = id;
			ump_addresses[i].size = size;
			ump_addresses[i].address = address;
			return 0;
		}

	printf("%s: No more free slots for 0x%08X (0x%x)!\n",
	       __func__, id, size);
	return -1;
}
