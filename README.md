Sunxi / H3 Linux mainline 4.11.y Mali test repository - fbdev mode


Requirements:
* Linux kernel: https://github.com/megous/linux.git branch: orange-pi-4.11 with the patches from kernel-megous-patches/*.patch applied.
* Mali linux driver: https://github.com/mripard/sunxi-mali directory: r6p2
* Mali blob from https://github.com/mosajjal/r6p2 fbdev (md5sum: 6eaec1a71a2bf2beab30b9e443bf7acf)

The patch set a framebuffer large enough for 1980x1080 double buffering; This is required for the blob to operate. We have some limitation today, the display driver will not display the second image.
* The 'de2' drm fbdev driver must be loaded and running.
* The current drm/framebuffer implementation can't change the vyres size (fbset -vyres 2160 will fail). A 'fix' is provided that will change the fbdev ioctl value on the fly.

* To compile the 'fixer' (based on code from lima (https://github.com/limadriver-ng/lima.git)):pr
make  

To test:
LD_PRELOAD=fixer/libMali_fixer.so glmark2-es2-fb
