#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x5cdb9d2f, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x38461209, __VMLINUX_SYMBOL_STR(dev_remove_pack) },
	{ 0x9ed554b3, __VMLINUX_SYMBOL_STR(unregister_keyboard_notifier) },
	{ 0x2d0d0f1b, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xe71ed36e, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x96554810, __VMLINUX_SYMBOL_STR(register_keyboard_notifier) },
	{ 0xc590bbd2, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0xbb583eb5, __VMLINUX_SYMBOL_STR(sock_create) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x5abbc019, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x4e6a3638, __VMLINUX_SYMBOL_STR(dev_add_pack) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

