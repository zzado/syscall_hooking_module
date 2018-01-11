#include<linux/kernel.h>
#include<linux/module.h>
#include<asm/unistd.h>
#include<linux/syscalls.h>
#include<linux/hugetlb.h>

unsigned long** syscall_table;
int (*set_memory_rw)(unsigned long addr, int numpages);

/*
asmlinkage long (*orig_call)(const char __user *, int, mode_t);

asmlinkage long hook_open(const char __user *filename, int flags, umode_t mode){
	printk("open system\n");
	return (orig_call(filename, flags, mode));
}
*/

asmlinkage long (*orig_zzado)(void);

asmlinkage long hook_func(void){
	printk("Hooked sys_zzado\n");
	return (orig_zzado());
}

int hook_init(void){

/*
	printk("int size : %zu\n", sizeof(int));
	printk("long size : %zu\n", sizeof(long));
	printk("long long size : %zu\n", sizeof(long long));
*/
//	set_memory_rw = (void *)0xffffffff9466ad80;
	syscall_table = (unsigned long**)0xffffffff86c00180;
	unsigned long cr0;
	cr0 = read_cr0();
	write_cr0(cr0 & ~0x00010000);
	printk("[*] cr0 : %zx\n", cr0);	
	
	printk("[*] hooking func : %lx\n", (unsigned long)hook_func);	
	
	//set_memory_rw(syscall_table, 3);
	orig_zzado = (void *)syscall_table[400];	
	printk("[*] sys_zzado : %lx\n", (unsigned long)syscall_table[400]);	
	syscall_table[400] = (void *)hook_func;	
	printk("[*] hooked sys_zzado : %lx\n", (unsigned long)syscall_table[400]);	
	
	write_cr0(cr0);	
	return 0;
}

void hook_cleanup(void){

	printk("Module cleanup\n");
}

module_init(hook_init);
module_exit(hook_cleanup);
MODULE_LICENSE("GPL");
