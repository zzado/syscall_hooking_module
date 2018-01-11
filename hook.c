#include<linux/kernel.h>
#include<linux/module.h>
#include<asm/unistd.h>
#include<linux/syscalls.h>
#include<linux/hugetlb.h>

#define CR0_WP 0xFFFEFFFF
unsigned long** syscall_table;
//int (*set_memory_rw)(unsigned long addr, int numpages);

asmlinkage long (*orig_zzado)(void);

asmlinkage long hook_func(void){
	printk("[*] Hooked sys_zzado\n");
	printk("[*] PID : %lu - %s", (unsigned long)current->pid, current->comm);
	return (orig_zzado());
}

void clear_cr0_WP(unsigned long cr0){
	write_cr0(cr0 & CR0_WP); // 16bit - Write protect
	printk("[*] cr0 : %lx\n", cr0 & CR0_WP);	
	printk("[*] clear CR0.WP bit\n");	
}

void set_cr0_WP(unsigned long cr0){
	write_cr0(cr0);
	printk("[*] cr0 : %lx\n", cr0);
	printk("[*] set cr0's WP bit\n");	
}

int hook_init(void){
	unsigned long cr0 = (unsigned long)read_cr0();	
	syscall_table = (unsigned long**)0xffffffffa4600180;

	clear_cr0_WP(cr0);

	printk("[*] hooking func : %lx\n", (unsigned long)hook_func);	
	orig_zzado = (void *)syscall_table[400];	
	printk("[*] sys_zzado : %lx\n", (unsigned long)syscall_table[400]);	
	syscall_table[400] = (void *)hook_func;	
	printk("[*] hooked sys_zzado : %lx\n", (unsigned long)syscall_table[400]);	
	
	set_cr0_WP(cr0);
	return 0;
}

void hook_cleanup(void){
	unsigned long cr0 = (unsigned long)read_cr0();	
	clear_cr0_WP(cr0);
	syscall_table[400] = (void *)orig_zzado;		
	set_cr0_WP(cr0);
	printk("[*] Remove Module\n");
}

module_init(hook_init);
module_exit(hook_cleanup);
MODULE_LICENSE("GPL");
