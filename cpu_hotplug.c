#include "cpu_hotplug.h"

static int my_cpu_online(unsigned int cpu)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu %d coming online\n", cpu);
	return ccode;
}


static int my_cpu_going_offline(unsigned int cpu)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu %d going offline\n", cpu);
	return ccode;
}

int cpu_hotplug_init(void)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu hotplug demo module\n");
	ccode = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
                            "x86/demo:online",
                            my_cpu_online,
                            my_cpu_going_offline);

	printk(KERN_DEBUG "cpuhp_setup_state returned %d\n", ccode);
	return 0;
}
EXPORT_SYMBOL(cpu_hotplug_init);


void cpu_hotplug_cleanup(void)
{
	printk(KERN_DEBUG "cpu hotplug demo unloading...\n");
	cpuhp_remove_state(CPUHP_AP_ONLINE_DYN);
}
EXPORT_SYMBOL(cpu_hotplug_cleanup);

MODULE_LICENSE("GPL v2");
