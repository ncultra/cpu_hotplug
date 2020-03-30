#include "cpu_hotplug.h"


static int __init cpu_hotplug_init(void)
{
  int ccode = 0;
  printk(KERN_DEBUG "cpu hotplug demo module\n");
  return ccode;
}

static void __exit cpu_hotplug_cleanup(void)
{
  printk(KERN_DEBUG "cpu hotplug demo unloading...\n");
}



module_init(cpu_hotplug_init);
module_exit(cpu_hotplug_cleanup);


MODULE_LICENSE(_MODULE_LICENSE);
MODULE_AUTHOR(_MODULE_AUTHOR);
MODULE_DESCRIPTION(_MODULE_INFO);
