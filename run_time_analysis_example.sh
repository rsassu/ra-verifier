#! /bin/bash

./run_time_analysis.sh init_t "systemd_networkd_t|gssproxy_t|auditd_t|udev_t|restorecond_t|unconfined_service_t|getty_t|systemd_tmpfiles_t|chronyd_t|sshd_t|NetworkManager_t|chronyc_t|systemd_logind_t|chkpwd_t|fsadm_t|sshd_net_t|kmod_t|ifconfig_t|lvm_t|system_dbusd_t|iptables_t|firewalld_t|dhcpc_t" "null_device_t:chr_file|devtty_t:chr_file|tty_device_t:chr_file|kernel_t:socket;init_t|init_t:fifo_file;init_t;chkpwd_t|init_t:socket;init_t|systemd_logind_inhibit_var_run_t:fifo_file;systemd_logind_t|ptmx_t:chr_file|sshd_t:socket;sshd_t;sshd_net_t" www
