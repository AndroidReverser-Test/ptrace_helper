/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/cred.h>
#include <taskext.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/current.h>
#include "ptrace_helper.h"


KPM_NAME("ptrace_helper");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("test");
KPM_DESCRIPTION("Ptrace Helper");


uid_t test_uid = 0;
char *test_tpid = "0";
void *proc_pid_status_addr;
void *do_task_stat_addr;
void *proc_pid_wchan_addr;


long (*simple_strtol)(const char *cp, char **endp, unsigned int base) = 0;
int (*num_to_str)(char *buf, int size, unsigned long long num, unsigned int width) = 0; //num_to_str(m->buf + m->count, 字符最大长度, num, 0);
pid_t (*__mtask_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

void after_proc_pid_status(hook_fargs4_t *args, void *udata)
{
    struct seq_file* o_seq_file;
    struct task_struct* o_task_struct;

    o_task_struct = (struct task_struct*)args->arg3;
    struct cred* cred = *(struct cred**)((uintptr_t)o_task_struct + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    if(uid != test_uid){
        return;
    }

    o_seq_file = (struct seq_file*)args->arg0;
    char *o_status_buf = o_seq_file->buf;
    char *state_start_flag = strstr(o_status_buf,"State:\t");
    char state_flag[1];
    memcpy(state_flag,state_start_flag+7,1);
    char *tpid_start_flag = strstr(o_status_buf,"TracerPid:\t");
    char *tpid_end_flag = strstr(tpid_start_flag,"\n");
    int tpid_len = tpid_end_flag -(tpid_start_flag+11);
    char tpid[tpid_len];
    memcpy(tpid,tpid_start_flag+11,tpid_len);
//    logkd("Test_log7===pid_len:%d,tpid:%s\n",tpid_len,tpid);
    int state_flag_len;
    switch (state_flag[0]) {
        case 'R':
            state_flag_len = 11;
            break;
        case 'S':
            state_flag_len=12;
            break;
        case 'D':
            state_flag_len=13;
            break;
        case 'T':
            state_flag_len=11;
            break;
        case 't':
            state_flag_len=16;
            break;
        case 'X':
            state_flag_len=8;
            break;
        case 'I':
            state_flag_len=8;
            break;
        default:
            state_flag_len=10;
            break;
    }
    if(strncmp(tpid,test_tpid,tpid_len)==0){
        return;
    }else{
        char copy_str[5000];
        int copy_str_size = 0;
        int g1=(state_start_flag-o_status_buf)+7;
        memcpy(copy_str,o_status_buf,g1);
        copy_str_size = copy_str_size + g1;
        //change state
        memcpy(copy_str+copy_str_size,"R (running)",11);
        copy_str_size = copy_str_size + 11;
        int count1 = tpid_start_flag-(o_status_buf+g1+state_flag_len);
        memcpy(copy_str+copy_str_size,o_status_buf+g1+state_flag_len,count1);
        copy_str_size = copy_str_size + count1;
        //change ptracepid
        int test_tpid_len = strlen(test_tpid);
        memcpy(copy_str+copy_str_size,tpid_start_flag,11);
        copy_str_size = copy_str_size + 11;
        memcpy(copy_str+copy_str_size,test_tpid,test_tpid_len);
        copy_str_size = copy_str_size + test_tpid_len;
        int count2 = strlen(tpid_start_flag) -11 - test_tpid_len;
        memcpy(copy_str+copy_str_size,tpid_start_flag+11+tpid_len,count2);
        copy_str_size = copy_str_size + count2;
        memcpy(o_seq_file->buf,copy_str,copy_str_size);
        o_seq_file->count=copy_str_size;
        args->arg0 = (uint64_t)o_seq_file;
        logkd("+Test-Log+ success change status\n");
    }


}


void after_do_task_stat(hook_fargs5_t *args, void *udata){
    struct seq_file* o_seq_file;
    struct task_struct* o_task_struct;
    o_task_struct = (struct task_struct*)args->arg3;
    struct cred* cred = *(struct cred**)((uintptr_t)o_task_struct + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    if(uid != test_uid){
        return;
    }

    o_seq_file = (struct seq_file*)args->arg0;
    char *o_status_buf = o_seq_file->buf;
    char *state_start_flag = strstr(o_status_buf,") ");
//    char state_flag[1];
//    memcpy(state_flag,state_start_flag+2,1);//读取到的值是错误的
//    if(strcmp(state_start_flag,"t")!=0){
//        return;
//    }else{
//        memcpy(o_seq_file->buf+(state_start_flag-o_status_buf)+2,"R",1);
//        args->arg0 = o_seq_file;
//        logkd("Test_log55:state_flag->%s\n",state_flag);
//    }
    memcpy(o_seq_file->buf+(state_start_flag-o_status_buf)+2,"R",1);
    args->arg0 = (uint64_t)o_seq_file;
//    logkd("+Test-Log+ success change stat\n");
}

void after_proc_pid_wchan(hook_fargs4_t *args, void *udata){
    struct seq_file* o_seq_file;
    struct task_struct* o_task_struct;
    o_task_struct = (struct task_struct*)args->arg3;
    struct cred* cred = *(struct cred**)((uintptr_t)o_task_struct + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    if(uid != test_uid){
        return;
    }

    o_seq_file = (struct seq_file*)args->arg0;
    char *o_status_buf = o_seq_file->buf;
    if(strcmp(o_status_buf,"ptrace_stop")==0){
        strcpy(o_seq_file->buf,"do_epoll_wait");
        o_seq_file->count=13;
        args->arg0 = (uint64_t)o_seq_file;
        logkd("+Test-Log+ success change whcan\n");
    }
}

void before_ptrace(hook_fargs4_t *args, void *udata)
{
    struct task_struct *task = current;
    struct cred* cred = *(struct cred**)((uintptr_t)task + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    if(uid != test_uid){
        return;
    }
    int request = (int)syscall_argn(args, 0);
    pid_t tpid = (pid_t)syscall_argn(args, 1);
    pid_t pid = -1;
    if (__mtask_pid_nr_ns) {
        pid = __mtask_pid_nr_ns(task, PIDTYPE_PID, 0);
    }
    logkd("+Test-Log+ pid:%d,request:%d,tpid:%d\n", pid,request,tpid);
    args->ret = -1;
    args->skip_origin = 1;
}

static long ptrace_helper_init(const char *args, const char *event, void *__user reserved)
{
    simple_strtol = (typeof(simple_strtol))kallsyms_lookup_name("simple_strtol");
    num_to_str = (typeof(num_to_str))kallsyms_lookup_name("num_to_str");
    __mtask_pid_nr_ns = (typeof(__mtask_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    proc_pid_status_addr = (void *)kallsyms_lookup_name("proc_pid_status");
    do_task_stat_addr = (void *)kallsyms_lookup_name("do_task_stat");
    proc_pid_wchan_addr = (void *)kallsyms_lookup_name("proc_pid_wchan");
    logkd("+Test-Log+ proc_pid_status_addr:%llx,do_task_stat_addr:%llx,proc_pid_wchan_addr:%llx",proc_pid_status_addr,do_task_stat_addr,proc_pid_wchan_addr);
    hook_err_t err = HOOK_NO_ERR;
    if(proc_pid_status_addr){
        err = hook_wrap4((void *)proc_pid_status_addr, NULL, after_proc_pid_status, 0);
        logkd("+Test-Log+ proc_pid_status hook err: %d\n", err);
    }
    if(do_task_stat_addr){
        err = hook_wrap5((void *)do_task_stat_addr, NULL, after_do_task_stat, 0);
        logkd("+Test-Log+ do_task_stat hook err: %d\n", err);
    }

    if(proc_pid_wchan_addr){
        err = hook_wrap4((void *)proc_pid_wchan_addr, NULL, after_proc_pid_wchan, 0);
        logkd("+Test-Log+ proc_pid_wchan hook err: %d\n", err);
    }

    err = fp_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);
    logkd("+Test-Log+ syscall ptrace hook err: %d\n", err);
    return 0;
}

static long ptrace_helper_control0(const char *args, char *__user out_msg, int outlen)
{
    char **endptr;
    if(simple_strtol){
        test_uid=simple_strtol(args,endptr,10);
    }
    test_tpid = "0";
    logkd("+Test-Log+ test_uid:%d,test_tpid:%s",test_uid,test_tpid);
    return 0;
}

static long ptrace_helper_exit(void *__user reserved)
{
    if(proc_pid_status_addr){
        unhook((void *)proc_pid_status_addr);
    }

    if(do_task_stat_addr){
        unhook((void *)do_task_stat_addr);
    }

    if(proc_pid_wchan_addr){
        unhook((void *)proc_pid_wchan_addr);
    }
    fp_unhook_syscall(__NR_ptrace, before_ptrace, 0);
    logkd("kpm ptrace_helper  exit\n");
}

KPM_INIT(ptrace_helper_init);
KPM_CTL0(ptrace_helper_control0);
KPM_EXIT(ptrace_helper_exit);