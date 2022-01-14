diff --git a/Documentation/cgroup-legacy/cgroups.txt b/Documentation/cgroup-legacy/cgroups.txt
index 2d984e20783b..c6256ae9885b 100644
--- a/Documentation/cgroup-legacy/cgroups.txt
+++ b/Documentation/cgroup-legacy/cgroups.txt
@@ -578,15 +578,6 @@ is completely unused; @cgrp->parent is still valid. (Note - can also
 be called for a newly-created cgroup if an error occurs after this
 subsystem's create() method has been called for the new cgroup).
 
-int allow_attach(struct cgroup *cgrp, struct cgroup_taskset *tset)
-(cgroup_mutex held by caller)
-
-Called prior to moving a task into a cgroup; if the subsystem
-returns an error, this will abort the attach operation.  Used
-to extend the permission checks - if all subsystems in a cgroup
-return 0, the attach will be allowed to proceed, even if the
-default permission check (root or same user) fails.
-
 int can_attach(struct cgroup *cgrp, struct cgroup_taskset *tset)
 (cgroup_mutex held by caller)
 
diff --git a/Documentation/sysctl/kernel.txt b/Documentation/sysctl/kernel.txt
index 512060d8ad76..6475fa234065 100644
--- a/Documentation/sysctl/kernel.txt
+++ b/Documentation/sysctl/kernel.txt
@@ -62,7 +62,6 @@ show up in /proc/sys/kernel:
 - panic_on_warn
 - perf_cpu_time_max_percent
 - perf_event_paranoid
-- perf_event_max_stack
 - pid_max
 - powersave-nap               [ PPC only ]
 - printk
@@ -666,19 +665,6 @@ CONFIG_SECURITY_PERF_EVENTS_RESTRICT is set, or 1 otherwise.
 
 ==============================================================
 
-perf_event_max_stack:
-
-Controls maximum number of stack frames to copy for (attr.sample_type &
-PERF_SAMPLE_CALLCHAIN) configured events, for instance, when using
-'perf record -g' or 'perf trace --call-graph fp'.
-
-This can only be done when no events are in use that have callchains
-enabled, otherwise writing to this file will return -EBUSY.
-
-The default value is 127.
-
-==============================================================
-
 pid_max:
 
 PID allocation wrap value.  When the kernel's next PID value
diff --git a/Documentation/sysctl/net.txt b/Documentation/sysctl/net.txt
index 4d5e3b0cab3f..809ab6efcc74 100644
--- a/Documentation/sysctl/net.txt
+++ b/Documentation/sysctl/net.txt
@@ -43,25 +43,6 @@ Values :
 	1 - enable the JIT
 	2 - enable the JIT and ask the compiler to emit traces on kernel log.
 
-bpf_jit_harden
---------------
-
-This enables hardening for the Berkeley Packet Filter Just in Time compiler.
-Supported are eBPF JIT backends. Enabling hardening trades off performance,
-but can mitigate JIT spraying.
-Values :
-	0 - disable JIT hardening (default value)
-	1 - enable JIT hardening for unprivileged users only
-	2 - enable JIT hardening for all users
-
-bpf_jit_limit
--------------
-
-This enforces a global limit for memory allocations to the BPF JIT
-compiler in order to reject unprivileged JIT requests once it has
-been surpassed. bpf_jit_limit contains the value of the global limit
-in bytes.
-
 dev_weight
 --------------
 
diff --git a/arch/alpha/include/uapi/asm/socket.h b/arch/alpha/include/uapi/asm/socket.h
index c5fb9e6bc3a5..9a20821b111c 100644
--- a/arch/alpha/include/uapi/asm/socket.h
+++ b/arch/alpha/include/uapi/asm/socket.h
@@ -92,7 +92,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _UAPI_ASM_SOCKET_H */
diff --git a/arch/arc/kernel/perf_event.c b/arch/arc/kernel/perf_event.c
index b725efd36af3..71fcbccc8f98 100644
--- a/arch/arc/kernel/perf_event.c
+++ b/arch/arc/kernel/perf_event.c
@@ -48,7 +48,7 @@ struct arc_callchain_trace {
 static int callchain_trace(unsigned int addr, void *data)
 {
 	struct arc_callchain_trace *ctrl = data;
-	struct perf_callchain_entry_ctx *entry = ctrl->perf_stuff;
+	struct perf_callchain_entry *entry = ctrl->perf_stuff;
 	perf_callchain_store(entry, addr);
 
 	if (ctrl->depth++ < 3)
@@ -58,7 +58,7 @@ static int callchain_trace(unsigned int addr, void *data)
 }
 
 void
-perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	struct arc_callchain_trace ctrl = {
 		.depth = 0,
@@ -69,7 +69,7 @@ perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *re
 }
 
 void
-perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	/*
 	 * User stack can't be unwound trivially with kernel dwarf unwinder
diff --git a/arch/arm/kernel/hw_breakpoint.c b/arch/arm/kernel/hw_breakpoint.c
index 9bc6840ad229..78c6be1b2714 100644
--- a/arch/arm/kernel/hw_breakpoint.c
+++ b/arch/arm/kernel/hw_breakpoint.c
@@ -631,7 +631,7 @@ int arch_validate_hwbkpt_settings(struct perf_event *bp)
 	info->address &= ~alignment_mask;
 	info->ctrl.len <<= offset;
 
-	if (is_default_overflow_handler(bp)) {
+	if (!bp->overflow_handler) {
 		/*
 		 * Mismatch breakpoints are required for single-stepping
 		 * breakpoints.
@@ -760,7 +760,7 @@ static void watchpoint_handler(unsigned long addr, unsigned int fsr,
 		 * can't help us with this.
 		 */
 		if (watchpoint_fault_on_uaccess(regs, info))
-			enable_single_step(wp, instruction_pointer(regs));
+			goto step;
 
 		perf_bp_event(wp, regs);
 
@@ -769,8 +769,11 @@ static void watchpoint_handler(unsigned long addr, unsigned int fsr,
 		 * Otherwise, insert a temporary mismatch breakpoint so that
 		 * we can single-step over the watchpoint trigger.
 		 */
-		if (is_default_overflow_handler(wp))
-			enable_single_step(wp, instruction_pointer(regs));
+		if (wp->overflow_handler)
+			goto unlock;
+
+step:
+		enable_single_step(wp, instruction_pointer(regs));
 unlock:
 		rcu_read_unlock();
 	}
diff --git a/arch/arm/kernel/perf_callchain.c b/arch/arm/kernel/perf_callchain.c
index bc552e813e7b..4e02ae5950ff 100644
--- a/arch/arm/kernel/perf_callchain.c
+++ b/arch/arm/kernel/perf_callchain.c
@@ -31,7 +31,7 @@ struct frame_tail {
  */
 static struct frame_tail __user *
 user_backtrace(struct frame_tail __user *tail,
-	       struct perf_callchain_entry_ctx *entry)
+	       struct perf_callchain_entry *entry)
 {
 	struct frame_tail buftail;
 	unsigned long err;
@@ -59,7 +59,7 @@ user_backtrace(struct frame_tail __user *tail,
 }
 
 void
-perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	struct frame_tail __user *tail;
 
@@ -75,7 +75,7 @@ perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs
 
 	tail = (struct frame_tail __user *)regs->ARM_fp - 1;
 
-	while ((entry->entry->nr < entry->max_stack) &&
+	while ((entry->nr < PERF_MAX_STACK_DEPTH) &&
 	       tail && !((unsigned long)tail & 0x3))
 		tail = user_backtrace(tail, entry);
 }
@@ -89,13 +89,13 @@ static int
 callchain_trace(struct stackframe *fr,
 		void *data)
 {
-	struct perf_callchain_entry_ctx *entry = data;
+	struct perf_callchain_entry *entry = data;
 	perf_callchain_store(entry, fr->pc);
 	return 0;
 }
 
 void
-perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	struct stackframe fr;
 
diff --git a/arch/arm/net/bpf_jit_32.c b/arch/arm/net/bpf_jit_32.c
index 7fd448b23b94..93d0b6d0b63e 100644
--- a/arch/arm/net/bpf_jit_32.c
+++ b/arch/arm/net/bpf_jit_32.c
@@ -72,6 +72,8 @@ struct jit_ctx {
 #endif
 };
 
+int bpf_jit_enable __read_mostly;
+
 static inline int call_neg_helper(struct sk_buff *skb, int offset, void *ret,
 		      unsigned int size)
 {
diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 10f91864c043..56ba6a13bfd6 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -63,6 +63,7 @@ config ARM64
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_BPF_JIT
+	select HAVE_EBPF_JIT
 	select HAVE_C_RECORDMCOUNT
 	select HAVE_CC_STACKPROTECTOR
 	select HAVE_CMPXCHG_DOUBLE
diff --git a/arch/arm64/configs/lavender-perf_defconfig b/arch/arm64/configs/lavender-perf_defconfig
index 5b929b368a31..cbff90913c0d 100644
--- a/arch/arm64/configs/lavender-perf_defconfig
+++ b/arch/arm64/configs/lavender-perf_defconfig
@@ -153,7 +153,7 @@ CONFIG_CGROUP_SCHED=y
 CONFIG_FAIR_GROUP_SCHED=y
 # CONFIG_CFS_BANDWIDTH is not set
 CONFIG_RT_GROUP_SCHED=y
-CONFIG_BLK_CGROUP=y
+# CONFIG_BLK_CGROUP is not set
 # CONFIG_DEBUG_BLK_CGROUP is not set
 CONFIG_CGROUP_BPF=y
 CONFIG_SOCK_CGROUP_DATA=y
@@ -914,10 +914,10 @@ CONFIG_NETFILTER_XT_MATCH_MARK=y
 CONFIG_NETFILTER_XT_MATCH_MULTIPORT=y
 # CONFIG_NETFILTER_XT_MATCH_NFACCT is not set
 # CONFIG_NETFILTER_XT_MATCH_OSF is not set
-CONFIG_NETFILTER_XT_MATCH_OWNER=y
+# CONFIG_NETFILTER_XT_MATCH_OWNER is not set
 CONFIG_NETFILTER_XT_MATCH_POLICY=y
 CONFIG_NETFILTER_XT_MATCH_PKTTYPE=y
-# CONFIG_NETFILTER_XT_MATCH_QTAGUID is not set
+CONFIG_NETFILTER_XT_MATCH_QTAGUID=y
 CONFIG_NETFILTER_XT_MATCH_QUOTA=y
 CONFIG_NETFILTER_XT_MATCH_QUOTA2=y
 # CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG is not set
diff --git a/arch/arm64/kernel/hw_breakpoint.c b/arch/arm64/kernel/hw_breakpoint.c
index 3530541b3f5b..bef4b659d816 100644
--- a/arch/arm64/kernel/hw_breakpoint.c
+++ b/arch/arm64/kernel/hw_breakpoint.c
@@ -662,7 +662,7 @@ static int breakpoint_handler(unsigned long unused, unsigned int esr,
 		perf_bp_event(bp, regs);
 
 		/* Do we need to handle the stepping? */
-		if (is_default_overflow_handler(bp))
+		if (!bp->overflow_handler)
 			step = 1;
 unlock:
 		rcu_read_unlock();
@@ -788,7 +788,7 @@ static int watchpoint_handler(unsigned long addr, unsigned int esr,
 		perf_bp_event(wp, regs);
 
 		/* Do we need to handle the stepping? */
-		if (is_default_overflow_handler(wp))
+		if (!wp->overflow_handler)
 			step = 1;
 	}
 	if (min_dist > 0 && min_dist != -1) {
diff --git a/arch/arm64/kernel/perf_callchain.c b/arch/arm64/kernel/perf_callchain.c
index 0d60150057cf..ff4665462a02 100644
--- a/arch/arm64/kernel/perf_callchain.c
+++ b/arch/arm64/kernel/perf_callchain.c
@@ -31,7 +31,7 @@ struct frame_tail {
  */
 static struct frame_tail __user *
 user_backtrace(struct frame_tail __user *tail,
-	       struct perf_callchain_entry_ctx *entry)
+	       struct perf_callchain_entry *entry)
 {
 	struct frame_tail buftail;
 	unsigned long err;
@@ -76,7 +76,7 @@ struct compat_frame_tail {
 
 static struct compat_frame_tail __user *
 compat_user_backtrace(struct compat_frame_tail __user *tail,
-		      struct perf_callchain_entry_ctx *entry)
+		      struct perf_callchain_entry *entry)
 {
 	struct compat_frame_tail buftail;
 	unsigned long err;
@@ -106,7 +106,7 @@ compat_user_backtrace(struct compat_frame_tail __user *tail,
 }
 #endif /* CONFIG_COMPAT */
 
-void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_user(struct perf_callchain_entry *entry,
 			 struct pt_regs *regs)
 {
 	if (perf_guest_cbs && perf_guest_cbs->is_in_guest()) {
@@ -122,7 +122,7 @@ void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
 
 		tail = (struct frame_tail __user *)regs->regs[29];
 
-		while (entry->entry->nr < entry->max_stack &&
+		while (entry->nr < PERF_MAX_STACK_DEPTH &&
 		       tail && !((unsigned long)tail & 0xf))
 			tail = user_backtrace(tail, entry);
 	} else {
@@ -132,7 +132,7 @@ void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
 
 		tail = (struct compat_frame_tail __user *)regs->compat_fp - 1;
 
-		while ((entry->entry->nr < entry->max_stack) &&
+		while ((entry->nr < PERF_MAX_STACK_DEPTH) &&
 			tail && !((unsigned long)tail & 0x3))
 			tail = compat_user_backtrace(tail, entry);
 #endif
@@ -146,12 +146,12 @@ void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
  */
 static int callchain_trace(struct stackframe *frame, void *data)
 {
-	struct perf_callchain_entry_ctx *entry = data;
+	struct perf_callchain_entry *entry = data;
 	perf_callchain_store(entry, frame->pc);
 	return 0;
 }
 
-void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_kernel(struct perf_callchain_entry *entry,
 			   struct pt_regs *regs)
 {
 	struct stackframe frame;
diff --git a/arch/arm64/net/bpf_jit.h b/arch/arm64/net/bpf_jit.h
index 7c16e547ccb2..aee5637ea436 100644
--- a/arch/arm64/net/bpf_jit.h
+++ b/arch/arm64/net/bpf_jit.h
@@ -1,7 +1,7 @@
 /*
  * BPF JIT compiler for ARM64
  *
- * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
+ * Copyright (C) 2014-2015 Zi Shen Lim <zlim.lnx@gmail.com>
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -55,7 +55,6 @@
 #define A64_BL(imm26) A64_BRANCH((imm26) << 2, LINK)
 
 /* Unconditional branch (register) */
-#define A64_BR(Rn)  aarch64_insn_gen_branch_reg(Rn, AARCH64_INSN_BRANCH_NOLINK)
 #define A64_BLR(Rn) aarch64_insn_gen_branch_reg(Rn, AARCH64_INSN_BRANCH_LINK)
 #define A64_RET(Rn) aarch64_insn_gen_branch_reg(Rn, AARCH64_INSN_BRANCH_RETURN)
 
diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
index cf738f5b6cba..fb413052e10a 100644
--- a/arch/arm64/net/bpf_jit_comp.c
+++ b/arch/arm64/net/bpf_jit_comp.c
@@ -1,7 +1,7 @@
 /*
  * BPF JIT compiler for ARM64
  *
- * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
+ * Copyright (C) 2014-2015 Zi Shen Lim <zlim.lnx@gmail.com>
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
@@ -18,7 +18,6 @@
 
 #define pr_fmt(fmt) "bpf_jit: " fmt
 
-#include <linux/bpf.h>
 #include <linux/filter.h>
 #include <linux/printk.h>
 #include <linux/skbuff.h>
@@ -30,9 +29,10 @@
 
 #include "bpf_jit.h"
 
-#define TMP_REG_1 (MAX_BPF_JIT_REG + 0)
-#define TMP_REG_2 (MAX_BPF_JIT_REG + 1)
-#define TCALL_CNT (MAX_BPF_JIT_REG + 2)
+int bpf_jit_enable __read_mostly;
+
+#define TMP_REG_1 (MAX_BPF_REG + 0)
+#define TMP_REG_2 (MAX_BPF_REG + 1)
 
 /* Map BPF registers to A64 registers */
 static const int bpf2a64[] = {
@@ -51,18 +51,15 @@ static const int bpf2a64[] = {
 	[BPF_REG_9] = A64_R(22),
 	/* read-only frame pointer to access stack */
 	[BPF_REG_FP] = A64_R(25),
-	/* temporary registers for internal BPF JIT */
-	[TMP_REG_1] = A64_R(10),
-	[TMP_REG_2] = A64_R(11),
-	/* tail_call_cnt */
-	[TCALL_CNT] = A64_R(26),
-	/* temporary register for blinding constants */
-	[BPF_REG_AX] = A64_R(9),
+	/* temporary register for internal BPF JIT */
+	[TMP_REG_1] = A64_R(23),
+	[TMP_REG_2] = A64_R(24),
 };
 
 struct jit_ctx {
 	const struct bpf_prog *prog;
 	int idx;
+	int tmp_used;
 	int epilogue_offset;
 	int *offset;
 	u32 *image;
@@ -148,18 +145,17 @@ static inline int epilogue_offset(const struct jit_ctx *ctx)
 
 #define STACK_SIZE STACK_ALIGN(_STACK_SIZE)
 
-#define PROLOGUE_OFFSET 8
-
-static int build_prologue(struct jit_ctx *ctx)
+static void build_prologue(struct jit_ctx *ctx)
 {
 	const u8 r6 = bpf2a64[BPF_REG_6];
 	const u8 r7 = bpf2a64[BPF_REG_7];
 	const u8 r8 = bpf2a64[BPF_REG_8];
 	const u8 r9 = bpf2a64[BPF_REG_9];
 	const u8 fp = bpf2a64[BPF_REG_FP];
-	const u8 tcc = bpf2a64[TCALL_CNT];
-	const int idx0 = ctx->idx;
-	int cur_offset;
+	const u8 ra = bpf2a64[BPF_REG_A];
+	const u8 rx = bpf2a64[BPF_REG_X];
+	const u8 tmp1 = bpf2a64[TMP_REG_1];
+	const u8 tmp2 = bpf2a64[TMP_REG_2];
 
 	/*
 	 * BPF prog stack layout
@@ -169,7 +165,9 @@ static int build_prologue(struct jit_ctx *ctx)
 	 *                        |FP/LR|
 	 * current A64_FP =>  -16:+-----+
 	 *                        | ... | callee saved registers
-	 * BPF fp register => -64:+-----+ <= (BPF_FP)
+	 *                        +-----+
+	 *                        |     | x25/x26
+	 * BPF fp register => -80:+-----+ <= (BPF_FP)
 	 *                        |     |
 	 *                        | ... | BPF prog stack
 	 *                        |     |
@@ -188,90 +186,24 @@ static int build_prologue(struct jit_ctx *ctx)
 	emit(A64_PUSH(A64_FP, A64_LR, A64_SP), ctx);
 	emit(A64_MOV(1, A64_FP, A64_SP), ctx);
 
-	/* Save callee-saved registers */
+	/* Save callee-saved register */
 	emit(A64_PUSH(r6, r7, A64_SP), ctx);
 	emit(A64_PUSH(r8, r9, A64_SP), ctx);
-	emit(A64_PUSH(fp, tcc, A64_SP), ctx);
+	if (ctx->tmp_used)
+		emit(A64_PUSH(tmp1, tmp2, A64_SP), ctx);
 
-	/* Set up BPF prog stack base register */
-	emit(A64_MOV(1, fp, A64_SP), ctx);
+	/* Save fp (x25) and x26. SP requires 16 bytes alignment */
+	emit(A64_PUSH(fp, A64_R(26), A64_SP), ctx);
 
-	/* Initialize tail_call_cnt */
-	emit(A64_MOVZ(1, tcc, 0, 0), ctx);
+	/* Set up BPF prog stack base register (x25) */
+	emit(A64_MOV(1, fp, A64_SP), ctx);
 
 	/* Set up function call stack */
 	emit(A64_SUB_I(1, A64_SP, A64_SP, STACK_SIZE), ctx);
 
-	cur_offset = ctx->idx - idx0;
-	if (cur_offset != PROLOGUE_OFFSET) {
-		pr_err_once("PROLOGUE_OFFSET = %d, expected %d!\n",
-			    cur_offset, PROLOGUE_OFFSET);
-		return -1;
-	}
-	return 0;
-}
-
-static int out_offset = -1; /* initialized on the first pass of build_body() */
-static int emit_bpf_tail_call(struct jit_ctx *ctx)
-{
-	/* bpf_tail_call(void *prog_ctx, struct bpf_array *array, u64 index) */
-	const u8 r2 = bpf2a64[BPF_REG_2];
-	const u8 r3 = bpf2a64[BPF_REG_3];
-
-	const u8 tmp = bpf2a64[TMP_REG_1];
-	const u8 prg = bpf2a64[TMP_REG_2];
-	const u8 tcc = bpf2a64[TCALL_CNT];
-	const int idx0 = ctx->idx;
-#define cur_offset (ctx->idx - idx0)
-#define jmp_offset (out_offset - (cur_offset))
-	size_t off;
-
-	/* if (index >= array->map.max_entries)
-	 *     goto out;
-	 */
-	off = offsetof(struct bpf_array, map.max_entries);
-	emit_a64_mov_i64(tmp, off, ctx);
-	emit(A64_LDR32(tmp, r2, tmp), ctx);
-	emit(A64_CMP(0, r3, tmp), ctx);
-	emit(A64_B_(A64_COND_GE, jmp_offset), ctx);
-
-	/* if (tail_call_cnt > MAX_TAIL_CALL_CNT)
-	 *     goto out;
-	 * tail_call_cnt++;
-	 */
-	emit_a64_mov_i64(tmp, MAX_TAIL_CALL_CNT, ctx);
-	emit(A64_CMP(1, tcc, tmp), ctx);
-	emit(A64_B_(A64_COND_GT, jmp_offset), ctx);
-	emit(A64_ADD_I(1, tcc, tcc, 1), ctx);
-
-	/* prog = array->ptrs[index];
-	 * if (prog == NULL)
-	 *     goto out;
-	 */
-	off = offsetof(struct bpf_array, ptrs);
-	emit_a64_mov_i64(tmp, off, ctx);
-	emit(A64_LDR64(tmp, r2, tmp), ctx);
-	emit(A64_LDR64(prg, tmp, r3), ctx);
-	emit(A64_CBZ(1, prg, jmp_offset), ctx);
-
-	/* goto *(prog->bpf_func + prologue_size); */
-	off = offsetof(struct bpf_prog, bpf_func);
-	emit_a64_mov_i64(tmp, off, ctx);
-	emit(A64_LDR64(tmp, prg, tmp), ctx);
-	emit(A64_ADD_I(1, tmp, tmp, sizeof(u32) * PROLOGUE_OFFSET), ctx);
-	emit(A64_BR(tmp), ctx);
-
-	/* out: */
-	if (out_offset == -1)
-		out_offset = cur_offset;
-	if (cur_offset != out_offset) {
-		pr_err_once("tail_call out_offset = %d, expected %d!\n",
-			    cur_offset, out_offset);
-		return -1;
-	}
-	return 0;
-#undef cur_offset
-#undef jmp_offset
+	/* Clear registers A and X */
+	emit_a64_mov_i64(ra, 0, ctx);
+	emit_a64_mov_i64(rx, 0, ctx);
 }
 
 static void build_epilogue(struct jit_ctx *ctx)
@@ -282,6 +214,8 @@ static void build_epilogue(struct jit_ctx *ctx)
 	const u8 r8 = bpf2a64[BPF_REG_8];
 	const u8 r9 = bpf2a64[BPF_REG_9];
 	const u8 fp = bpf2a64[BPF_REG_FP];
+	const u8 tmp1 = bpf2a64[TMP_REG_1];
+	const u8 tmp2 = bpf2a64[TMP_REG_2];
 
 	/* We're done with BPF stack */
 	emit(A64_ADD_I(1, A64_SP, A64_SP, STACK_SIZE), ctx);
@@ -290,6 +224,8 @@ static void build_epilogue(struct jit_ctx *ctx)
 	emit(A64_POP(fp, A64_R(26), A64_SP), ctx);
 
 	/* Restore callee-saved register */
+	if (ctx->tmp_used)
+		emit(A64_POP(tmp1, tmp2, A64_SP), ctx);
 	emit(A64_POP(r8, r9, A64_SP), ctx);
 	emit(A64_POP(r6, r7, A64_SP), ctx);
 
@@ -385,6 +321,7 @@ static int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx)
 			emit(A64_UDIV(is64, dst, dst, src), ctx);
 			break;
 		case BPF_MOD:
+			ctx->tmp_used = 1;
 			emit(A64_UDIV(is64, tmp, dst, src), ctx);
 			emit(A64_MUL(is64, tmp, tmp, src), ctx);
 			emit(A64_SUB(is64, dst, dst, tmp), ctx);
@@ -457,41 +394,49 @@ emit_bswap_uxt:
 	/* dst = dst OP imm */
 	case BPF_ALU | BPF_ADD | BPF_K:
 	case BPF_ALU64 | BPF_ADD | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_ADD(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_SUB | BPF_K:
 	case BPF_ALU64 | BPF_SUB | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_SUB(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_AND | BPF_K:
 	case BPF_ALU64 | BPF_AND | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_AND(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_OR | BPF_K:
 	case BPF_ALU64 | BPF_OR | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_ORR(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_XOR | BPF_K:
 	case BPF_ALU64 | BPF_XOR | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_EOR(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_MUL | BPF_K:
 	case BPF_ALU64 | BPF_MUL | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_MUL(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_DIV | BPF_K:
 	case BPF_ALU64 | BPF_DIV | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp, imm, ctx);
 		emit(A64_UDIV(is64, dst, dst, tmp), ctx);
 		break;
 	case BPF_ALU | BPF_MOD | BPF_K:
 	case BPF_ALU64 | BPF_MOD | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(is64, tmp2, imm, ctx);
 		emit(A64_UDIV(is64, tmp, dst, tmp2), ctx);
 		emit(A64_MUL(is64, tmp, tmp, tmp2), ctx);
@@ -562,10 +507,12 @@ emit_cond_jmp:
 	case BPF_JMP | BPF_JNE | BPF_K:
 	case BPF_JMP | BPF_JSGT | BPF_K:
 	case BPF_JMP | BPF_JSGE | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(1, tmp, imm, ctx);
 		emit(A64_CMP(1, dst, tmp), ctx);
 		goto emit_cond_jmp;
 	case BPF_JMP | BPF_JSET | BPF_K:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(1, tmp, imm, ctx);
 		emit(A64_TST(1, dst, tmp), ctx);
 		goto emit_cond_jmp;
@@ -575,6 +522,7 @@ emit_cond_jmp:
 		const u8 r0 = bpf2a64[BPF_REG_0];
 		const u64 func = (u64)__bpf_call_base + imm;
 
+		ctx->tmp_used = 1;
 		emit_a64_mov_i64(tmp, func, ctx);
 		emit(A64_PUSH(A64_FP, A64_LR, A64_SP), ctx);
 		emit(A64_MOV(1, A64_FP, A64_SP), ctx);
@@ -583,11 +531,6 @@ emit_cond_jmp:
 		emit(A64_POP(A64_FP, A64_LR, A64_SP), ctx);
 		break;
 	}
-	/* tail call */
-	case BPF_JMP | BPF_CALL | BPF_X:
-		if (emit_bpf_tail_call(ctx))
-			return -EFAULT;
-		break;
 	/* function return */
 	case BPF_JMP | BPF_EXIT:
 		/* Optimization: when last instruction is EXIT,
@@ -625,6 +568,7 @@ emit_cond_jmp:
 	case BPF_LDX | BPF_MEM | BPF_H:
 	case BPF_LDX | BPF_MEM | BPF_B:
 	case BPF_LDX | BPF_MEM | BPF_DW:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(1, tmp, off, ctx);
 		switch (BPF_SIZE(code)) {
 		case BPF_W:
@@ -648,6 +592,7 @@ emit_cond_jmp:
 	case BPF_ST | BPF_MEM | BPF_B:
 	case BPF_ST | BPF_MEM | BPF_DW:
 		/* Load imm to a register then store it */
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(1, tmp2, off, ctx);
 		emit_a64_mov_i(1, tmp, imm, ctx);
 		switch (BPF_SIZE(code)) {
@@ -671,6 +616,7 @@ emit_cond_jmp:
 	case BPF_STX | BPF_MEM | BPF_H:
 	case BPF_STX | BPF_MEM | BPF_B:
 	case BPF_STX | BPF_MEM | BPF_DW:
+		ctx->tmp_used = 1;
 		emit_a64_mov_i(1, tmp, off, ctx);
 		switch (BPF_SIZE(code)) {
 		case BPF_W:
@@ -798,20 +744,6 @@ static int build_body(struct jit_ctx *ctx)
 	return 0;
 }
 
-static int validate_code(struct jit_ctx *ctx)
-{
-	int i;
-
-	for (i = 0; i < ctx->idx; i++) {
-		u32 a64_insn = le32_to_cpu(ctx->image[i]);
-
-		if (a64_insn == AARCH64_BREAK_FAULT)
-			return -1;
-	}
-
-	return 0;
-}
-
 static inline void bpf_flush_icache(void *start, void *end)
 {
 	flush_icache_range((unsigned long)start, (unsigned long)end);
@@ -822,50 +754,33 @@ void bpf_jit_compile(struct bpf_prog *prog)
 	/* Nothing to do here. We support Internal BPF. */
 }
 
-struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
+void bpf_int_jit_compile(struct bpf_prog *prog)
 {
-	struct bpf_prog *tmp, *orig_prog = prog;
 	struct bpf_binary_header *header;
-	bool tmp_blinded = false;
 	struct jit_ctx ctx;
 	int image_size;
 	u8 *image_ptr;
 
 	if (!bpf_jit_enable)
-		return orig_prog;
+		return;
 
-	tmp = bpf_jit_blind_constants(prog);
-	/* If blinding was requested and we failed during blinding,
-	 * we must fall back to the interpreter.
-	 */
-	if (IS_ERR(tmp))
-		return orig_prog;
-	if (tmp != prog) {
-		tmp_blinded = true;
-		prog = tmp;
-	}
+	if (!prog || !prog->len)
+		return;
 
 	memset(&ctx, 0, sizeof(ctx));
 	ctx.prog = prog;
 
 	ctx.offset = kcalloc(prog->len, sizeof(int), GFP_KERNEL);
-	if (ctx.offset == NULL) {
-		prog = orig_prog;
-		goto out;
-	}
+	if (ctx.offset == NULL)
+		return;
 
 	/* 1. Initial fake pass to compute ctx->idx. */
 
-	/* Fake pass to fill in ctx->offset. */
-	if (build_body(&ctx)) {
-		prog = orig_prog;
-		goto out_off;
-	}
+	/* Fake pass to fill in ctx->offset and ctx->tmp_used. */
+	if (build_body(&ctx))
+		goto out;
 
-	if (build_prologue(&ctx)) {
-		prog = orig_prog;
-		goto out_off;
-	}
+	build_prologue(&ctx);
 
 	ctx.epilogue_offset = ctx.idx;
 	build_epilogue(&ctx);
@@ -874,10 +789,8 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 	image_size = sizeof(u32) * ctx.idx;
 	header = bpf_jit_binary_alloc(image_size, &image_ptr,
 				      sizeof(u32), jit_fill_hole);
-	if (header == NULL) {
-		prog = orig_prog;
-		goto out_off;
-	}
+	if (header == NULL)
+		goto out;
 
 	/* 2. Now, the actual pass. */
 
@@ -888,19 +801,11 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 
 	if (build_body(&ctx)) {
 		bpf_jit_binary_free(header);
-		prog = orig_prog;
-		goto out_off;
+		goto out;
 	}
 
 	build_epilogue(&ctx);
 
-	/* 3. Extra pass to validate JITed code. */
-	if (validate_code(&ctx)) {
-		bpf_jit_binary_free(header);
-		prog = orig_prog;
-		goto out_off;
-	}
-
 	/* And we're done. */
 	if (bpf_jit_enable > 1)
 		bpf_jit_dump(prog->len, image_size, 2, ctx.image);
@@ -910,14 +815,8 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 	set_memory_ro((unsigned long)header, header->pages);
 	prog->bpf_func = (void *)ctx.image;
 	prog->jited = 1;
-
-out_off:
-	kfree(ctx.offset);
 out:
-	if (tmp_blinded)
-		bpf_jit_prog_release_other(prog, prog == orig_prog ?
-					   tmp : orig_prog);
-	return prog;
+	kfree(ctx.offset);
 }
 
 void bpf_jit_free(struct bpf_prog *prog)
diff --git a/arch/avr32/include/uapi/asm/socket.h b/arch/avr32/include/uapi/asm/socket.h
index 9de0796240a0..2b65ed6b277c 100644
--- a/arch/avr32/include/uapi/asm/socket.h
+++ b/arch/avr32/include/uapi/asm/socket.h
@@ -85,7 +85,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _UAPI__ASM_AVR32_SOCKET_H */
diff --git a/arch/frv/include/uapi/asm/socket.h b/arch/frv/include/uapi/asm/socket.h
index f02e4849ae83..4823ad125578 100644
--- a/arch/frv/include/uapi/asm/socket.h
+++ b/arch/frv/include/uapi/asm/socket.h
@@ -85,8 +85,5 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _ASM_SOCKET_H */
 
diff --git a/arch/ia64/include/uapi/asm/socket.h b/arch/ia64/include/uapi/asm/socket.h
index bce29166de1b..59be3d87f86d 100644
--- a/arch/ia64/include/uapi/asm/socket.h
+++ b/arch/ia64/include/uapi/asm/socket.h
@@ -94,7 +94,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _ASM_IA64_SOCKET_H */
diff --git a/arch/m32r/include/uapi/asm/socket.h b/arch/m32r/include/uapi/asm/socket.h
index 14aa4a6bccf1..7bc4cb273856 100644
--- a/arch/m32r/include/uapi/asm/socket.h
+++ b/arch/m32r/include/uapi/asm/socket.h
@@ -85,7 +85,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _ASM_M32R_SOCKET_H */
diff --git a/arch/metag/kernel/perf_callchain.c b/arch/metag/kernel/perf_callchain.c
index b3261a98b15b..315633461a94 100644
--- a/arch/metag/kernel/perf_callchain.c
+++ b/arch/metag/kernel/perf_callchain.c
@@ -29,7 +29,7 @@ static bool is_valid_call(unsigned long calladdr)
 
 static struct metag_frame __user *
 user_backtrace(struct metag_frame __user *user_frame,
-	       struct perf_callchain_entry_ctx *entry)
+	       struct perf_callchain_entry *entry)
 {
 	struct metag_frame frame;
 	unsigned long calladdr;
@@ -56,7 +56,7 @@ user_backtrace(struct metag_frame __user *user_frame,
 }
 
 void
-perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	unsigned long sp = regs->ctx.AX[0].U0;
 	struct metag_frame __user *frame;
@@ -65,7 +65,7 @@ perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs
 
 	--frame;
 
-	while ((entry->entry->nr < entry->max_stack) && frame)
+	while ((entry->nr < PERF_MAX_STACK_DEPTH) && frame)
 		frame = user_backtrace(frame, entry);
 }
 
@@ -78,13 +78,13 @@ static int
 callchain_trace(struct stackframe *fr,
 		void *data)
 {
-	struct perf_callchain_entry_ctx *entry = data;
+	struct perf_callchain_entry *entry = data;
 	perf_callchain_store(entry, fr->pc);
 	return 0;
 }
 
 void
-perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	struct stackframe fr;
 
diff --git a/arch/mips/include/uapi/asm/socket.h b/arch/mips/include/uapi/asm/socket.h
index 5910fe294e93..dec3c850f36b 100644
--- a/arch/mips/include/uapi/asm/socket.h
+++ b/arch/mips/include/uapi/asm/socket.h
@@ -103,7 +103,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _UAPI_ASM_SOCKET_H */
diff --git a/arch/mips/kernel/perf_event.c b/arch/mips/kernel/perf_event.c
index 22395c7d7030..c1cf9c6c3f77 100644
--- a/arch/mips/kernel/perf_event.c
+++ b/arch/mips/kernel/perf_event.c
@@ -25,8 +25,8 @@
  * the user stack callchains, we will add it here.
  */
 
-static void save_raw_perf_callchain(struct perf_callchain_entry_ctx *entry,
-				    unsigned long reg29)
+static void save_raw_perf_callchain(struct perf_callchain_entry *entry,
+	unsigned long reg29)
 {
 	unsigned long *sp = (unsigned long *)reg29;
 	unsigned long addr;
@@ -35,14 +35,14 @@ static void save_raw_perf_callchain(struct perf_callchain_entry_ctx *entry,
 		addr = *sp++;
 		if (__kernel_text_address(addr)) {
 			perf_callchain_store(entry, addr);
-			if (entry->entry->nr >= entry->max_stack)
+			if (entry->nr >= PERF_MAX_STACK_DEPTH)
 				break;
 		}
 	}
 }
 
-void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
-			   struct pt_regs *regs)
+void perf_callchain_kernel(struct perf_callchain_entry *entry,
+		      struct pt_regs *regs)
 {
 	unsigned long sp = regs->regs[29];
 #ifdef CONFIG_KALLSYMS
@@ -59,7 +59,7 @@ void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
 	}
 	do {
 		perf_callchain_store(entry, pc);
-		if (entry->entry->nr >= entry->max_stack)
+		if (entry->nr >= PERF_MAX_STACK_DEPTH)
 			break;
 		pc = unwind_stack(current, &sp, pc, &ra);
 	} while (pc);
diff --git a/arch/mips/net/bpf_jit.c b/arch/mips/net/bpf_jit.c
index 08bf4f56c3b4..742daf8351b9 100644
--- a/arch/mips/net/bpf_jit.c
+++ b/arch/mips/net/bpf_jit.c
@@ -1195,6 +1195,8 @@ jmp_cmp:
 	return 0;
 }
 
+int bpf_jit_enable __read_mostly;
+
 void bpf_jit_compile(struct bpf_prog *fp)
 {
 	struct jit_ctx ctx;
diff --git a/arch/mn10300/include/uapi/asm/socket.h b/arch/mn10300/include/uapi/asm/socket.h
index 58b1aa01ab9f..cab7d6d50051 100644
--- a/arch/mn10300/include/uapi/asm/socket.h
+++ b/arch/mn10300/include/uapi/asm/socket.h
@@ -85,7 +85,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _ASM_SOCKET_H */
diff --git a/arch/parisc/include/uapi/asm/socket.h b/arch/parisc/include/uapi/asm/socket.h
index f9cf1223422c..a5cd40cd8ee1 100644
--- a/arch/parisc/include/uapi/asm/socket.h
+++ b/arch/parisc/include/uapi/asm/socket.h
@@ -84,7 +84,4 @@
 #define SO_ATTACH_BPF		0x402B
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	0x402C
-#define SO_ATTACH_REUSEPORT_EBPF	0x402D
-
 #endif /* _UAPI_ASM_SOCKET_H */
diff --git a/arch/powerpc/include/uapi/asm/socket.h b/arch/powerpc/include/uapi/asm/socket.h
index dd54f28ecdec..c046666038f8 100644
--- a/arch/powerpc/include/uapi/asm/socket.h
+++ b/arch/powerpc/include/uapi/asm/socket.h
@@ -92,7 +92,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif	/* _ASM_POWERPC_SOCKET_H */
diff --git a/arch/powerpc/net/bpf_jit_comp.c b/arch/powerpc/net/bpf_jit_comp.c
index 9cbc64a8f15a..345e255c06a2 100644
--- a/arch/powerpc/net/bpf_jit_comp.c
+++ b/arch/powerpc/net/bpf_jit_comp.c
@@ -18,6 +18,8 @@
 
 #include "bpf_jit.h"
 
+int bpf_jit_enable __read_mostly;
+
 static inline void bpf_flush_icache(void *start, void *end)
 {
 	smp_wmb();
diff --git a/arch/powerpc/perf/callchain.c b/arch/powerpc/perf/callchain.c
index c9260c1dfdbc..e04a6752b399 100644
--- a/arch/powerpc/perf/callchain.c
+++ b/arch/powerpc/perf/callchain.c
@@ -47,7 +47,7 @@ static int valid_next_sp(unsigned long sp, unsigned long prev_sp)
 }
 
 void
-perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	unsigned long sp, next_sp;
 	unsigned long next_ip;
@@ -232,7 +232,7 @@ static int sane_signal_64_frame(unsigned long sp)
 		puc == (unsigned long) &sf->uc;
 }
 
-static void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
+static void perf_callchain_user_64(struct perf_callchain_entry *entry,
 				   struct pt_regs *regs)
 {
 	unsigned long sp, next_sp;
@@ -247,7 +247,7 @@ static void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
 	sp = regs->gpr[1];
 	perf_callchain_store(entry, next_ip);
 
-	while (entry->entry->nr < entry->max_stack) {
+	while (entry->nr < PERF_MAX_STACK_DEPTH) {
 		fp = (unsigned long __user *) sp;
 		if (!valid_user_sp(sp, 1) || read_user_stack_64(fp, &next_sp))
 			return;
@@ -319,7 +319,7 @@ static int read_user_stack_32(unsigned int __user *ptr, unsigned int *ret)
 	return rc;
 }
 
-static inline void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
+static inline void perf_callchain_user_64(struct perf_callchain_entry *entry,
 					  struct pt_regs *regs)
 {
 }
@@ -439,7 +439,7 @@ static unsigned int __user *signal_frame_32_regs(unsigned int sp,
 	return mctx->mc_gregs;
 }
 
-static void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
+static void perf_callchain_user_32(struct perf_callchain_entry *entry,
 				   struct pt_regs *regs)
 {
 	unsigned int sp, next_sp;
@@ -453,7 +453,7 @@ static void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
 	sp = regs->gpr[1];
 	perf_callchain_store(entry, next_ip);
 
-	while (entry->entry->nr < entry->max_stack) {
+	while (entry->nr < PERF_MAX_STACK_DEPTH) {
 		fp = (unsigned int __user *) (unsigned long) sp;
 		if (!valid_user_sp(sp, 0) || read_user_stack_32(fp, &next_sp))
 			return;
@@ -487,7 +487,7 @@ static void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
 }
 
 void
-perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	if (current_is_64bit())
 		perf_callchain_user_64(entry, regs);
diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 848539d8cac1..73a301873fbf 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -125,6 +125,7 @@ config S390
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
 	select HAVE_BPF_JIT if PACK_STACK && HAVE_MARCH_Z196_FEATURES
+	select HAVE_EBPF_JIT if PACK_STACK && HAVE_MARCH_Z196_FEATURES
 	select HAVE_CMPXCHG_DOUBLE
 	select HAVE_CMPXCHG_LOCAL
 	select HAVE_DEBUG_KMEMLEAK
diff --git a/arch/s390/include/uapi/asm/socket.h b/arch/s390/include/uapi/asm/socket.h
index d02e89d14fef..296942d56e6a 100644
--- a/arch/s390/include/uapi/asm/socket.h
+++ b/arch/s390/include/uapi/asm/socket.h
@@ -91,7 +91,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* _ASM_SOCKET_H */
diff --git a/arch/s390/kernel/perf_event.c b/arch/s390/kernel/perf_event.c
index 87035fa58bbe..61595c1f0a0f 100644
--- a/arch/s390/kernel/perf_event.c
+++ b/arch/s390/kernel/perf_event.c
@@ -74,7 +74,7 @@ static unsigned long guest_is_user_mode(struct pt_regs *regs)
 
 static unsigned long instruction_pointer_guest(struct pt_regs *regs)
 {
-	return sie_block(regs)->gpsw.addr;
+	return sie_block(regs)->gpsw.addr & PSW_ADDR_INSN;
 }
 
 unsigned long perf_instruction_pointer(struct pt_regs *regs)
@@ -222,23 +222,67 @@ static int __init service_level_perf_register(void)
 }
 arch_initcall(service_level_perf_register);
 
-static int __perf_callchain_kernel(void *data, unsigned long address)
+/* See also arch/s390/kernel/traps.c */
+static unsigned long __store_trace(struct perf_callchain_entry *entry,
+				   unsigned long sp,
+				   unsigned long low, unsigned long high)
 {
-	struct perf_callchain_entry_ctx *entry = data;
-
-	perf_callchain_store(entry, address);
-	return 0;
+	struct stack_frame *sf;
+	struct pt_regs *regs;
+
+	while (1) {
+		sp = sp & PSW_ADDR_INSN;
+		if (sp < low || sp > high - sizeof(*sf))
+			return sp;
+		sf = (struct stack_frame *) sp;
+		perf_callchain_store(entry, sf->gprs[8] & PSW_ADDR_INSN);
+		/* Follow the backchain. */
+		while (1) {
+			low = sp;
+			sp = sf->back_chain & PSW_ADDR_INSN;
+			if (!sp)
+				break;
+			if (sp <= low || sp > high - sizeof(*sf))
+				return sp;
+			sf = (struct stack_frame *) sp;
+			perf_callchain_store(entry,
+					     sf->gprs[8] & PSW_ADDR_INSN);
+		}
+		/* Zero backchain detected, check for interrupt frame. */
+		sp = (unsigned long) (sf + 1);
+		if (sp <= low || sp > high - sizeof(*regs))
+			return sp;
+		regs = (struct pt_regs *) sp;
+		perf_callchain_store(entry, sf->gprs[8] & PSW_ADDR_INSN);
+		low = sp;
+		sp = regs->gprs[15];
+	}
 }
 
-void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_kernel(struct perf_callchain_entry *entry,
 			   struct pt_regs *regs)
 {
+	unsigned long head;
+	struct stack_frame *head_sf;
+
 	if (user_mode(regs))
 		return;
-	dump_trace(__perf_callchain_kernel, entry, NULL, regs->gprs[15]);
+
+	head = regs->gprs[15];
+	head_sf = (struct stack_frame *) head;
+
+	if (!head_sf || !head_sf->back_chain)
+		return;
+
+	head = head_sf->back_chain;
+	head = __store_trace(entry, head, S390_lowcore.async_stack - ASYNC_SIZE,
+			     S390_lowcore.async_stack);
+
+	__store_trace(entry, head, S390_lowcore.thread_info,
+		      S390_lowcore.thread_info + THREAD_SIZE);
 }
 
-/* Perf definitions for PMU event attributes in sysfs */
+/* Perf defintions for PMU event attributes in sysfs */
 ssize_t cpumf_events_sysfs_show(struct device *dev,
 				struct device_attribute *attr, char *page)
 {
diff --git a/arch/s390/net/bpf_jit_comp.c b/arch/s390/net/bpf_jit_comp.c
index 633172c5b065..03ad0455931d 100644
--- a/arch/s390/net/bpf_jit_comp.c
+++ b/arch/s390/net/bpf_jit_comp.c
@@ -28,6 +28,8 @@
 #include <asm/nospec-branch.h>
 #include "bpf_jit.h"
 
+int bpf_jit_enable __read_mostly;
+
 struct bpf_jit {
 	u32 seen;		/* Flags to remember seen eBPF instructions */
 	u32 seen_reg[16];	/* Array to remember which registers are used */
@@ -423,7 +425,7 @@ static void emit_load_skb_data_hlen(struct bpf_jit *jit)
  * Save registers and create stack frame if necessary.
  * See stack frame layout desription in "bpf_jit.h"!
  */
-static void bpf_jit_prologue(struct bpf_jit *jit)
+static void bpf_jit_prologue(struct bpf_jit *jit, bool is_classic)
 {
 	if (jit->seen & SEEN_TAIL_CALL) {
 		/* xc STK_OFF_TCCNT(4,%r15),STK_OFF_TCCNT(%r15) */
@@ -463,6 +465,15 @@ static void bpf_jit_prologue(struct bpf_jit *jit)
 		/* stg %b1,ST_OFF_SKBP(%r0,%r15) */
 		EMIT6_DISP_LH(0xe3000000, 0x0024, BPF_REG_1, REG_0, REG_15,
 			      STK_OFF_SKBP);
+	/* Clear A (%b0) and X (%b7) registers for converted BPF programs */
+	if (is_classic) {
+		if (REG_SEEN(BPF_REG_A))
+			/* lghi %ba,0 */
+			EMIT4_IMM(0xa7090000, BPF_REG_A, 0);
+		if (REG_SEEN(BPF_REG_X))
+			/* lghi %bx,0 */
+			EMIT4_IMM(0xa7090000, BPF_REG_X, 0);
+	}
 }
 
 /*
@@ -1300,7 +1311,7 @@ static int bpf_jit_prog(struct bpf_jit *jit, struct bpf_prog *fp)
 	jit->lit = jit->lit_start;
 	jit->prg = 0;
 
-	bpf_jit_prologue(jit);
+	bpf_jit_prologue(jit, bpf_prog_was_classic(fp));
 	for (i = 0; i < fp->len; i += insn_count) {
 		insn_count = bpf_jit_insn(jit, fp, i);
 		if (insn_count < 0)
@@ -1327,19 +1338,18 @@ void bpf_jit_compile(struct bpf_prog *fp)
 /*
  * Compile eBPF program "fp"
  */
-struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *fp)
+void bpf_int_jit_compile(struct bpf_prog *fp)
 {
 	struct bpf_binary_header *header;
 	struct bpf_jit jit;
 	int pass;
 
 	if (!bpf_jit_enable)
-		return fp;
-
+		return;
 	memset(&jit, 0, sizeof(jit));
 	jit.addrs = kcalloc(fp->len + 1, sizeof(*jit.addrs), GFP_KERNEL);
 	if (jit.addrs == NULL)
-		return fp;
+		return;
 	/*
 	 * Three initial passes:
 	 *   - 1/2: Determine clobbered registers
@@ -1371,7 +1381,6 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *fp)
 	}
 free_addrs:
 	kfree(jit.addrs);
-	return fp;
 }
 
 /*
diff --git a/arch/sh/kernel/perf_callchain.c b/arch/sh/kernel/perf_callchain.c
index fa2c0cd23eaa..cc80b614b5fa 100644
--- a/arch/sh/kernel/perf_callchain.c
+++ b/arch/sh/kernel/perf_callchain.c
@@ -21,7 +21,7 @@ static int callchain_stack(void *data, char *name)
 
 static void callchain_address(void *data, unsigned long addr, int reliable)
 {
-	struct perf_callchain_entry_ctx *entry = data;
+	struct perf_callchain_entry *entry = data;
 
 	if (reliable)
 		perf_callchain_store(entry, addr);
@@ -33,7 +33,7 @@ static const struct stacktrace_ops callchain_ops = {
 };
 
 void
-perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	perf_callchain_store(entry, regs->pc);
 
diff --git a/arch/sparc/include/uapi/asm/socket.h b/arch/sparc/include/uapi/asm/socket.h
index d270ee91968e..e6a16c40be5f 100644
--- a/arch/sparc/include/uapi/asm/socket.h
+++ b/arch/sparc/include/uapi/asm/socket.h
@@ -81,9 +81,6 @@
 #define SO_ATTACH_BPF		0x0034
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	0x0035
-#define SO_ATTACH_REUSEPORT_EBPF	0x0036
-
 /* Security levels - as per NRL IPv6 - don't actually do anything */
 #define SO_SECURITY_AUTHENTICATION		0x5001
 #define SO_SECURITY_ENCRYPTION_TRANSPORT	0x5002
diff --git a/arch/sparc/kernel/perf_event.c b/arch/sparc/kernel/perf_event.c
index 785f0c63431c..815352d501f0 100644
--- a/arch/sparc/kernel/perf_event.c
+++ b/arch/sparc/kernel/perf_event.c
@@ -1724,7 +1724,7 @@ static int __init init_hw_perf_events(void)
 }
 pure_initcall(init_hw_perf_events);
 
-void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_kernel(struct perf_callchain_entry *entry,
 			   struct pt_regs *regs)
 {
 	unsigned long ksp, fp;
@@ -1769,7 +1769,7 @@ void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
 			}
 		}
 #endif
-	} while (entry->entry->nr < entry->max_stack);
+	} while (entry->nr < PERF_MAX_STACK_DEPTH);
 }
 
 static inline int
@@ -1782,7 +1782,7 @@ valid_user_frame(const void __user *fp, unsigned long size)
 	return (__range_not_ok(fp, size, TASK_SIZE) == 0);
 }
 
-static void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
+static void perf_callchain_user_64(struct perf_callchain_entry *entry,
 				   struct pt_regs *regs)
 {
 	unsigned long ufp;
@@ -1803,10 +1803,10 @@ static void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
 		pc = sf.callers_pc;
 		ufp = (unsigned long)sf.fp + STACK_BIAS;
 		perf_callchain_store(entry, pc);
-	} while (entry->entry->nr < entry->max_stack);
+	} while (entry->nr < PERF_MAX_STACK_DEPTH);
 }
 
-static void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
+static void perf_callchain_user_32(struct perf_callchain_entry *entry,
 				   struct pt_regs *regs)
 {
 	unsigned long ufp;
@@ -1835,11 +1835,11 @@ static void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
 			ufp = (unsigned long)sf.fp;
 		}
 		perf_callchain_store(entry, pc);
-	} while (entry->entry->nr < entry->max_stack);
+	} while (entry->nr < PERF_MAX_STACK_DEPTH);
 }
 
 void
-perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
+perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
 {
 	u64 saved_fault_address = current_thread_info()->fault_address;
 	u8 saved_fault_code = get_thread_fault_code();
diff --git a/arch/sparc/net/bpf_jit_comp.c b/arch/sparc/net/bpf_jit_comp.c
index 5db3a27bcb94..3e6e05a7c4c2 100644
--- a/arch/sparc/net/bpf_jit_comp.c
+++ b/arch/sparc/net/bpf_jit_comp.c
@@ -10,6 +10,8 @@
 
 #include "bpf_jit.h"
 
+int bpf_jit_enable __read_mostly;
+
 static inline bool is_simm13(unsigned int value)
 {
 	return value + 0x1000 < 0x2000;
diff --git a/arch/tile/kernel/perf_event.c b/arch/tile/kernel/perf_event.c
index 6394c1ccb68e..8767060d70fb 100644
--- a/arch/tile/kernel/perf_event.c
+++ b/arch/tile/kernel/perf_event.c
@@ -941,7 +941,7 @@ arch_initcall(init_hw_perf_events);
 /*
  * Tile specific backtracing code for perf_events.
  */
-static inline void perf_callchain(struct perf_callchain_entry_ctx *entry,
+static inline void perf_callchain(struct perf_callchain_entry *entry,
 		    struct pt_regs *regs)
 {
 	struct KBacktraceIterator kbt;
@@ -992,13 +992,13 @@ static inline void perf_callchain(struct perf_callchain_entry_ctx *entry,
 	}
 }
 
-void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_user(struct perf_callchain_entry *entry,
 		    struct pt_regs *regs)
 {
 	perf_callchain(entry, regs);
 }
 
-void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_kernel(struct perf_callchain_entry *entry,
 		      struct pt_regs *regs)
 {
 	perf_callchain(entry, regs);
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index c61fd52677f1..3d5d6f51d74c 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -92,7 +92,7 @@ config X86
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
 	select HAVE_ARCH_WITHIN_STACK_FRAMES
-	select HAVE_BPF_JIT			if X86_64
+	select HAVE_EBPF_JIT			if X86_64
 	select HAVE_CC_STACKPROTECTOR
 	select HAVE_CMPXCHG_DOUBLE
 	select HAVE_CMPXCHG_LOCAL
diff --git a/arch/x86/include/asm/stacktrace.h b/arch/x86/include/asm/stacktrace.h
index 7c247e7404be..70bbe39043a9 100644
--- a/arch/x86/include/asm/stacktrace.h
+++ b/arch/x86/include/asm/stacktrace.h
@@ -37,7 +37,7 @@ print_context_stack_bp(struct thread_info *tinfo,
 /* Generic stack tracer with callbacks */
 
 struct stacktrace_ops {
-	int (*address)(void *data, unsigned long address, int reliable);
+	void (*address)(void *data, unsigned long address, int reliable);
 	/* On negative return stop dumping */
 	int (*stack)(void *data, char *name);
 	walk_stack_t	walk_stack;
diff --git a/arch/x86/kernel/cpu/perf_event.c b/arch/x86/kernel/cpu/perf_event.c
index 3e71f89be1c2..851fbdb99767 100644
--- a/arch/x86/kernel/cpu/perf_event.c
+++ b/arch/x86/kernel/cpu/perf_event.c
@@ -2197,11 +2197,11 @@ static int backtrace_stack(void *data, char *name)
 	return 0;
 }
 
-static int backtrace_address(void *data, unsigned long addr, int reliable)
+static void backtrace_address(void *data, unsigned long addr, int reliable)
 {
 	struct perf_callchain_entry *entry = data;
 
-	return perf_callchain_store(entry, addr);
+	perf_callchain_store(entry, addr);
 }
 
 static const struct stacktrace_ops backtrace_ops = {
diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index 0d1ff4b407d4..9c30acfadae2 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -135,8 +135,7 @@ print_context_stack_bp(struct thread_info *tinfo,
 		if (!__kernel_text_address(addr))
 			break;
 
-		if (ops->address(data, addr, 1))
-			break;
+		ops->address(data, addr, 1);
 		frame = frame->next_frame;
 		ret_addr = &frame->return_address;
 		print_ftrace_graph_addr(addr, data, ops, tinfo, graph);
@@ -155,11 +154,10 @@ static int print_trace_stack(void *data, char *name)
 /*
  * Print one address/symbol entries per line.
  */
-static int print_trace_address(void *data, unsigned long addr, int reliable)
+static void print_trace_address(void *data, unsigned long addr, int reliable)
 {
 	touch_nmi_watchdog();
 	printk_stack_address(addr, reliable, data);
-	return 0;
 }
 
 static const struct stacktrace_ops print_trace_ops = {
diff --git a/arch/x86/kernel/stacktrace.c b/arch/x86/kernel/stacktrace.c
index 9ee98eefc44d..fdd0c6430e5a 100644
--- a/arch/x86/kernel/stacktrace.c
+++ b/arch/x86/kernel/stacktrace.c
@@ -14,34 +14,30 @@ static int save_stack_stack(void *data, char *name)
 	return 0;
 }
 
-static int
+static void
 __save_stack_address(void *data, unsigned long addr, bool reliable, bool nosched)
 {
 	struct stack_trace *trace = data;
 #ifdef CONFIG_FRAME_POINTER
 	if (!reliable)
-		return 0;
+		return;
 #endif
 	if (nosched && in_sched_functions(addr))
-		return 0;
+		return;
 	if (trace->skip > 0) {
 		trace->skip--;
-		return 0;
+		return;
 	}
-	if (trace->nr_entries < trace->max_entries) {
+	if (trace->nr_entries < trace->max_entries)
 		trace->entries[trace->nr_entries++] = addr;
-		return 0;
-	} else {
-		return -1; /* no more room, stop walking the stack */
-	}
 }
 
-static int save_stack_address(void *data, unsigned long addr, int reliable)
+static void save_stack_address(void *data, unsigned long addr, int reliable)
 {
 	return __save_stack_address(data, addr, reliable, false);
 }
 
-static int
+static void
 save_stack_address_nosched(void *data, unsigned long addr, int reliable)
 {
 	return __save_stack_address(data, addr, reliable, true);
diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index 238b7dcd5e93..864e6f847d88 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -348,10 +348,7 @@ SECTIONS
 
 	/* Sections to be discarded */
 	DISCARDS
-	/DISCARD/ : {
-		*(.eh_frame)
-		*(__func_stack_frame_non_standard)
-	}
+	/DISCARD/ : { *(.eh_frame) }
 }
 
 
diff --git a/arch/x86/net/bpf_jit_comp.c b/arch/x86/net/bpf_jit_comp.c
index 85a7c0b0627c..82f8cd0a3af9 100644
--- a/arch/x86/net/bpf_jit_comp.c
+++ b/arch/x86/net/bpf_jit_comp.c
@@ -15,6 +15,8 @@
 #include <asm/nospec-branch.h>
 #include <linux/bpf.h>
 
+int bpf_jit_enable __read_mostly;
+
 /*
  * assembly code in arch/x86/net/bpf_jit.S
  */
@@ -205,7 +207,7 @@ struct jit_context {
 	 32 /* space for rbx, r13, r14, r15 */ + \
 	 8 /* space for skb_copy_bits() buffer */)
 
-#define PROLOGUE_SIZE 48
+#define PROLOGUE_SIZE 51
 
 /* emit x64 prologue code for BPF program and check it's size.
  * bpf_tail_call helper will skip it while jumping into another program
@@ -241,15 +243,11 @@ static void emit_prologue(u8 **pprog)
 	/* mov qword ptr [rbp-X],r15 */
 	EMIT3_off32(0x4C, 0x89, 0xBD, -STACKSIZE + 24);
 
-	/* Clear the tail call counter (tail_call_cnt): for eBPF tail calls
-	 * we need to reset the counter to 0. It's done in two instructions,
-	 * resetting rax register to 0 (xor on eax gets 0 extended), and
-	 * moving it to the counter location.
-	 */
+	/* clear A and X registers */
+	EMIT2(0x31, 0xc0); /* xor eax, eax */
+	EMIT3(0x4D, 0x31, 0xED); /* xor r13, r13 */
 
-	/* xor eax, eax */
-	EMIT2(0x31, 0xc0);
-	/* mov qword ptr [rbp-X], rax */
+	/* clear tail_cnt: mov qword ptr [rbp-X], rax */
 	EMIT3_off32(0x48, 0x89, 0x85, -STACKSIZE + 32);
 
 	BUILD_BUG_ON(cnt != PROLOGUE_SIZE);
@@ -1066,7 +1064,7 @@ void bpf_jit_compile(struct bpf_prog *prog)
 {
 }
 
-struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
+void bpf_int_jit_compile(struct bpf_prog *prog)
 {
 	struct bpf_binary_header *header = NULL;
 	int proglen, oldproglen = 0;
@@ -1077,14 +1075,14 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 	int i;
 
 	if (!bpf_jit_enable)
-		return prog;
+		return;
 
 	if (!prog || !prog->len)
 		return;
 
 	addrs = kmalloc(prog->len * sizeof(*addrs), GFP_KERNEL);
 	if (!addrs)
-		return prog;
+		return;
 
 	/* Before first pass, make a rough estimation of addrs[]
 	 * each bpf instruction is translated to less than 64 bytes
@@ -1137,7 +1135,6 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 	}
 out:
 	kfree(addrs);
-	return prog;
 }
 
 void bpf_jit_free(struct bpf_prog *fp)
diff --git a/arch/x86/oprofile/backtrace.c b/arch/x86/oprofile/backtrace.c
index cb31a4440e58..4e664bdb535a 100644
--- a/arch/x86/oprofile/backtrace.c
+++ b/arch/x86/oprofile/backtrace.c
@@ -23,13 +23,12 @@ static int backtrace_stack(void *data, char *name)
 	return 0;
 }
 
-static int backtrace_address(void *data, unsigned long addr, int reliable)
+static void backtrace_address(void *data, unsigned long addr, int reliable)
 {
 	unsigned int *depth = data;
 
 	if ((*depth)--)
 		oprofile_add_trace(addr);
-	return 0;
 }
 
 static struct stacktrace_ops backtrace_ops = {
diff --git a/arch/xtensa/include/uapi/asm/socket.h b/arch/xtensa/include/uapi/asm/socket.h
index fd3b96d1153f..4120af086160 100644
--- a/arch/xtensa/include/uapi/asm/socket.h
+++ b/arch/xtensa/include/uapi/asm/socket.h
@@ -96,7 +96,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif	/* _XTENSA_SOCKET_H */
diff --git a/arch/xtensa/kernel/perf_event.c b/arch/xtensa/kernel/perf_event.c
index ef90479e0397..54f01188c29c 100644
--- a/arch/xtensa/kernel/perf_event.c
+++ b/arch/xtensa/kernel/perf_event.c
@@ -323,23 +323,23 @@ static void xtensa_pmu_read(struct perf_event *event)
 
 static int callchain_trace(struct stackframe *frame, void *data)
 {
-	struct perf_callchain_entry_ctx *entry = data;
+	struct perf_callchain_entry *entry = data;
 
 	perf_callchain_store(entry, frame->pc);
 	return 0;
 }
 
-void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_kernel(struct perf_callchain_entry *entry,
 			   struct pt_regs *regs)
 {
-	xtensa_backtrace_kernel(regs, entry->max_stack,
+	xtensa_backtrace_kernel(regs, PERF_MAX_STACK_DEPTH,
 				callchain_trace, NULL, entry);
 }
 
-void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
+void perf_callchain_user(struct perf_callchain_entry *entry,
 			 struct pt_regs *regs)
 {
-	xtensa_backtrace_user(regs, entry->max_stack,
+	xtensa_backtrace_user(regs, PERF_MAX_STACK_DEPTH,
 			      callchain_trace, entry);
 }
 
diff --git a/drivers/android/binder.c b/drivers/android/binder.c
index 27113321c88a..2474977609f4 100644
--- a/drivers/android/binder.c
+++ b/drivers/android/binder.c
@@ -51,6 +51,7 @@
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <asm/cacheflush.h>
 #include <linux/fdtable.h>
 #include <linux/file.h>
 #include <linux/freezer.h>
@@ -72,10 +73,6 @@
 #include <linux/ratelimit.h>
 
 #include <uapi/linux/android/binder.h>
-#include <uapi/linux/eventpoll.h>
-
-#include <asm/cacheflush.h>
-
 #include "binder_alloc.h"
 #include "binder_trace.h"
 
@@ -92,6 +89,7 @@ static DEFINE_SPINLOCK(binder_dead_nodes_lock);
 static struct dentry *binder_debugfs_dir_entry_root;
 static struct dentry *binder_debugfs_dir_entry_proc;
 static atomic_t binder_last_id;
+static struct workqueue_struct *binder_deferred_workqueue;
 
 #define BINDER_DEBUG_ENTRY(name) \
 static int binder_##name##_open(struct inode *inode, struct file *file) \
@@ -121,6 +119,8 @@ BINDER_DEBUG_ENTRY(proc);
 
 #define FORBIDDEN_MMAP_FLAGS                (VM_WRITE)
 
+#define BINDER_SMALL_BUF_SIZE (PAGE_SIZE * 64)
+
 enum {
 	BINDER_DEBUG_USER_ERROR             = 1U << 0,
 	BINDER_DEBUG_FAILED_TRANSACTION     = 1U << 1,
@@ -142,7 +142,7 @@ static uint32_t binder_debug_mask = 0;
 module_param_named(debug_mask, binder_debug_mask, uint, 0644);
 
 static char *binder_devices_param = CONFIG_ANDROID_BINDER_DEVICES;
-module_param_named(devices, binder_devices_param, charp, 0444);
+module_param_named(devices, binder_devices_param, charp, S_IRUGO);
 
 static DECLARE_WAIT_QUEUE_HEAD(binder_user_error_wait);
 static int binder_stop_on_user_error;
@@ -531,7 +531,8 @@ struct binder_priority {
  * @requested_threads_started: number binder threads started
  *                        (protected by @inner_lock)
  * @tmp_ref:              temporary reference to indicate proc is in use
- *                        (protected by @inner_lock)
+ *                        (atomic since @proc->inner_lock cannot
+ *                        always be acquired)
  * @default_priority:     default scheduler priority
  *                        (invariant after initialized)
  * @debugfs_entry:        debugfs node
@@ -566,7 +567,7 @@ struct binder_proc {
 	int max_threads;
 	int requested_threads;
 	int requested_threads_started;
-	int tmp_ref;
+	atomic_t tmp_ref;
 	struct binder_priority default_priority;
 	struct dentry *debugfs_entry;
 	struct binder_alloc alloc;
@@ -668,26 +669,6 @@ struct binder_transaction {
 	spinlock_t lock;
 };
 
-/**
- * struct binder_object - union of flat binder object types
- * @hdr:   generic object header
- * @fbo:   binder object (nodes and refs)
- * @fdo:   file descriptor object
- * @bbo:   binder buffer pointer
- * @fdao:  file descriptor array
- *
- * Used for type-independent object copies
- */
-struct binder_object {
-	union {
-		struct binder_object_header hdr;
-		struct flat_binder_object fbo;
-		struct binder_fd_object fdo;
-		struct binder_buffer_object bbo;
-		struct binder_fd_array_object fdao;
-	};
-};
-
 /**
  * binder_proc_lock() - Acquire outer lock for given binder_proc
  * @proc:         struct binder_proc to acquire
@@ -873,7 +854,6 @@ static void
 binder_enqueue_deferred_thread_work_ilocked(struct binder_thread *thread,
 					    struct binder_work *work)
 {
-	WARN_ON(!list_empty(&thread->waiting_thread_node));
 	binder_enqueue_work_ilocked(work, &thread->todo);
 }
 
@@ -891,7 +871,6 @@ static void
 binder_enqueue_thread_work_ilocked(struct binder_thread *thread,
 				   struct binder_work *work)
 {
-	WARN_ON(!list_empty(&thread->waiting_thread_node));
 	binder_enqueue_work_ilocked(work, &thread->todo);
 	thread->process_todo = true;
 }
@@ -1421,7 +1400,8 @@ static int binder_inc_node_nilocked(struct binder_node *node, int strong,
 			if (target_list == NULL &&
 			    node->internal_strong_refs == 0 &&
 			    !(node->proc &&
-			      node == node->proc->context->binder_context_mgr_node &&
+			      node == node->proc->context->
+				      binder_context_mgr_node &&
 			      node->has_strong_ref)) {
 				pr_err("invalid inc strong node for %d\n",
 					node->debug_id);
@@ -1431,12 +1411,19 @@ static int binder_inc_node_nilocked(struct binder_node *node, int strong,
 		} else
 			node->local_strong_refs++;
 		if (!node->has_strong_ref && target_list) {
-			struct binder_thread *thread = container_of(target_list,
-						    struct binder_thread, todo);
 			binder_dequeue_work_ilocked(&node->work);
-			BUG_ON(&thread->todo != target_list);
-			binder_enqueue_deferred_thread_work_ilocked(thread,
-								   &node->work);
+			/*
+			 * Note: this function is the only place where we queue
+			 * directly to a thread->todo without using the
+			 * corresponding binder_enqueue_thread_work() helper
+			 * functions; in this case it's ok to not set the
+			 * process_todo flag, since we know this node work will
+			 * always be followed by other work that starts queue
+			 * processing: in case of synchronous transactions, a
+			 * BR_REPLY or BR_ERROR; in case of oneway
+			 * transactions, a BR_TRANSACTION_COMPLETE.
+			 */
+			binder_enqueue_work_ilocked(&node->work, target_list);
 		}
 	} else {
 		if (!internal)
@@ -2050,9 +2037,9 @@ static void binder_thread_dec_tmpref(struct binder_thread *thread)
 static void binder_proc_dec_tmpref(struct binder_proc *proc)
 {
 	binder_inner_proc_lock(proc);
-	proc->tmp_ref--;
+	atomic_dec(&proc->tmp_ref);
 	if (proc->is_dead && RB_EMPTY_ROOT(&proc->threads) &&
-			!proc->tmp_ref) {
+			!atomic_read(&proc->tmp_ref)) {
 		binder_inner_proc_unlock(proc);
 		binder_free_proc(proc);
 		return;
@@ -2114,18 +2101,26 @@ static struct binder_thread *binder_get_txn_from_and_acq_inner(
 
 static void binder_free_transaction(struct binder_transaction *t)
 {
-	struct binder_proc *target_proc = t->to_proc;
+	struct binder_proc *target_proc;
 
+	spin_lock(&t->lock);
+	target_proc = t->to_proc;
 	if (target_proc) {
+		atomic_inc(&target_proc->tmp_ref);
+		spin_unlock(&t->lock);
+
 		binder_inner_proc_lock(target_proc);
 		if (t->buffer)
 			t->buffer->transaction = NULL;
 		binder_inner_proc_unlock(target_proc);
+		binder_proc_dec_tmpref(target_proc);
+	} else {
+		/*
+		 * If the transaction has no target_proc, then
+		 * t->buffer->transaction * has already been cleared.
+		 */
+		spin_unlock(&t->lock);
 	}
-	/*
-	 * If the transaction has no target_proc, then
-	 * t->buffer->transaction has already been cleared.
-	 */
 	kfree(t);
 	binder_stats_deleted(BINDER_STAT_TRANSACTION);
 }
@@ -2208,34 +2203,26 @@ static void binder_cleanup_transaction(struct binder_transaction *t,
 }
 
 /**
- * binder_get_object() - gets object and checks for valid metadata
- * @proc:	binder_proc owning the buffer
+ * binder_validate_object() - checks for a valid metadata object in a buffer.
  * @buffer:	binder_buffer that we're parsing.
- * @offset:	offset in the @buffer at which to validate an object.
- * @object:	struct binder_object to read into
+ * @offset:	offset in the buffer at which to validate an object.
  *
  * Return:	If there's a valid metadata object at @offset in @buffer, the
- *		size of that object. Otherwise, it returns zero. The object
- *		is read into the struct binder_object pointed to by @object.
+ *		size of that object. Otherwise, it returns zero.
  */
-static size_t binder_get_object(struct binder_proc *proc,
-				struct binder_buffer *buffer,
-				unsigned long offset,
-				struct binder_object *object)
+static size_t binder_validate_object(struct binder_buffer *buffer, u64 offset)
 {
-	size_t read_size;
+	/* Check if we can read a header first */
 	struct binder_object_header *hdr;
 	size_t object_size = 0;
 
-	read_size = min_t(size_t, sizeof(*object), buffer->data_size - offset);
-	if (offset > buffer->data_size || read_size < sizeof(*hdr) ||
+	if (buffer->data_size < sizeof(*hdr) ||
+	    offset > buffer->data_size - sizeof(*hdr) ||
 	    !IS_ALIGNED(offset, sizeof(u32)))
 		return 0;
-	binder_alloc_copy_from_buffer(&proc->alloc, object, buffer,
-				      offset, read_size);
 
-	/* Ok, now see if we read a complete object. */
-	hdr = &object->hdr;
+	/* Ok, now see if we can read a complete object. */
+	hdr = (struct binder_object_header *)(buffer->data + offset);
 	switch (hdr->type) {
 	case BINDER_TYPE_BINDER:
 	case BINDER_TYPE_WEAK_BINDER:
@@ -2264,13 +2251,10 @@ static size_t binder_get_object(struct binder_proc *proc,
 
 /**
  * binder_validate_ptr() - validates binder_buffer_object in a binder_buffer.
- * @proc:	binder_proc owning the buffer
  * @b:		binder_buffer containing the object
- * @object:	struct binder_object to read into
  * @index:	index in offset array at which the binder_buffer_object is
  *		located
- * @start_offset: points to the start of the offset array
- * @object_offsetp: offset of @object read from @b
+ * @start:	points to the start of the offset array
  * @num_valid:	the number of valid offsets in the offset array
  *
  * Return:	If @index is within the valid range of the offset array
@@ -2281,46 +2265,34 @@ static size_t binder_get_object(struct binder_proc *proc,
  *		Note that the offset found in index @index itself is not
  *		verified; this function assumes that @num_valid elements
  *		from @start were previously verified to have valid offsets.
- *		If @object_offsetp is non-NULL, then the offset within
- *		@b is written to it.
  */
-static struct binder_buffer_object *binder_validate_ptr(
-						struct binder_proc *proc,
-						struct binder_buffer *b,
-						struct binder_object *object,
-						binder_size_t index,
-						binder_size_t start_offset,
-						binder_size_t *object_offsetp,
-						binder_size_t num_valid)
+static struct binder_buffer_object *binder_validate_ptr(struct binder_buffer *b,
+							binder_size_t index,
+							binder_size_t *start,
+							binder_size_t num_valid)
 {
-	size_t object_size;
-	binder_size_t object_offset;
-	unsigned long buffer_offset;
+	struct binder_buffer_object *buffer_obj;
+	binder_size_t *offp;
 
 	if (index >= num_valid)
 		return NULL;
 
-	buffer_offset = start_offset + sizeof(binder_size_t) * index;
-	binder_alloc_copy_from_buffer(&proc->alloc, &object_offset,
-				      b, buffer_offset, sizeof(object_offset));
-	object_size = binder_get_object(proc, b, object_offset, object);
-	if (!object_size || object->hdr.type != BINDER_TYPE_PTR)
+	offp = start + index;
+	buffer_obj = (struct binder_buffer_object *)(b->data + *offp);
+	if (buffer_obj->hdr.type != BINDER_TYPE_PTR)
 		return NULL;
-	if (object_offsetp)
-		*object_offsetp = object_offset;
 
-	return &object->bbo;
+	return buffer_obj;
 }
 
 /**
  * binder_validate_fixup() - validates pointer/fd fixups happen in order.
- * @proc:		binder_proc owning the buffer
  * @b:			transaction buffer
- * @objects_start_offset: offset to start of objects buffer
- * @buffer_obj_offset:	offset to binder_buffer_object in which to fix up
- * @fixup_offset:	start offset in @buffer to fix up
- * @last_obj_offset:	offset to last binder_buffer_object that we fixed
- * @last_min_offset:	minimum fixup offset in object at @last_obj_offset
+ * @objects_start	start of objects buffer
+ * @buffer:		binder_buffer_object in which to fix up
+ * @offset:		start offset in @buffer to fix up
+ * @last_obj:		last binder_buffer_object that we fixed up in
+ * @last_min_offset:	minimum fixup offset in @last_obj
  *
  * Return:		%true if a fixup in buffer @buffer at offset @offset is
  *			allowed.
@@ -2351,83 +2323,63 @@ static struct binder_buffer_object *binder_validate_ptr(
  *   C (parent = A, offset = 16)
  *     D (parent = B, offset = 0) // B is not A or any of A's parents
  */
-static bool binder_validate_fixup(struct binder_proc *proc,
-				  struct binder_buffer *b,
-				  binder_size_t objects_start_offset,
-				  binder_size_t buffer_obj_offset,
+static bool binder_validate_fixup(struct binder_buffer *b,
+				  binder_size_t *objects_start,
+				  struct binder_buffer_object *buffer,
 				  binder_size_t fixup_offset,
-				  binder_size_t last_obj_offset,
+				  struct binder_buffer_object *last_obj,
 				  binder_size_t last_min_offset)
 {
-	if (!last_obj_offset) {
+	if (!last_obj) {
 		/* Nothing to fix up in */
 		return false;
 	}
 
-	while (last_obj_offset != buffer_obj_offset) {
-		unsigned long buffer_offset;
-		struct binder_object last_object;
-		struct binder_buffer_object *last_bbo;
-		size_t object_size = binder_get_object(proc, b, last_obj_offset,
-						       &last_object);
-		if (object_size != sizeof(*last_bbo))
-			return false;
-
-		last_bbo = &last_object.bbo;
+	while (last_obj != buffer) {
 		/*
 		 * Safe to retrieve the parent of last_obj, since it
 		 * was already previously verified by the driver.
 		 */
-		if ((last_bbo->flags & BINDER_BUFFER_FLAG_HAS_PARENT) == 0)
+		if ((last_obj->flags & BINDER_BUFFER_FLAG_HAS_PARENT) == 0)
 			return false;
-		last_min_offset = last_bbo->parent_offset + sizeof(uintptr_t);
-		buffer_offset = objects_start_offset +
-			sizeof(binder_size_t) * last_bbo->parent,
-		binder_alloc_copy_from_buffer(&proc->alloc, &last_obj_offset,
-					      b, buffer_offset,
-					      sizeof(last_obj_offset));
+		last_min_offset = last_obj->parent_offset + sizeof(uintptr_t);
+		last_obj = (struct binder_buffer_object *)
+			(b->data + *(objects_start + last_obj->parent));
 	}
 	return (fixup_offset >= last_min_offset);
 }
 
 static void binder_transaction_buffer_release(struct binder_proc *proc,
 					      struct binder_buffer *buffer,
-					      binder_size_t failed_at,
-					      bool is_failure)
+					      binder_size_t *failed_at)
 {
+	binder_size_t *offp, *off_start, *off_end;
 	int debug_id = buffer->debug_id;
-	binder_size_t off_start_offset, buffer_offset, off_end_offset;
 
 	binder_debug(BINDER_DEBUG_TRANSACTION,
-		     "%d buffer release %d, size %zd-%zd, failed at %llx\n",
+		     "%d buffer release %d, size %zd-%zd, failed at %pK\n",
 		     proc->pid, buffer->debug_id,
-		     buffer->data_size, buffer->offsets_size,
-		     (unsigned long long)failed_at);
+		     buffer->data_size, buffer->offsets_size, failed_at);
 
 	if (buffer->target_node)
 		binder_dec_node(buffer->target_node, 1, 0);
 
-	off_start_offset = ALIGN(buffer->data_size, sizeof(void *));
-	off_end_offset = is_failure ? failed_at :
-				off_start_offset + buffer->offsets_size;
-	for (buffer_offset = off_start_offset; buffer_offset < off_end_offset;
-	     buffer_offset += sizeof(binder_size_t)) {
+	off_start = (binder_size_t *)(buffer->data +
+				      ALIGN(buffer->data_size, sizeof(void *)));
+	if (failed_at)
+		off_end = failed_at;
+	else
+		off_end = (void *)off_start + buffer->offsets_size;
+	for (offp = off_start; offp < off_end; offp++) {
 		struct binder_object_header *hdr;
-		size_t object_size;
-		struct binder_object object;
-		binder_size_t object_offset;
-
-		binder_alloc_copy_from_buffer(&proc->alloc, &object_offset,
-					      buffer, buffer_offset,
-					      sizeof(object_offset));
-		object_size = binder_get_object(proc, buffer,
-						object_offset, &object);
+		size_t object_size = binder_validate_object(buffer, *offp);
+
 		if (object_size == 0) {
 			pr_err("transaction release %d bad object at offset %lld, size %zd\n",
-			       debug_id, (u64)object_offset, buffer->data_size);
+			       debug_id, (u64)*offp, buffer->data_size);
 			continue;
 		}
-		hdr = &object.hdr;
+		hdr = (struct binder_object_header *)(buffer->data + *offp);
 		switch (hdr->type) {
 		case BINDER_TYPE_BINDER:
 		case BINDER_TYPE_WEAK_BINDER: {
@@ -2485,25 +2437,28 @@ static void binder_transaction_buffer_release(struct binder_proc *proc,
 		case BINDER_TYPE_FDA: {
 			struct binder_fd_array_object *fda;
 			struct binder_buffer_object *parent;
-			struct binder_object ptr_object;
-			binder_size_t fda_offset;
+			uintptr_t parent_buffer;
+			u32 *fd_array;
 			size_t fd_index;
 			binder_size_t fd_buf_size;
-			binder_size_t num_valid;
 
-			num_valid = (buffer_offset - off_start_offset) /
-						sizeof(binder_size_t);
 			fda = to_binder_fd_array_object(hdr);
-			parent = binder_validate_ptr(proc, buffer, &ptr_object,
-						     fda->parent,
-						     off_start_offset,
-						     NULL,
-						     num_valid);
+			parent = binder_validate_ptr(buffer, fda->parent,
+						     off_start,
+						     offp - off_start);
 			if (!parent) {
-				pr_err("transaction release %d bad parent offset\n",
+				pr_err("transaction release %d bad parent offset",
 				       debug_id);
 				continue;
 			}
+			/*
+			 * Since the parent was already fixed up, convert it
+			 * back to kernel address space to access it
+			 */
+			parent_buffer = parent->buffer -
+				binder_alloc_get_user_buffer_offset(
+						&proc->alloc);
+
 			fd_buf_size = sizeof(u32) * fda->num_fds;
 			if (fda->num_fds >= SIZE_MAX / sizeof(u32)) {
 				pr_err("transaction release %d invalid number of fds (%lld)\n",
@@ -2517,29 +2472,9 @@ static void binder_transaction_buffer_release(struct binder_proc *proc,
 				       debug_id, (u64)fda->num_fds);
 				continue;
 			}
-			/*
-			 * the source data for binder_buffer_object is visible
-			 * to user-space and the @buffer element is the user
-			 * pointer to the buffer_object containing the fd_array.
-			 * Convert the address to an offset relative to
-			 * the base of the transaction buffer.
-			 */
-			fda_offset =
-			    (parent->buffer - (uintptr_t)buffer->user_data) +
-			    fda->parent_offset;
-			for (fd_index = 0; fd_index < fda->num_fds;
-			     fd_index++) {
-				u32 fd;
-				binder_size_t offset = fda_offset +
-					fd_index * sizeof(fd);
-
-				binder_alloc_copy_from_buffer(&proc->alloc,
-							      &fd,
-							      buffer,
-							      offset,
-							      sizeof(fd));
-				task_close_fd(proc, fd);
-			}
+			fd_array = (u32 *)(parent_buffer + (uintptr_t)fda->parent_offset);
+			for (fd_index = 0; fd_index < fda->num_fds; fd_index++)
+				task_close_fd(proc, fd_array[fd_index]);
 		} break;
 		default:
 			pr_err("transaction release %d bad object type %x\n",
@@ -2736,8 +2671,9 @@ static int binder_translate_fd_array(struct binder_fd_array_object *fda,
 				     struct binder_transaction *in_reply_to)
 {
 	binder_size_t fdi, fd_buf_size, num_installed_fds;
-	binder_size_t fda_offset;
 	int target_fd;
+	uintptr_t parent_buffer;
+	u32 *fd_array;
 	struct binder_proc *proc = thread->proc;
 	struct binder_proc *target_proc = t->to_proc;
 
@@ -2755,33 +2691,23 @@ static int binder_translate_fd_array(struct binder_fd_array_object *fda,
 		return -EINVAL;
 	}
 	/*
-	 * the source data for binder_buffer_object is visible
-	 * to user-space and the @buffer element is the user
-	 * pointer to the buffer_object containing the fd_array.
-	 * Convert the address to an offset relative to
-	 * the base of the transaction buffer.
+	 * Since the parent was already fixed up, convert it
+	 * back to the kernel address space to access it
 	 */
-	fda_offset = (parent->buffer - (uintptr_t)t->buffer->user_data) +
-		fda->parent_offset;
-	if (!IS_ALIGNED((unsigned long)fda_offset, sizeof(u32))) {
+	parent_buffer = parent->buffer -
+		binder_alloc_get_user_buffer_offset(&target_proc->alloc);
+	fd_array = (u32 *)(parent_buffer + (uintptr_t)fda->parent_offset);
+	if (!IS_ALIGNED((unsigned long)fd_array, sizeof(u32))) {
 		binder_user_error("%d:%d parent offset not aligned correctly.\n",
 				  proc->pid, thread->pid);
 		return -EINVAL;
 	}
 	for (fdi = 0; fdi < fda->num_fds; fdi++) {
-		u32 fd;
-
-		binder_size_t offset = fda_offset + fdi * sizeof(fd);
-
-		binder_alloc_copy_from_buffer(&target_proc->alloc,
-					      &fd, t->buffer,
-					      offset, sizeof(fd));
-		target_fd = binder_translate_fd(fd, t, thread, in_reply_to);
+		target_fd = binder_translate_fd(fd_array[fdi], t, thread,
+						in_reply_to);
 		if (target_fd < 0)
 			goto err_translate_fd_failed;
-		binder_alloc_copy_to_buffer(&target_proc->alloc,
-					    t->buffer, offset,
-					    &target_fd, sizeof(fd));
+		fd_array[fdi] = target_fd;
 	}
 	return 0;
 
@@ -2791,48 +2717,38 @@ err_translate_fd_failed:
 	 * installed so far.
 	 */
 	num_installed_fds = fdi;
-	for (fdi = 0; fdi < num_installed_fds; fdi++) {
-		u32 fd;
-		binder_size_t offset = fda_offset + fdi * sizeof(fd);
-		binder_alloc_copy_from_buffer(&target_proc->alloc,
-					      &fd, t->buffer,
-					      offset, sizeof(fd));
-		task_close_fd(target_proc, fd);
-	}
+	for (fdi = 0; fdi < num_installed_fds; fdi++)
+		task_close_fd(target_proc, fd_array[fdi]);
 	return target_fd;
 }
 
 static int binder_fixup_parent(struct binder_transaction *t,
 			       struct binder_thread *thread,
 			       struct binder_buffer_object *bp,
-			       binder_size_t off_start_offset,
+			       binder_size_t *off_start,
 			       binder_size_t num_valid,
-			       binder_size_t last_fixup_obj_off,
+			       struct binder_buffer_object *last_fixup_obj,
 			       binder_size_t last_fixup_min_off)
 {
 	struct binder_buffer_object *parent;
+	u8 *parent_buffer;
 	struct binder_buffer *b = t->buffer;
 	struct binder_proc *proc = thread->proc;
 	struct binder_proc *target_proc = t->to_proc;
-	struct binder_object object;
-	binder_size_t buffer_offset;
-	binder_size_t parent_offset;
 
 	if (!(bp->flags & BINDER_BUFFER_FLAG_HAS_PARENT))
 		return 0;
 
-	parent = binder_validate_ptr(target_proc, b, &object, bp->parent,
-				     off_start_offset, &parent_offset,
-				     num_valid);
+	parent = binder_validate_ptr(b, bp->parent, off_start, num_valid);
 	if (!parent) {
 		binder_user_error("%d:%d got transaction with invalid parent offset or type\n",
 				  proc->pid, thread->pid);
 		return -EINVAL;
 	}
 
-	if (!binder_validate_fixup(target_proc, b, off_start_offset,
-				   parent_offset, bp->parent_offset,
-				   last_fixup_obj_off,
+	if (!binder_validate_fixup(b, off_start,
+				   parent, bp->parent_offset,
+				   last_fixup_obj,
 				   last_fixup_min_off)) {
 		binder_user_error("%d:%d got transaction with out-of-order buffer fixup\n",
 				  proc->pid, thread->pid);
@@ -2846,10 +2762,10 @@ static int binder_fixup_parent(struct binder_transaction *t,
 				  proc->pid, thread->pid);
 		return -EINVAL;
 	}
-	buffer_offset = bp->parent_offset +
-			(uintptr_t)parent->buffer - (uintptr_t)b->user_data;
-	binder_alloc_copy_to_buffer(&target_proc->alloc, b, buffer_offset,
-				    &bp->buffer, sizeof(bp->buffer));
+	parent_buffer = (u8 *)((uintptr_t)parent->buffer -
+			binder_alloc_get_user_buffer_offset(
+				&target_proc->alloc));
+	*(binder_uintptr_t *)(parent_buffer + bp->parent_offset) = bp->buffer;
 
 	return 0;
 }
@@ -2957,7 +2873,7 @@ static struct binder_node *binder_get_node_refs_for_txn(
 		target_node = node;
 		binder_inc_node_nilocked(node, 1, 0, NULL);
 		binder_inc_node_tmpref_ilocked(node);
-		node->proc->tmp_ref++;
+		atomic_inc(&node->proc->tmp_ref);
 		*procp = node->proc;
 	} else
 		*error = BR_DEAD_REPLY;
@@ -2973,12 +2889,10 @@ static void binder_transaction(struct binder_proc *proc,
 {
 	int ret;
 	struct binder_transaction *t;
-	struct binder_work *w;
 	struct binder_work *tcomplete;
-	binder_size_t buffer_offset = 0;
-	binder_size_t off_start_offset, off_end_offset;
+	binder_size_t *offp, *off_end, *off_start;
 	binder_size_t off_min;
-	binder_size_t sg_buf_offset, sg_buf_end_offset;
+	u8 *sg_bufp, *sg_buf_end;
 	struct binder_proc *target_proc = NULL;
 	struct binder_thread *target_thread = NULL;
 	struct binder_node *target_node = NULL;
@@ -2987,7 +2901,7 @@ static void binder_transaction(struct binder_proc *proc,
 	uint32_t return_error = 0;
 	uint32_t return_error_param = 0;
 	uint32_t return_error_line = 0;
-	binder_size_t last_fixup_obj_off = 0;
+	struct binder_buffer_object *last_fixup_obj = NULL;
 	binder_size_t last_fixup_min_off = 0;
 	struct binder_context *context = proc->context;
 	int t_debug_id = atomic_inc_return(&binder_last_id);
@@ -3055,7 +2969,7 @@ static void binder_transaction(struct binder_proc *proc,
 			goto err_dead_binder;
 		}
 		target_proc = target_thread->proc;
-		target_proc->tmp_ref++;
+		atomic_inc(&target_proc->tmp_ref);
 		binder_inner_proc_unlock(target_thread->proc);
 	} else {
 		if (tr->target.handle) {
@@ -3091,7 +3005,7 @@ static void binder_transaction(struct binder_proc *proc,
 			else
 				return_error = BR_DEAD_REPLY;
 			mutex_unlock(&context->context_mgr_node_lock);
-			if (target_node && target_proc->pid == proc->pid) {
+			if (target_node && target_proc == proc) {
 				binder_user_error("%d:%d got transaction to context manager from process owning it\n",
 						  proc->pid, thread->pid);
 				return_error = BR_FAILED_REPLY;
@@ -3123,29 +3037,6 @@ static void binder_transaction(struct binder_proc *proc,
 			goto err_invalid_target_handle;
 		}
 		binder_inner_proc_lock(proc);
-
-		w = list_first_entry_or_null(&thread->todo,
-					     struct binder_work, entry);
-		if (!(tr->flags & TF_ONE_WAY) && w &&
-		    w->type == BINDER_WORK_TRANSACTION) {
-			/*
-			 * Do not allow new outgoing transaction from a
-			 * thread that has a transaction at the head of
-			 * its todo list. Only need to check the head
-			 * because binder_select_thread_ilocked picks a
-			 * thread from proc->waiting_threads to enqueue
-			 * the transaction, and nothing is queued to the
-			 * todo list while the thread is on waiting_threads.
-			 */
-			binder_user_error("%d:%d new transaction not allowed when there is a transaction on thread todo\n",
-					  proc->pid, thread->pid);
-			binder_inner_proc_unlock(proc);
-			return_error = BR_FAILED_REPLY;
-			return_error_param = -EPROTO;
-			return_error_line = __LINE__;
-			goto err_bad_todo_list;
-		}
-
 		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
 			struct binder_transaction *tmp;
 
@@ -3289,11 +3180,11 @@ static void binder_transaction(struct binder_proc *proc,
 				    ALIGN(tr->offsets_size, sizeof(void *)) +
 				    ALIGN(extra_buffers_size, sizeof(void *)) -
 				    ALIGN(secctx_sz, sizeof(u64));
+		char *kptr = t->buffer->data + buf_offset;
 
-		t->security_ctx = (uintptr_t)t->buffer->user_data + buf_offset;
-		binder_alloc_copy_to_buffer(&target_proc->alloc,
-					    t->buffer, buf_offset,
-					    secctx, secctx_sz);
+		t->security_ctx = (uintptr_t)kptr +
+		    binder_alloc_get_user_buffer_offset(&target_proc->alloc);
+		memcpy(kptr, secctx, secctx_sz);
 		security_release_secctx(secctx, secctx_sz);
 		secctx = NULL;
 	}
@@ -3301,13 +3192,12 @@ static void binder_transaction(struct binder_proc *proc,
 	t->buffer->transaction = t;
 	t->buffer->target_node = target_node;
 	trace_binder_transaction_alloc_buf(t->buffer);
+	off_start = (binder_size_t *)(t->buffer->data +
+				      ALIGN(tr->data_size, sizeof(void *)));
+	offp = off_start;
 
-	if (binder_alloc_copy_user_to_buffer(
-				&target_proc->alloc,
-				t->buffer, 0,
-				(const void __user *)
-					(uintptr_t)tr->data.ptr.buffer,
-				tr->data_size)) {
+	if (copy_from_user(t->buffer->data, (const void __user *)(uintptr_t)
+			   tr->data.ptr.buffer, tr->data_size)) {
 		binder_user_error("%d:%d got transaction with invalid data ptr\n",
 				proc->pid, thread->pid);
 		return_error = BR_FAILED_REPLY;
@@ -3315,13 +3205,8 @@ static void binder_transaction(struct binder_proc *proc,
 		return_error_line = __LINE__;
 		goto err_copy_data_failed;
 	}
-	if (binder_alloc_copy_user_to_buffer(
-				&target_proc->alloc,
-				t->buffer,
-				ALIGN(tr->data_size, sizeof(void *)),
-				(const void __user *)
-					(uintptr_t)tr->data.ptr.offsets,
-				tr->offsets_size)) {
+	if (copy_from_user(offp, (const void __user *)(uintptr_t)
+			   tr->data.ptr.offsets, tr->offsets_size)) {
 		binder_user_error("%d:%d got transaction with invalid offsets ptr\n",
 				proc->pid, thread->pid);
 		return_error = BR_FAILED_REPLY;
@@ -3346,31 +3231,18 @@ static void binder_transaction(struct binder_proc *proc,
 		return_error_line = __LINE__;
 		goto err_bad_offset;
 	}
-	off_start_offset = ALIGN(tr->data_size, sizeof(void *));
-	buffer_offset = off_start_offset;
-	off_end_offset = off_start_offset + tr->offsets_size;
-	sg_buf_offset = ALIGN(off_end_offset, sizeof(void *));
-	sg_buf_end_offset = sg_buf_offset + extra_buffers_size -
+	off_end = (void *)off_start + tr->offsets_size;
+	sg_bufp = (u8 *)(PTR_ALIGN(off_end, sizeof(void *)));
+	sg_buf_end = sg_bufp + extra_buffers_size -
 		ALIGN(secctx_sz, sizeof(u64));
 	off_min = 0;
-	for (buffer_offset = off_start_offset; buffer_offset < off_end_offset;
-	     buffer_offset += sizeof(binder_size_t)) {
+	for (; offp < off_end; offp++) {
 		struct binder_object_header *hdr;
-		size_t object_size;
-		struct binder_object object;
-		binder_size_t object_offset;
-
-		binder_alloc_copy_from_buffer(&target_proc->alloc,
-					      &object_offset,
-					      t->buffer,
-					      buffer_offset,
-					      sizeof(object_offset));
-		object_size = binder_get_object(target_proc, t->buffer,
-						object_offset, &object);
-		if (object_size == 0 || object_offset < off_min) {
+		size_t object_size = binder_validate_object(t->buffer, *offp);
+
+		if (object_size == 0 || *offp < off_min) {
 			binder_user_error("%d:%d got transaction with invalid offset (%lld, min %lld max %lld) or object.\n",
-					  proc->pid, thread->pid,
-					  (u64)object_offset,
+					  proc->pid, thread->pid, (u64)*offp,
 					  (u64)off_min,
 					  (u64)t->buffer->data_size);
 			return_error = BR_FAILED_REPLY;
@@ -3379,8 +3251,8 @@ static void binder_transaction(struct binder_proc *proc,
 			goto err_bad_offset;
 		}
 
-		hdr = &object.hdr;
-		off_min = object_offset + object_size;
+		hdr = (struct binder_object_header *)(t->buffer->data + *offp);
+		off_min = *offp + object_size;
 		switch (hdr->type) {
 		case BINDER_TYPE_BINDER:
 		case BINDER_TYPE_WEAK_BINDER: {
@@ -3394,9 +3266,6 @@ static void binder_transaction(struct binder_proc *proc,
 				return_error_line = __LINE__;
 				goto err_translate_failed;
 			}
-			binder_alloc_copy_to_buffer(&target_proc->alloc,
-						    t->buffer, object_offset,
-						    fp, sizeof(*fp));
 		} break;
 		case BINDER_TYPE_HANDLE:
 		case BINDER_TYPE_WEAK_HANDLE: {
@@ -3410,9 +3279,6 @@ static void binder_transaction(struct binder_proc *proc,
 				return_error_line = __LINE__;
 				goto err_translate_failed;
 			}
-			binder_alloc_copy_to_buffer(&target_proc->alloc,
-						    t->buffer, object_offset,
-						    fp, sizeof(*fp));
 		} break;
 
 		case BINDER_TYPE_FD: {
@@ -3428,23 +3294,14 @@ static void binder_transaction(struct binder_proc *proc,
 			}
 			fp->pad_binder = 0;
 			fp->fd = target_fd;
-			binder_alloc_copy_to_buffer(&target_proc->alloc,
-						    t->buffer, object_offset,
-						    fp, sizeof(*fp));
 		} break;
 		case BINDER_TYPE_FDA: {
-			struct binder_object ptr_object;
-			binder_size_t parent_offset;
 			struct binder_fd_array_object *fda =
 				to_binder_fd_array_object(hdr);
-			size_t num_valid = (buffer_offset - off_start_offset) /
-						sizeof(binder_size_t);
 			struct binder_buffer_object *parent =
-				binder_validate_ptr(target_proc, t->buffer,
-						    &ptr_object, fda->parent,
-						    off_start_offset,
-						    &parent_offset,
-						    num_valid);
+				binder_validate_ptr(t->buffer, fda->parent,
+						    off_start,
+						    offp - off_start);
 			if (!parent) {
 				binder_user_error("%d:%d got transaction with invalid parent offset or type\n",
 						  proc->pid, thread->pid);
@@ -3453,11 +3310,9 @@ static void binder_transaction(struct binder_proc *proc,
 				return_error_line = __LINE__;
 				goto err_bad_parent;
 			}
-			if (!binder_validate_fixup(target_proc, t->buffer,
-						   off_start_offset,
-						   parent_offset,
-						   fda->parent_offset,
-						   last_fixup_obj_off,
+			if (!binder_validate_fixup(t->buffer, off_start,
+						   parent, fda->parent_offset,
+						   last_fixup_obj,
 						   last_fixup_min_off)) {
 				binder_user_error("%d:%d got transaction with out-of-order buffer fixup\n",
 						  proc->pid, thread->pid);
@@ -3474,15 +3329,14 @@ static void binder_transaction(struct binder_proc *proc,
 				return_error_line = __LINE__;
 				goto err_translate_failed;
 			}
-			last_fixup_obj_off = parent_offset;
+			last_fixup_obj = parent;
 			last_fixup_min_off =
 				fda->parent_offset + sizeof(u32) * fda->num_fds;
 		} break;
 		case BINDER_TYPE_PTR: {
 			struct binder_buffer_object *bp =
 				to_binder_buffer_object(hdr);
-			size_t buf_left = sg_buf_end_offset - sg_buf_offset;
-			size_t num_valid;
+			size_t buf_left = sg_buf_end - sg_bufp;
 
 			if (bp->length > buf_left) {
 				binder_user_error("%d:%d got transaction with too large buffer\n",
@@ -3492,13 +3346,9 @@ static void binder_transaction(struct binder_proc *proc,
 				return_error_line = __LINE__;
 				goto err_bad_offset;
 			}
-			if (binder_alloc_copy_user_to_buffer(
-						&target_proc->alloc,
-						t->buffer,
-						sg_buf_offset,
-						(const void __user *)
-							(uintptr_t)bp->buffer,
-						bp->length)) {
+			if (copy_from_user(sg_bufp,
+					   (const void __user *)(uintptr_t)
+					   bp->buffer, bp->length)) {
 				binder_user_error("%d:%d got transaction with invalid offsets ptr\n",
 						  proc->pid, thread->pid);
 				return_error_param = -EFAULT;
@@ -3507,16 +3357,14 @@ static void binder_transaction(struct binder_proc *proc,
 				goto err_copy_data_failed;
 			}
 			/* Fixup buffer pointer to target proc address space */
-			bp->buffer = (uintptr_t)
-				t->buffer->user_data + sg_buf_offset;
-			sg_buf_offset += ALIGN(bp->length, sizeof(u64));
-
-			num_valid = (buffer_offset - off_start_offset) /
-					sizeof(binder_size_t);
-			ret = binder_fixup_parent(t, thread, bp,
-						  off_start_offset,
-						  num_valid,
-						  last_fixup_obj_off,
+			bp->buffer = (uintptr_t)sg_bufp +
+				binder_alloc_get_user_buffer_offset(
+						&target_proc->alloc);
+			sg_bufp += ALIGN(bp->length, sizeof(u64));
+
+			ret = binder_fixup_parent(t, thread, bp, off_start,
+						  offp - off_start,
+						  last_fixup_obj,
 						  last_fixup_min_off);
 			if (ret < 0) {
 				return_error = BR_FAILED_REPLY;
@@ -3524,10 +3372,7 @@ static void binder_transaction(struct binder_proc *proc,
 				return_error_line = __LINE__;
 				goto err_translate_failed;
 			}
-			binder_alloc_copy_to_buffer(&target_proc->alloc,
-						    t->buffer, object_offset,
-						    bp, sizeof(*bp));
-			last_fixup_obj_off = object_offset;
+			last_fixup_obj = bp;
 			last_fixup_min_off = 0;
 		} break;
 		default:
@@ -3607,8 +3452,7 @@ err_bad_offset:
 err_bad_parent:
 err_copy_data_failed:
 	trace_binder_transaction_failed_buffer_release(t->buffer);
-	binder_transaction_buffer_release(target_proc, t->buffer,
-					  buffer_offset, true);
+	binder_transaction_buffer_release(target_proc, t->buffer, offp);
 	if (target_node)
 		binder_dec_node_tmpref(target_node);
 	target_node = NULL;
@@ -3625,7 +3469,6 @@ err_alloc_tcomplete_failed:
 	kfree(t);
 	binder_stats_deleted(BINDER_STAT_TRANSACTION);
 err_alloc_t_failed:
-err_bad_todo_list:
 err_bad_call_stack:
 err_empty_call_stack:
 err_dead_binder:
@@ -3898,7 +3741,7 @@ static int binder_thread_write(struct binder_proc *proc,
 				binder_node_inner_unlock(buf_node);
 			}
 			trace_binder_transaction_buffer_release(buffer);
-			binder_transaction_buffer_release(proc, buffer, 0, false);
+			binder_transaction_buffer_release(proc, buffer, NULL);
 			binder_alloc_free_buf(&proc->alloc, buffer);
 			break;
 		}
@@ -4323,13 +4166,11 @@ retry:
 			e->cmd = BR_OK;
 			ptr += sizeof(uint32_t);
 
-			binder_stat_br(proc, thread, e->cmd);
+			binder_stat_br(proc, thread, cmd);
 		} break;
 		case BINDER_WORK_TRANSACTION_COMPLETE: {
 			binder_inner_proc_unlock(proc);
 			cmd = BR_TRANSACTION_COMPLETE;
-			kfree(w);
-			binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
 			if (put_user(cmd, (uint32_t __user *)ptr))
 				return -EFAULT;
 			ptr += sizeof(uint32_t);
@@ -4338,6 +4179,8 @@ retry:
 			binder_debug(BINDER_DEBUG_TRANSACTION_COMPLETE,
 				     "%d:%d BR_TRANSACTION_COMPLETE\n",
 				     proc->pid, thread->pid);
+			kfree(w);
+			binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
 		} break;
 		case BINDER_WORK_NODE: {
 			struct binder_node *node = container_of(w, struct binder_node, work);
@@ -4506,7 +4349,9 @@ retry:
 
 		trd->data_size = t->buffer->data_size;
 		trd->offsets_size = t->buffer->offsets_size;
-		trd->data.ptr.buffer = (uintptr_t)t->buffer->user_data;
+		trd->data.ptr.buffer = (binder_uintptr_t)
+			((uintptr_t)t->buffer->data +
+			binder_alloc_get_user_buffer_offset(&proc->alloc));
 		trd->data.ptr.offsets = trd->data.ptr.buffer +
 					ALIGN(t->buffer->data_size,
 					    sizeof(void *));
@@ -4744,7 +4589,7 @@ static int binder_thread_release(struct binder_proc *proc,
 	 * The corresponding dec is when we actually
 	 * free the thread in binder_free_thread()
 	 */
-	proc->tmp_ref++;
+	atomic_inc(&proc->tmp_ref);
 	/*
 	 * take a ref on this thread to ensure it
 	 * survives while we are releasing it
@@ -4790,10 +4635,8 @@ static int binder_thread_release(struct binder_proc *proc,
 	 * If this thread used poll, make sure we remove the waitqueue from any
 	 * poll data structures holding it.
 	 */
-	if ((thread->looper & BINDER_LOOPER_STATE_POLL) &&
-	    waitqueue_active(&thread->wait)) {
-		wake_up_poll(&thread->wait, EPOLLHUP | POLLFREE);
-	}
+	if (thread->looper & BINDER_LOOPER_STATE_POLL)
+		wake_up_pollfree(&thread->wait);
 
 	binder_inner_proc_unlock(thread->proc);
 
@@ -4834,7 +4677,7 @@ static unsigned int binder_poll(struct file *filp,
 	poll_wait(filp, &thread->wait, wait);
 
 	if (binder_has_work(thread, wait_for_proc_work))
-		return EPOLLIN;
+		return POLLIN;
 
 	return 0;
 }
@@ -4990,8 +4833,7 @@ static int binder_ioctl_get_node_info_for_ref(struct binder_proc *proc,
 }
 
 static int binder_ioctl_get_node_debug_info(struct binder_proc *proc,
-				struct binder_node_debug_info *info)
-{
+				struct binder_node_debug_info *info) {
 	struct rb_node *n;
 	binder_uintptr_t ptr = info->ptr;
 
@@ -5239,6 +5081,7 @@ static int binder_open(struct inode *nodp, struct file *filp)
 		return -ENOMEM;
 	spin_lock_init(&proc->inner_lock);
 	spin_lock_init(&proc->outer_lock);
+	atomic_set(&proc->tmp_ref, 0);
 	get_task_struct(current->group_leader);
 	proc->tsk = current->group_leader;
 	mutex_init(&proc->files_lock);
@@ -5419,7 +5262,7 @@ static void binder_deferred_release(struct binder_proc *proc)
 	 * Make sure proc stays alive after we
 	 * remove all the threads
 	 */
-	proc->tmp_ref++;
+	atomic_inc(&proc->tmp_ref);
 
 	proc->is_dead = true;
 	threads = 0;
@@ -5529,7 +5372,7 @@ binder_defer_work(struct binder_proc *proc, enum binder_deferred_state defer)
 	if (hlist_unhashed(&proc->deferred_work_node)) {
 		hlist_add_head(&proc->deferred_work_node,
 				&binder_deferred_list);
-		schedule_work(&binder_deferred_work);
+		queue_work(binder_deferred_workqueue, &binder_deferred_work);
 	}
 	mutex_unlock(&binder_deferred_lock);
 }
@@ -5572,7 +5415,7 @@ static void print_binder_transaction_ilocked(struct seq_file *m,
 		seq_printf(m, " node %d", buffer->target_node->debug_id);
 	seq_printf(m, " size %zd:%zd data %pK\n",
 		   buffer->data_size, buffer->offsets_size,
-		   buffer->user_data);
+		   buffer->data);
 }
 
 static void print_binder_work_ilocked(struct seq_file *m,
@@ -6118,6 +5961,9 @@ static int __init binder_init(void)
 
 	atomic_set(&binder_transaction_log.cur, ~0U);
 	atomic_set(&binder_transaction_log_failed.cur, ~0U);
+	binder_deferred_workqueue = create_singlethread_workqueue("binder");
+	if (!binder_deferred_workqueue)
+		return -ENOMEM;
 
 	binder_debugfs_dir_entry_root = debugfs_create_dir("binder", NULL);
 	if (binder_debugfs_dir_entry_root)
@@ -6184,6 +6030,8 @@ err_init_binder_device_failed:
 err_alloc_device_names_failed:
 	debugfs_remove_recursive(binder_debugfs_dir_entry_root);
 
+	destroy_workqueue(binder_deferred_workqueue);
+
 	return ret;
 }
 
diff --git a/drivers/android/binder_alloc.c b/drivers/android/binder_alloc.c
index c9e6c941f669..8dd79c8057f7 100644
--- a/drivers/android/binder_alloc.c
+++ b/drivers/android/binder_alloc.c
@@ -17,6 +17,7 @@
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <asm/cacheflush.h>
 #include <linux/list.h>
 #include <linux/mm.h>
 #include <linux/module.h>
@@ -28,9 +29,6 @@
 #include <linux/sched.h>
 #include <linux/list_lru.h>
 #include <linux/ratelimit.h>
-#include <asm/cacheflush.h>
-#include <linux/uaccess.h>
-#include <linux/highmem.h>
 #include "binder_alloc.h"
 #include "binder_trace.h"
 
@@ -44,10 +42,10 @@ enum {
 	BINDER_DEBUG_BUFFER_ALLOC           = 1U << 2,
 	BINDER_DEBUG_BUFFER_ALLOC_ASYNC     = 1U << 3,
 };
-static uint32_t binder_alloc_debug_mask = BINDER_DEBUG_USER_ERROR;
+static uint32_t binder_alloc_debug_mask;
 
 module_param_named(debug_mask, binder_alloc_debug_mask,
-		   uint, 0644);
+		   uint, S_IWUSR | S_IRUGO);
 
 #define binder_alloc_debug(mask, x...) \
 	do { \
@@ -69,8 +67,9 @@ static size_t binder_alloc_buffer_size(struct binder_alloc *alloc,
 				       struct binder_buffer *buffer)
 {
 	if (list_is_last(&buffer->entry, &alloc->buffers))
-		return alloc->buffer + alloc->buffer_size - buffer->user_data;
-	return binder_buffer_next(buffer)->user_data - buffer->user_data;
+		return (u8 *)alloc->buffer +
+			alloc->buffer_size - (u8 *)buffer->data;
+	return (u8 *)binder_buffer_next(buffer)->data - (u8 *)buffer->data;
 }
 
 static void binder_insert_free_buffer(struct binder_alloc *alloc,
@@ -120,9 +119,9 @@ static void binder_insert_allocated_buffer_locked(
 		buffer = rb_entry(parent, struct binder_buffer, rb_node);
 		BUG_ON(buffer->free);
 
-		if (new_buffer->user_data < buffer->user_data)
+		if (new_buffer->data < buffer->data)
 			p = &parent->rb_left;
-		else if (new_buffer->user_data > buffer->user_data)
+		else if (new_buffer->data > buffer->data)
 			p = &parent->rb_right;
 		else
 			BUG();
@@ -137,17 +136,17 @@ static struct binder_buffer *binder_alloc_prepare_to_free_locked(
 {
 	struct rb_node *n = alloc->allocated_buffers.rb_node;
 	struct binder_buffer *buffer;
-	void __user *uptr;
+	void *kern_ptr;
 
-	uptr = (void __user *)user_ptr;
+	kern_ptr = (void *)(user_ptr - alloc->user_buffer_offset);
 
 	while (n) {
 		buffer = rb_entry(n, struct binder_buffer, rb_node);
 		BUG_ON(buffer->free);
 
-		if (uptr < buffer->user_data)
+		if (kern_ptr < buffer->data)
 			n = n->rb_left;
-		else if (uptr > buffer->user_data)
+		else if (kern_ptr > buffer->data)
 			n = n->rb_right;
 		else {
 			/*
@@ -187,9 +186,9 @@ struct binder_buffer *binder_alloc_prepare_to_free(struct binder_alloc *alloc,
 }
 
 static int binder_update_page_range(struct binder_alloc *alloc, int allocate,
-				    void __user *start, void __user *end)
+				    void *start, void *end)
 {
-	void __user *page_addr;
+	void *page_addr;
 	unsigned long user_page_addr;
 	struct binder_lru_page *page;
 	struct vm_area_struct *vma = NULL;
@@ -216,11 +215,17 @@ static int binder_update_page_range(struct binder_alloc *alloc, int allocate,
 		}
 	}
 
-	if (need_mm && mmget_not_zero(alloc->vma_vm_mm))
+	/* Same as mmget_not_zero() in later kernel versions */
+	if (need_mm && atomic_inc_not_zero(&alloc->vma_vm_mm->mm_users))
 		mm = alloc->vma_vm_mm;
 
 	if (mm) {
 		down_read(&mm->mmap_sem);
+		if (!mmget_still_valid(mm)) {
+			if (allocate == 0)
+				goto free_range;
+			goto err_no_vma;
+		}
 		vma = alloc->vma;
 	}
 
@@ -264,7 +269,18 @@ static int binder_update_page_range(struct binder_alloc *alloc, int allocate,
 		page->alloc = alloc;
 		INIT_LIST_HEAD(&page->lru);
 
-		user_page_addr = (uintptr_t)page_addr;
+		ret = map_kernel_range_noflush((unsigned long)page_addr,
+					       PAGE_SIZE, PAGE_KERNEL,
+					       &page->page_ptr);
+		flush_cache_vmap((unsigned long)page_addr,
+				(unsigned long)page_addr + PAGE_SIZE);
+		if (ret != 1) {
+			pr_err("%d: binder_alloc_buf failed to map page at %pK in kernel\n",
+			       alloc->pid, page_addr);
+			goto err_map_kernel_failed;
+		}
+		user_page_addr =
+			(uintptr_t)page_addr + alloc->user_buffer_offset;
 		ret = vm_insert_page(vma, user_page_addr, page[0].page_ptr);
 		if (ret) {
 			pr_err("%d: binder_alloc_buf failed to map page at %lx in userspace\n",
@@ -285,7 +301,8 @@ static int binder_update_page_range(struct binder_alloc *alloc, int allocate,
 	return 0;
 
 free_range:
-	for (page_addr = end - PAGE_SIZE; 1; page_addr -= PAGE_SIZE) {
+	for (page_addr = end - PAGE_SIZE; page_addr >= start;
+	     page_addr -= PAGE_SIZE) {
 		bool ret;
 		size_t index;
 
@@ -298,17 +315,16 @@ free_range:
 		WARN_ON(!ret);
 
 		trace_binder_free_lru_end(alloc, index);
-		if (page_addr == start)
-			break;
 		continue;
 
 err_vm_insert_page_failed:
+		unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
+err_map_kernel_failed:
 		__free_page(page->page_ptr);
 		page->page_ptr = NULL;
 err_alloc_page_failed:
 err_page_ptr_cleared:
-		if (page_addr == start)
-			break;
+		;
 	}
 err_no_vma:
 	if (mm) {
@@ -318,35 +334,6 @@ err_no_vma:
 	return vma ? -ENOMEM : -ESRCH;
 }
 
-
-static inline void binder_alloc_set_vma(struct binder_alloc *alloc,
-		struct vm_area_struct *vma)
-{
-	if (vma)
-		alloc->vma_vm_mm = vma->vm_mm;
-	/*
-	 * If we see alloc->vma is not NULL, buffer data structures set up
-	 * completely. Look at smp_rmb side binder_alloc_get_vma.
-	 * We also want to guarantee new alloc->vma_vm_mm is always visible
-	 * if alloc->vma is set.
-	 */
-	smp_wmb();
-	alloc->vma = vma;
-}
-
-static inline struct vm_area_struct *binder_alloc_get_vma(
-		struct binder_alloc *alloc)
-{
-	struct vm_area_struct *vma = NULL;
-
-	if (alloc->vma) {
-		/* Look at description in binder_alloc_set_vma */
-		smp_rmb();
-		vma = alloc->vma;
-	}
-	return vma;
-}
-
 static struct binder_buffer *binder_alloc_new_buf_locked(
 				struct binder_alloc *alloc,
 				size_t data_size,
@@ -358,12 +345,12 @@ static struct binder_buffer *binder_alloc_new_buf_locked(
 	struct binder_buffer *buffer;
 	size_t buffer_size;
 	struct rb_node *best_fit = NULL;
-	void __user *has_page_addr;
-	void __user *end_page_addr;
+	void *has_page_addr;
+	void *end_page_addr;
 	size_t size, data_offsets_size;
 	int ret;
 
-	if (!binder_alloc_get_vma(alloc)) {
+	if (alloc->vma == NULL) {
 		binder_alloc_debug(BINDER_DEBUG_USER_ERROR,
 				   "%d: binder_alloc_buf, no vma\n",
 				   alloc->pid);
@@ -457,15 +444,15 @@ static struct binder_buffer *binder_alloc_new_buf_locked(
 		     "%d: binder_alloc_buf size %zd got buffer %pK size %zd\n",
 		      alloc->pid, size, buffer, buffer_size);
 
-	has_page_addr = (void __user *)
-		(((uintptr_t)buffer->user_data + buffer_size) & PAGE_MASK);
+	has_page_addr =
+		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
 	WARN_ON(n && buffer_size != size);
 	end_page_addr =
-		(void __user *)PAGE_ALIGN((uintptr_t)buffer->user_data + size);
+		(void *)PAGE_ALIGN((uintptr_t)buffer->data + size);
 	if (end_page_addr > has_page_addr)
 		end_page_addr = has_page_addr;
-	ret = binder_update_page_range(alloc, 1, (void __user *)
-		PAGE_ALIGN((uintptr_t)buffer->user_data), end_page_addr);
+	ret = binder_update_page_range(alloc, 1,
+	    (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr);
 	if (ret)
 		return ERR_PTR(ret);
 
@@ -478,7 +465,7 @@ static struct binder_buffer *binder_alloc_new_buf_locked(
 			       __func__, alloc->pid);
 			goto err_alloc_buf_struct_failed;
 		}
-		new_buffer->user_data = (u8 __user *)buffer->user_data + size;
+		new_buffer->data = (u8 *)buffer->data + size;
 		list_add(&new_buffer->entry, &buffer->entry);
 		new_buffer->free = 1;
 		binder_insert_free_buffer(alloc, new_buffer);
@@ -504,8 +491,8 @@ static struct binder_buffer *binder_alloc_new_buf_locked(
 	return buffer;
 
 err_alloc_buf_struct_failed:
-	binder_update_page_range(alloc, 0, (void __user *)
-				 PAGE_ALIGN((uintptr_t)buffer->user_data),
+	binder_update_page_range(alloc, 0,
+				 (void *)PAGE_ALIGN((uintptr_t)buffer->data),
 				 end_page_addr);
 	return ERR_PTR(-ENOMEM);
 }
@@ -540,15 +527,14 @@ struct binder_buffer *binder_alloc_new_buf(struct binder_alloc *alloc,
 	return buffer;
 }
 
-static void __user *buffer_start_page(struct binder_buffer *buffer)
+static void *buffer_start_page(struct binder_buffer *buffer)
 {
-	return (void __user *)((uintptr_t)buffer->user_data & PAGE_MASK);
+	return (void *)((uintptr_t)buffer->data & PAGE_MASK);
 }
 
-static void __user *prev_buffer_end_page(struct binder_buffer *buffer)
+static void *prev_buffer_end_page(struct binder_buffer *buffer)
 {
-	return (void __user *)
-		(((uintptr_t)(buffer->user_data) - 1) & PAGE_MASK);
+	return (void *)(((uintptr_t)(buffer->data) - 1) & PAGE_MASK);
 }
 
 static void binder_delete_free_buffer(struct binder_alloc *alloc,
@@ -563,8 +549,7 @@ static void binder_delete_free_buffer(struct binder_alloc *alloc,
 		to_free = false;
 		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
 				   "%d: merge free, buffer %pK share page with %pK\n",
-				   alloc->pid, buffer->user_data,
-				   prev->user_data);
+				   alloc->pid, buffer->data, prev->data);
 	}
 
 	if (!list_is_last(&buffer->entry, &alloc->buffers)) {
@@ -574,24 +559,23 @@ static void binder_delete_free_buffer(struct binder_alloc *alloc,
 			binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
 					   "%d: merge free, buffer %pK share page with %pK\n",
 					   alloc->pid,
-					   buffer->user_data,
-					   next->user_data);
+					   buffer->data,
+					   next->data);
 		}
 	}
 
-	if (PAGE_ALIGNED(buffer->user_data)) {
+	if (PAGE_ALIGNED(buffer->data)) {
 		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
 				   "%d: merge free, buffer start %pK is page aligned\n",
-				   alloc->pid, buffer->user_data);
+				   alloc->pid, buffer->data);
 		to_free = false;
 	}
 
 	if (to_free) {
 		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
 				   "%d: merge free, buffer %pK do not share page with %pK or %pK\n",
-				   alloc->pid, buffer->user_data,
-				   prev->user_data,
-				   next ? next->user_data : NULL);
+				   alloc->pid, buffer->data,
+				   prev->data, next ? next->data : NULL);
 		binder_update_page_range(alloc, 0, buffer_start_page(buffer),
 					 buffer_start_page(buffer) + PAGE_SIZE);
 	}
@@ -617,8 +601,8 @@ static void binder_free_buf_locked(struct binder_alloc *alloc,
 	BUG_ON(buffer->free);
 	BUG_ON(size > buffer_size);
 	BUG_ON(buffer->transaction != NULL);
-	BUG_ON(buffer->user_data < alloc->buffer);
-	BUG_ON(buffer->user_data > alloc->buffer + alloc->buffer_size);
+	BUG_ON(buffer->data < alloc->buffer);
+	BUG_ON(buffer->data > alloc->buffer + alloc->buffer_size);
 
 	if (buffer->async_transaction) {
 		alloc->free_async_space += size + sizeof(struct binder_buffer);
@@ -629,9 +613,8 @@ static void binder_free_buf_locked(struct binder_alloc *alloc,
 	}
 
 	binder_update_page_range(alloc, 0,
-		(void __user *)PAGE_ALIGN((uintptr_t)buffer->user_data),
-		(void __user *)(((uintptr_t)
-			  buffer->user_data + buffer_size) & PAGE_MASK));
+		(void *)PAGE_ALIGN((uintptr_t)buffer->data),
+		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK));
 
 	rb_erase(&buffer->rb_node, &alloc->allocated_buffers);
 	buffer->free = 1;
@@ -687,6 +670,7 @@ int binder_alloc_mmap_handler(struct binder_alloc *alloc,
 			      struct vm_area_struct *vma)
 {
 	int ret;
+	struct vm_struct *area;
 	const char *failure_string;
 	struct binder_buffer *buffer;
 
@@ -697,11 +681,30 @@ int binder_alloc_mmap_handler(struct binder_alloc *alloc,
 		goto err_already_mapped;
 	}
 
-	alloc->buffer = (void __user *)vma->vm_start;
+	area = get_vm_area(vma->vm_end - vma->vm_start, VM_ALLOC);
+	if (area == NULL) {
+		ret = -ENOMEM;
+		failure_string = "get_vm_area";
+		goto err_get_vm_area_failed;
+	}
+	alloc->buffer = area->addr;
+	alloc->user_buffer_offset =
+		vma->vm_start - (uintptr_t)alloc->buffer;
 	mutex_unlock(&binder_alloc_mmap_lock);
 
-	alloc->pages = kcalloc((vma->vm_end - vma->vm_start) / PAGE_SIZE,
-			       sizeof(alloc->pages[0]),
+#ifdef CONFIG_CPU_CACHE_VIPT
+	if (cache_is_vipt_aliasing()) {
+		while (CACHE_COLOUR(
+				(vma->vm_start ^ (uint32_t)alloc->buffer))) {
+			pr_info("binder_mmap: %d %lx-%lx maps %pK bad alignment\n",
+				alloc->pid, vma->vm_start, vma->vm_end,
+				alloc->buffer);
+			vma->vm_start += PAGE_SIZE;
+		}
+	}
+#endif
+	alloc->pages = kzalloc(sizeof(alloc->pages[0]) *
+				   ((vma->vm_end - vma->vm_start) / PAGE_SIZE),
 			       GFP_KERNEL);
 	if (alloc->pages == NULL) {
 		ret = -ENOMEM;
@@ -717,12 +720,15 @@ int binder_alloc_mmap_handler(struct binder_alloc *alloc,
 		goto err_alloc_buf_struct_failed;
 	}
 
-	buffer->user_data = alloc->buffer;
+	buffer->data = alloc->buffer;
 	list_add(&buffer->entry, &alloc->buffers);
 	buffer->free = 1;
 	binder_insert_free_buffer(alloc, buffer);
 	alloc->free_async_space = alloc->buffer_size / 2;
-	binder_alloc_set_vma(alloc, vma);
+	barrier();
+	alloc->vma = vma;
+	alloc->vma_vm_mm = vma->vm_mm;
+	/* Same as mmgrab() in later kernel versions */
 	atomic_inc(&alloc->vma_vm_mm->mm_count);
 
 	return 0;
@@ -732,7 +738,9 @@ err_alloc_buf_struct_failed:
 	alloc->pages = NULL;
 err_alloc_pages_failed:
 	mutex_lock(&binder_alloc_mmap_lock);
+	vfree(alloc->buffer);
 	alloc->buffer = NULL;
+err_get_vm_area_failed:
 err_already_mapped:
 	mutex_unlock(&binder_alloc_mmap_lock);
 	binder_alloc_debug(BINDER_DEBUG_USER_ERROR,
@@ -749,10 +757,10 @@ void binder_alloc_deferred_release(struct binder_alloc *alloc)
 	int buffers, page_count;
 	struct binder_buffer *buffer;
 
-	buffers = 0;
-	mutex_lock(&alloc->mutex);
 	BUG_ON(alloc->vma);
 
+	buffers = 0;
+	mutex_lock(&alloc->mutex);
 	while ((n = rb_first(&alloc->allocated_buffers))) {
 		buffer = rb_entry(n, struct binder_buffer, rb_node);
 
@@ -778,7 +786,7 @@ void binder_alloc_deferred_release(struct binder_alloc *alloc)
 		int i;
 
 		for (i = 0; i < alloc->buffer_size / PAGE_SIZE; i++) {
-			void __user *page_addr;
+			void *page_addr;
 			bool on_lru;
 
 			if (!alloc->pages[i].page_ptr)
@@ -791,10 +799,12 @@ void binder_alloc_deferred_release(struct binder_alloc *alloc)
 				     "%s: %d: page %d at %pK %s\n",
 				     __func__, alloc->pid, i, page_addr,
 				     on_lru ? "on lru" : "active");
+			unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
 			__free_page(alloc->pages[i].page_ptr);
 			page_count++;
 		}
 		kfree(alloc->pages);
+		vfree(alloc->buffer);
 	}
 	mutex_unlock(&alloc->mutex);
 	if (alloc->vma_vm_mm)
@@ -809,7 +819,7 @@ static void print_binder_buffer(struct seq_file *m, const char *prefix,
 				struct binder_buffer *buffer)
 {
 	seq_printf(m, "%s %d: %pK size %zd:%zd:%zd %s\n",
-		   prefix, buffer->debug_id, buffer->user_data,
+		   prefix, buffer->debug_id, buffer->data,
 		   buffer->data_size, buffer->offsets_size,
 		   buffer->extra_buffers_size,
 		   buffer->transaction ? "active" : "delivered");
@@ -850,20 +860,14 @@ void binder_alloc_print_pages(struct seq_file *m,
 	int free = 0;
 
 	mutex_lock(&alloc->mutex);
-	/*
-	 * Make sure the binder_alloc is fully initialized, otherwise we might
-	 * read inconsistent state.
-	 */
-	if (binder_alloc_get_vma(alloc) != NULL) {
-		for (i = 0; i < alloc->buffer_size / PAGE_SIZE; i++) {
-			page = &alloc->pages[i];
-			if (!page->page_ptr)
-				free++;
-			else if (list_empty(&page->lru))
-				active++;
-			else
-				lru++;
-		}
+	for (i = 0; i < alloc->buffer_size / PAGE_SIZE; i++) {
+		page = &alloc->pages[i];
+		if (!page->page_ptr)
+			free++;
+		else if (list_empty(&page->lru))
+			active++;
+		else
+			lru++;
 	}
 	mutex_unlock(&alloc->mutex);
 	seq_printf(m, "  pages: %d:%d:%d\n", active, lru, free);
@@ -899,7 +903,7 @@ int binder_alloc_get_allocated_count(struct binder_alloc *alloc)
  */
 void binder_alloc_vma_close(struct binder_alloc *alloc)
 {
-	binder_alloc_set_vma(alloc, NULL);
+	WRITE_ONCE(alloc->vma, NULL);
 }
 
 /**
@@ -936,11 +940,12 @@ enum lru_status binder_alloc_free_page(struct list_head *item,
 	page_addr = (uintptr_t)alloc->buffer + index * PAGE_SIZE;
 
 	mm = alloc->vma_vm_mm;
-	if (!mmget_not_zero(mm))
+	/* Same as mmget_not_zero() in later kernel versions */
+	if (!atomic_inc_not_zero(&alloc->vma_vm_mm->mm_users))
 		goto err_mmget;
 	if (!down_write_trylock(&mm->mmap_sem))
 		goto err_down_write_mmap_sem_failed;
-	vma = binder_alloc_get_vma(alloc);
+	vma = alloc->vma;
 
 	list_lru_isolate(lru, item);
 	spin_unlock(lock);
@@ -948,7 +953,10 @@ enum lru_status binder_alloc_free_page(struct list_head *item,
 	if (vma) {
 		trace_binder_unmap_user_start(alloc, index);
 
-		zap_page_range(vma, page_addr, PAGE_SIZE, NULL);
+		zap_page_range(vma,
+			       page_addr +
+			       alloc->user_buffer_offset,
+			       PAGE_SIZE, NULL);
 
 		trace_binder_unmap_user_end(alloc, index);
 	}
@@ -957,6 +965,7 @@ enum lru_status binder_alloc_free_page(struct list_head *item,
 
 	trace_binder_unmap_kernel_start(alloc, index);
 
+	unmap_kernel_range(page_addr, PAGE_SIZE);
 	__free_page(page->page_ptr);
 	page->page_ptr = NULL;
 
@@ -1023,173 +1032,3 @@ int binder_alloc_shrinker_init(void)
 	}
 	return ret;
 }
-
-/**
- * check_buffer() - verify that buffer/offset is safe to access
- * @alloc: binder_alloc for this proc
- * @buffer: binder buffer to be accessed
- * @offset: offset into @buffer data
- * @bytes: bytes to access from offset
- *
- * Check that the @offset/@bytes are within the size of the given
- * @buffer and that the buffer is currently active and not freeable.
- * Offsets must also be multiples of sizeof(u32). The kernel is
- * allowed to touch the buffer in two cases:
- *
- * 1) when the buffer is being created:
- *     (buffer->free == 0 && buffer->allow_user_free == 0)
- * 2) when the buffer is being torn down:
- *     (buffer->free == 0 && buffer->transaction == NULL).
- *
- * Return: true if the buffer is safe to access
- */
-static inline bool check_buffer(struct binder_alloc *alloc,
-				struct binder_buffer *buffer,
-				binder_size_t offset, size_t bytes)
-{
-	size_t buffer_size = binder_alloc_buffer_size(alloc, buffer);
-
-	return buffer_size >= bytes &&
-		offset <= buffer_size - bytes &&
-		IS_ALIGNED(offset, sizeof(u32)) &&
-		!buffer->free &&
-		(!buffer->allow_user_free || !buffer->transaction);
-}
-
-/**
- * binder_alloc_get_page() - get kernel pointer for given buffer offset
- * @alloc: binder_alloc for this proc
- * @buffer: binder buffer to be accessed
- * @buffer_offset: offset into @buffer data
- * @pgoffp: address to copy final page offset to
- *
- * Lookup the struct page corresponding to the address
- * at @buffer_offset into @buffer->user_data. If @pgoffp is not
- * NULL, the byte-offset into the page is written there.
- *
- * The caller is responsible to ensure that the offset points
- * to a valid address within the @buffer and that @buffer is
- * not freeable by the user. Since it can't be freed, we are
- * guaranteed that the corresponding elements of @alloc->pages[]
- * cannot change.
- *
- * Return: struct page
- */
-static struct page *binder_alloc_get_page(struct binder_alloc *alloc,
-					  struct binder_buffer *buffer,
-					  binder_size_t buffer_offset,
-					  pgoff_t *pgoffp)
-{
-	binder_size_t buffer_space_offset = buffer_offset +
-		(buffer->user_data - alloc->buffer);
-	pgoff_t pgoff = buffer_space_offset & ~PAGE_MASK;
-	size_t index = buffer_space_offset >> PAGE_SHIFT;
-	struct binder_lru_page *lru_page;
-
-	lru_page = &alloc->pages[index];
-	*pgoffp = pgoff;
-	return lru_page->page_ptr;
-}
-
-/**
- * binder_alloc_copy_user_to_buffer() - copy src user to tgt user
- * @alloc: binder_alloc for this proc
- * @buffer: binder buffer to be accessed
- * @buffer_offset: offset into @buffer data
- * @from: userspace pointer to source buffer
- * @bytes: bytes to copy
- *
- * Copy bytes from source userspace to target buffer.
- *
- * Return: bytes remaining to be copied
- */
-unsigned long
-binder_alloc_copy_user_to_buffer(struct binder_alloc *alloc,
-				 struct binder_buffer *buffer,
-				 binder_size_t buffer_offset,
-				 const void __user *from,
-				 size_t bytes)
-{
-	if (!check_buffer(alloc, buffer, buffer_offset, bytes))
-		return bytes;
-
-	while (bytes) {
-		unsigned long size;
-		unsigned long ret;
-		struct page *page;
-		pgoff_t pgoff;
-		void *kptr;
-
-		page = binder_alloc_get_page(alloc, buffer,
-					     buffer_offset, &pgoff);
-		size = min_t(size_t, bytes, PAGE_SIZE - pgoff);
-		kptr = kmap(page) + pgoff;
-		ret = copy_from_user(kptr, from, size);
-		kunmap(page);
-		if (ret)
-			return bytes - size + ret;
-		bytes -= size;
-		from += size;
-		buffer_offset += size;
-	}
-	return 0;
-}
-
-static void binder_alloc_do_buffer_copy(struct binder_alloc *alloc,
-					bool to_buffer,
-					struct binder_buffer *buffer,
-					binder_size_t buffer_offset,
-					void *ptr,
-					size_t bytes)
-{
-	/* All copies must be 32-bit aligned and 32-bit size */
-	BUG_ON(!check_buffer(alloc, buffer, buffer_offset, bytes));
-
-	while (bytes) {
-		unsigned long size;
-		struct page *page;
-		pgoff_t pgoff;
-		void *tmpptr;
-		void *base_ptr;
-
-		page = binder_alloc_get_page(alloc, buffer,
-					     buffer_offset, &pgoff);
-		size = min_t(size_t, bytes, PAGE_SIZE - pgoff);
-		base_ptr = kmap_atomic(page);
-		tmpptr = base_ptr + pgoff;
-		if (to_buffer)
-			memcpy(tmpptr, ptr, size);
-		else
-			memcpy(ptr, tmpptr, size);
-		/*
-		 * kunmap_atomic() takes care of flushing the cache
-		 * if this device has VIVT cache arch
-		 */
-		kunmap_atomic(base_ptr);
-		bytes -= size;
-		pgoff = 0;
-		ptr = ptr + size;
-		buffer_offset += size;
-	}
-}
-
-void binder_alloc_copy_to_buffer(struct binder_alloc *alloc,
-				 struct binder_buffer *buffer,
-				 binder_size_t buffer_offset,
-				 void *src,
-				 size_t bytes)
-{
-	binder_alloc_do_buffer_copy(alloc, true, buffer, buffer_offset,
-				    src, bytes);
-}
-
-void binder_alloc_copy_from_buffer(struct binder_alloc *alloc,
-				   void *dest,
-				   struct binder_buffer *buffer,
-				   binder_size_t buffer_offset,
-				   size_t bytes)
-{
-	binder_alloc_do_buffer_copy(alloc, false, buffer, buffer_offset,
-				    dest, bytes);
-}
-
diff --git a/drivers/android/binder_alloc.h b/drivers/android/binder_alloc.h
index b60d161b7a7a..fb3238c74c8a 100644
--- a/drivers/android/binder_alloc.h
+++ b/drivers/android/binder_alloc.h
@@ -22,7 +22,6 @@
 #include <linux/vmalloc.h>
 #include <linux/slab.h>
 #include <linux/list_lru.h>
-#include <uapi/linux/android/binder.h>
 
 extern struct list_lru binder_alloc_lru;
 struct binder_transaction;
@@ -31,16 +30,16 @@ struct binder_transaction;
  * struct binder_buffer - buffer used for binder transactions
  * @entry:              entry alloc->buffers
  * @rb_node:            node for allocated_buffers/free_buffers rb trees
- * @free:               %true if buffer is free
- * @allow_user_free:    %true if user is allowed to free buffer
- * @async_transaction:  %true if buffer is in use for an async txn
- * @debug_id:           unique ID for debugging
- * @transaction:        pointer to associated struct binder_transaction
- * @target_node:        struct binder_node associated with this buffer
- * @data_size:          size of @transaction data
- * @offsets_size:       size of array of offsets
- * @extra_buffers_size: size of space for other objects (like sg lists)
- * @user_data:          user pointer to base of buffer space
+ * @free:               true if buffer is free
+ * @allow_user_free:    describe the second member of struct blah,
+ * @async_transaction:  describe the second member of struct blah,
+ * @debug_id:           describe the second member of struct blah,
+ * @transaction:        describe the second member of struct blah,
+ * @target_node:        describe the second member of struct blah,
+ * @data_size:          describe the second member of struct blah,
+ * @offsets_size:       describe the second member of struct blah,
+ * @extra_buffers_size: describe the second member of struct blah,
+ * @data:i              describe the second member of struct blah,
  *
  * Bookkeeping structure for binder transaction buffers
  */
@@ -59,7 +58,7 @@ struct binder_buffer {
 	size_t data_size;
 	size_t offsets_size;
 	size_t extra_buffers_size;
-	void __user *user_data;
+	void *data;
 };
 
 /**
@@ -82,6 +81,7 @@ struct binder_lru_page {
  *                      (invariant after init)
  * @vma_vm_mm:          copy of vma->vm_mm (invarient after mmap)
  * @buffer:             base of per-proc address space mapped via mmap
+ * @user_buffer_offset: offset between user and kernel VAs for buffer
  * @buffers:            list of all buffers for this proc
  * @free_buffers:       rb tree of buffers available for allocation
  *                      sorted by size
@@ -102,7 +102,8 @@ struct binder_alloc {
 	struct mutex mutex;
 	struct vm_area_struct *vma;
 	struct mm_struct *vma_vm_mm;
-	void __user *buffer;
+	void *buffer;
+	ptrdiff_t user_buffer_offset;
 	struct list_head buffers;
 	struct rb_root free_buffers;
 	struct rb_root allocated_buffers;
@@ -161,24 +162,26 @@ binder_alloc_get_free_async_space(struct binder_alloc *alloc)
 	return free_async_space;
 }
 
-unsigned long
-binder_alloc_copy_user_to_buffer(struct binder_alloc *alloc,
-				 struct binder_buffer *buffer,
-				 binder_size_t buffer_offset,
-				 const void __user *from,
-				 size_t bytes);
-
-void binder_alloc_copy_to_buffer(struct binder_alloc *alloc,
-				 struct binder_buffer *buffer,
-				 binder_size_t buffer_offset,
-				 void *src,
-				 size_t bytes);
-
-void binder_alloc_copy_from_buffer(struct binder_alloc *alloc,
-				   void *dest,
-				   struct binder_buffer *buffer,
-				   binder_size_t buffer_offset,
-				   size_t bytes);
+/**
+ * binder_alloc_get_user_buffer_offset() - get offset between kernel/user addrs
+ * @alloc:	binder_alloc for this proc
+ *
+ * Return:	the offset between kernel and user-space addresses to use for
+ * virtual address conversion
+ */
+static inline ptrdiff_t
+binder_alloc_get_user_buffer_offset(struct binder_alloc *alloc)
+{
+	/*
+	 * user_buffer_offset is constant if vma is set and
+	 * undefined if vma is not set. It is possible to
+	 * get here with !alloc->vma if the target process
+	 * is dying while a transaction is being initiated.
+	 * Returning the old value is ok in this case and
+	 * the transaction will fail.
+	 */
+	return alloc->user_buffer_offset;
+}
 
 #endif /* _LINUX_BINDER_ALLOC_H */
 
diff --git a/drivers/android/binder_trace.h b/drivers/android/binder_trace.h
index 7df1e94e5bdc..b11dffc521e8 100644
--- a/drivers/android/binder_trace.h
+++ b/drivers/android/binder_trace.h
@@ -272,17 +272,14 @@ DECLARE_EVENT_CLASS(binder_buffer_class,
 		__field(int, debug_id)
 		__field(size_t, data_size)
 		__field(size_t, offsets_size)
-		__field(size_t, extra_buffers_size)
 	),
 	TP_fast_assign(
 		__entry->debug_id = buf->debug_id;
 		__entry->data_size = buf->data_size;
 		__entry->offsets_size = buf->offsets_size;
-		__entry->extra_buffers_size = buf->extra_buffers_size;
 	),
-	TP_printk("transaction=%d data_size=%zd offsets_size=%zd extra_buffers_size=%zd",
-		  __entry->debug_id, __entry->data_size, __entry->offsets_size,
-		  __entry->extra_buffers_size)
+	TP_printk("transaction=%d data_size=%zd offsets_size=%zd",
+		  __entry->debug_id, __entry->data_size, __entry->offsets_size)
 );
 
 DEFINE_EVENT(binder_buffer_class, binder_transaction_alloc_buf,
@@ -299,7 +296,7 @@ DEFINE_EVENT(binder_buffer_class, binder_transaction_failed_buffer_release,
 
 TRACE_EVENT(binder_update_page_range,
 	TP_PROTO(struct binder_alloc *alloc, bool allocate,
-		 void __user *start, void __user *end),
+		 void *start, void *end),
 	TP_ARGS(alloc, allocate, start, end),
 	TP_STRUCT__entry(
 		__field(int, proc)
diff --git a/drivers/net/geneve.c b/drivers/net/geneve.c
index 19854416190e..ee38299f9c57 100644
--- a/drivers/net/geneve.c
+++ b/drivers/net/geneve.c
@@ -856,7 +856,7 @@ static netdev_tx_t geneve_xmit_skb(struct sk_buff *skb, struct net_device *dev,
 		u8 vni[3];
 
 		tunnel_id_to_vni(key->tun_id, vni);
-		if (info->options_len)
+		if (key->tun_flags & TUNNEL_GENEVE_OPT)
 			opts = ip_tunnel_info_opts(info);
 
 		udp_csum = !!(key->tun_flags & TUNNEL_CSUM);
@@ -939,7 +939,7 @@ static netdev_tx_t geneve6_xmit_skb(struct sk_buff *skb, struct net_device *dev,
 		u8 vni[3];
 
 		tunnel_id_to_vni(key->tun_id, vni);
-		if (info->options_len)
+		if (key->tun_flags & TUNNEL_GENEVE_OPT)
 			opts = ip_tunnel_info_opts(info);
 
 		udp_csum = !!(key->tun_flags & TUNNEL_CSUM);
@@ -965,7 +965,7 @@ static netdev_tx_t geneve6_xmit_skb(struct sk_buff *skb, struct net_device *dev,
 		ttl = ttl ? : ip6_dst_hoplimit(dst);
 	}
 	err = udp_tunnel6_xmit_skb(dst, gs6->sock->sk, skb, dev,
-				   &fl6.saddr, &fl6.daddr, prio, ttl, 0,
+				   &fl6.saddr, &fl6.daddr, prio, ttl,
 				   sport, geneve->dst_port, !udp_csum);
 	return NETDEV_TX_OK;
 
diff --git a/drivers/net/tun.c b/drivers/net/tun.c
index 2a66d61a24b0..d334e740b013 100644
--- a/drivers/net/tun.c
+++ b/drivers/net/tun.c
@@ -632,9 +632,8 @@ static int tun_attach(struct tun_struct *tun, struct file *file,
 
 	/* Re-attach the filter to persist device */
 	if (!skip_filter && (tun->filter_attached == true)) {
-		lock_sock(tfile->socket.sk);
-		err = sk_attach_filter(&tun->fprog, tfile->socket.sk);
-		release_sock(tfile->socket.sk);
+		err = __sk_attach_filter(&tun->fprog, tfile->socket.sk,
+					 lockdep_rtnl_is_held());
 		if (!err)
 			goto out;
 	}
@@ -1835,9 +1834,7 @@ static void tun_detach_filter(struct tun_struct *tun, int n)
 
 	for (i = 0; i < n; i++) {
 		tfile = rtnl_dereference(tun->tfiles[i]);
-		lock_sock(tfile->socket.sk);
-		sk_detach_filter(tfile->socket.sk);
-		release_sock(tfile->socket.sk);
+		__sk_detach_filter(tfile->socket.sk, lockdep_rtnl_is_held());
 	}
 
 	tun->filter_attached = false;
@@ -1850,9 +1847,8 @@ static int tun_attach_filter(struct tun_struct *tun)
 
 	for (i = 0; i < tun->numqueues; i++) {
 		tfile = rtnl_dereference(tun->tfiles[i]);
-		lock_sock(tfile->socket.sk);
-		ret = sk_attach_filter(&tun->fprog, tfile->socket.sk);
-		release_sock(tfile->socket.sk);
+		ret = __sk_attach_filter(&tun->fprog, tfile->socket.sk,
+					 lockdep_rtnl_is_held());
 		if (ret) {
 			tun_detach_filter(tun, i);
 			return ret;
diff --git a/drivers/net/vxlan.c b/drivers/net/vxlan.c
index d93e86055d5e..4d44ec5b7cd7 100644
--- a/drivers/net/vxlan.c
+++ b/drivers/net/vxlan.c
@@ -1783,7 +1783,7 @@ static int vxlan6_xmit_skb(struct dst_entry *dst, struct sock *sk,
 	skb_set_inner_protocol(skb, htons(ETH_P_TEB));
 
 	udp_tunnel6_xmit_skb(dst, sk, skb, dev, saddr, daddr, prio,
-			     ttl, 0, src_port, dst_port,
+			     ttl, src_port, dst_port,
 			     !!(vxflags & VXLAN_F_UDP_ZERO_CSUM6_TX));
 	return 0;
 err:
diff --git a/fs/kernfs/dir.c b/fs/kernfs/dir.c
index e5499c5f63da..91e004518237 100644
--- a/fs/kernfs/dir.c
+++ b/fs/kernfs/dir.c
@@ -44,116 +44,28 @@ static int kernfs_name_locked(struct kernfs_node *kn, char *buf, size_t buflen)
 	return strlcpy(buf, kn->parent ? kn->name : "/", buflen);
 }
 
-/* kernfs_node_depth - compute depth from @from to @to */
-static size_t kernfs_depth(struct kernfs_node *from, struct kernfs_node *to)
+static char * __must_check kernfs_path_locked(struct kernfs_node *kn, char *buf,
+					      size_t buflen)
 {
-	size_t depth = 0;
+	char *p = buf + buflen;
+	int len;
 
-	while (to->parent && to != from) {
-		depth++;
-		to = to->parent;
-	}
-	return depth;
-}
-
-static struct kernfs_node *kernfs_common_ancestor(struct kernfs_node *a,
-						  struct kernfs_node *b)
-{
-	size_t da, db;
-	struct kernfs_root *ra = kernfs_root(a), *rb = kernfs_root(b);
-
-	if (ra != rb)
-		return NULL;
-
-	da = kernfs_depth(ra->kn, a);
-	db = kernfs_depth(rb->kn, b);
-
-	while (da > db) {
-		a = a->parent;
-		da--;
-	}
-	while (db > da) {
-		b = b->parent;
-		db--;
-	}
-
-	/* worst case b and a will be the same at root */
-	while (b != a) {
-		b = b->parent;
-		a = a->parent;
-	}
-
-	return a;
-}
-
-/**
- * kernfs_path_from_node_locked - find a pseudo-absolute path to @kn_to,
- * where kn_from is treated as root of the path.
- * @kn_from: kernfs node which should be treated as root for the path
- * @kn_to: kernfs node to which path is needed
- * @buf: buffer to copy the path into
- * @buflen: size of @buf
- *
- * We need to handle couple of scenarios here:
- * [1] when @kn_from is an ancestor of @kn_to at some level
- * kn_from: /n1/n2/n3
- * kn_to:   /n1/n2/n3/n4/n5
- * result:  /n4/n5
- *
- * [2] when @kn_from is on a different hierarchy and we need to find common
- * ancestor between @kn_from and @kn_to.
- * kn_from: /n1/n2/n3/n4
- * kn_to:   /n1/n2/n5
- * result:  /../../n5
- * OR
- * kn_from: /n1/n2/n3/n4/n5   [depth=5]
- * kn_to:   /n1/n2/n3         [depth=3]
- * result:  /../..
- *
- * Returns the length of the full path.  If the full length is equal to or
- * greater than @buflen, @buf contains the truncated path with the trailing
- * '\0'.  On error, -errno is returned.
- */
-static int kernfs_path_from_node_locked(struct kernfs_node *kn_to,
-					struct kernfs_node *kn_from,
-					char *buf, size_t buflen)
-{
-	struct kernfs_node *kn, *common;
-	const char parent_str[] = "/..";
-	size_t depth_from, depth_to, len = 0;
-	int i, j;
-
-	if (!kn_from)
-		kn_from = kernfs_root(kn_to)->kn;
-
-	if (kn_from == kn_to)
-		return strlcpy(buf, "/", buflen);
-
-	common = kernfs_common_ancestor(kn_from, kn_to);
-	if (WARN_ON(!common))
-		return -EINVAL;
-
-	depth_to = kernfs_depth(common, kn_to);
-	depth_from = kernfs_depth(common, kn_from);
-
-	if (buf)
-		buf[0] = '\0';
+	*--p = '\0';
 
-	for (i = 0; i < depth_from; i++)
-		len += strlcpy(buf + len, parent_str,
-			       len < buflen ? buflen - len : 0);
-
-	/* Calculate how many bytes we need for the rest */
-	for (i = depth_to - 1; i >= 0; i--) {
-		for (kn = kn_to, j = 0; j < i; j++)
-			kn = kn->parent;
-		len += strlcpy(buf + len, "/",
-			       len < buflen ? buflen - len : 0);
-		len += strlcpy(buf + len, kn->name,
-			       len < buflen ? buflen - len : 0);
-	}
+	do {
+		len = strlen(kn->name);
+		if (p - buf < len + 1) {
+			buf[0] = '\0';
+			p = NULL;
+			break;
+		}
+		p -= len;
+		memcpy(p, kn->name, len);
+		*--p = '/';
+		kn = kn->parent;
+	} while (kn && kn->parent);
 
-	return len;
+	return p;
 }
 
 /**
@@ -203,33 +115,27 @@ size_t kernfs_path_len(struct kernfs_node *kn)
 }
 
 /**
- * kernfs_path_from_node - build path of node @to relative to @from.
- * @from: parent kernfs_node relative to which we need to build the path
- * @to: kernfs_node of interest
- * @buf: buffer to copy @to's path into
+ * kernfs_path - build full path of a given node
+ * @kn: kernfs_node of interest
+ * @buf: buffer to copy @kn's name into
  * @buflen: size of @buf
  *
- * Builds @to's path relative to @from in @buf. @from and @to must
- * be on the same kernfs-root. If @from is not parent of @to, then a relative
- * path (which includes '..'s) as needed to reach from @from to @to is
- * returned.
- *
- * Returns the length of the full path.  If the full length is equal to or
- * greater than @buflen, @buf contains the truncated path with the trailing
- * '\0'.  On error, -errno is returned.
+ * Builds and returns the full path of @kn in @buf of @buflen bytes.  The
+ * path is built from the end of @buf so the returned pointer usually
+ * doesn't match @buf.  If @buf isn't long enough, @buf is nul terminated
+ * and %NULL is returned.
  */
-int kernfs_path_from_node(struct kernfs_node *to, struct kernfs_node *from,
-			  char *buf, size_t buflen)
+char *kernfs_path(struct kernfs_node *kn, char *buf, size_t buflen)
 {
 	unsigned long flags;
-	int ret;
+	char *p;
 
 	spin_lock_irqsave(&kernfs_rename_lock, flags);
-	ret = kernfs_path_from_node_locked(to, from, buf, buflen);
+	p = kernfs_path_locked(kn, buf, buflen);
 	spin_unlock_irqrestore(&kernfs_rename_lock, flags);
-	return ret;
+	return p;
 }
-EXPORT_SYMBOL_GPL(kernfs_path_from_node);
+EXPORT_SYMBOL_GPL(kernfs_path);
 
 /**
  * pr_cont_kernfs_name - pr_cont name of a kernfs_node
@@ -258,25 +164,17 @@ void pr_cont_kernfs_name(struct kernfs_node *kn)
 void pr_cont_kernfs_path(struct kernfs_node *kn)
 {
 	unsigned long flags;
-	int sz;
+	char *p;
 
 	spin_lock_irqsave(&kernfs_rename_lock, flags);
 
-	sz = kernfs_path_from_node_locked(kn, NULL, kernfs_pr_cont_buf,
-					  sizeof(kernfs_pr_cont_buf));
-	if (sz < 0) {
-		pr_cont("(error)");
-		goto out;
-	}
-
-	if (sz >= sizeof(kernfs_pr_cont_buf)) {
-		pr_cont("(name too long)");
-		goto out;
-	}
-
-	pr_cont("%s", kernfs_pr_cont_buf);
+	p = kernfs_path_locked(kn, kernfs_pr_cont_buf,
+			       sizeof(kernfs_pr_cont_buf));
+	if (p)
+		pr_cont("%s", p);
+	else
+		pr_cont("<name too long>");
 
-out:
 	spin_unlock_irqrestore(&kernfs_rename_lock, flags);
 }
 
@@ -491,7 +389,7 @@ static void kernfs_drain(struct kernfs_node *kn)
 		rwsem_release(&kn->dep_map, 1, _RET_IP_);
 	}
 
-	kernfs_drain_open_files(kn);
+	kernfs_unmap_bin_file(kn);
 
 	mutex_lock(&kernfs_mutex);
 }
@@ -796,29 +694,6 @@ static struct kernfs_node *kernfs_find_ns(struct kernfs_node *parent,
 	return NULL;
 }
 
-static struct kernfs_node *kernfs_walk_ns(struct kernfs_node *parent,
-					  const unsigned char *path,
-					  const void *ns)
-{
-	static char path_buf[PATH_MAX];	/* protected by kernfs_mutex */
-	size_t len = strlcpy(path_buf, path, PATH_MAX);
-	char *p = path_buf;
-	char *name;
-
-	lockdep_assert_held(&kernfs_mutex);
-
-	if (len >= PATH_MAX)
-		return NULL;
-
-	while ((name = strsep(&p, "/")) && parent) {
-		if (*name == '\0')
-			continue;
-		parent = kernfs_find_ns(parent, name, ns);
-	}
-
-	return parent;
-}
-
 /**
  * kernfs_find_and_get_ns - find and get kernfs_node with the given name
  * @parent: kernfs_node to search under
@@ -843,29 +718,6 @@ struct kernfs_node *kernfs_find_and_get_ns(struct kernfs_node *parent,
 }
 EXPORT_SYMBOL_GPL(kernfs_find_and_get_ns);
 
-/**
- * kernfs_walk_and_get_ns - find and get kernfs_node with the given path
- * @parent: kernfs_node to search under
- * @path: path to look for
- * @ns: the namespace tag to use
- *
- * Look for kernfs_node with path @path under @parent and get a reference
- * if found.  This function may sleep and returns pointer to the found
- * kernfs_node on success, %NULL on failure.
- */
-struct kernfs_node *kernfs_walk_and_get_ns(struct kernfs_node *parent,
-					   const char *path, const void *ns)
-{
-	struct kernfs_node *kn;
-
-	mutex_lock(&kernfs_mutex);
-	kn = kernfs_walk_ns(parent, path, ns);
-	kernfs_get(kn);
-	mutex_unlock(&kernfs_mutex);
-
-	return kn;
-}
-
 /**
  * kernfs_create_root - create a new kernfs hierarchy
  * @scops: optional syscall operations for the hierarchy
diff --git a/fs/kernfs/file.c b/fs/kernfs/file.c
index 42dec396560f..35618947c064 100644
--- a/fs/kernfs/file.c
+++ b/fs/kernfs/file.c
@@ -707,8 +707,7 @@ static int kernfs_fop_open(struct inode *inode, struct file *file)
 	if (error)
 		goto err_free;
 
-	of->seq_file = file->private_data;
-	of->seq_file->private = of;
+	((struct seq_file *)file->private_data)->private = of;
 
 	/* seq_file clears PWRITE unconditionally, restore it if WRITE */
 	if (file->f_mode & FMODE_WRITE)
@@ -717,22 +716,13 @@ static int kernfs_fop_open(struct inode *inode, struct file *file)
 	/* make sure we have open node struct */
 	error = kernfs_get_open_node(kn, of);
 	if (error)
-		goto err_seq_release;
-
-	if (ops->open) {
-		/* nobody has access to @of yet, skip @of->mutex */
-		error = ops->open(of);
-		if (error)
-			goto err_put_node;
-	}
+		goto err_close;
 
 	/* open succeeded, put active references */
 	kernfs_put_active(kn);
 	return 0;
 
-err_put_node:
-	kernfs_put_open_node(kn, of);
-err_seq_release:
+err_close:
 	seq_release(inode, file);
 err_free:
 	kfree(of->prealloc_buf);
@@ -742,32 +732,11 @@ err_out:
 	return error;
 }
 
-/* used from release/drain to ensure that ->release() is called exactly once */
-static void kernfs_release_file(struct kernfs_node *kn,
-				struct kernfs_open_file *of)
-{
-	if (!(kn->flags & KERNFS_HAS_RELEASE))
-		return;
-
-	mutex_lock(&of->mutex);
-	if (!of->released) {
-		/*
-		 * A file is never detached without being released and we
-		 * need to be able to release files which are deactivated
-		 * and being drained.  Don't use kernfs_ops().
-		 */
-		kn->attr.ops->release(of);
-		of->released = true;
-	}
-	mutex_unlock(&of->mutex);
-}
-
 static int kernfs_fop_release(struct inode *inode, struct file *filp)
 {
 	struct kernfs_node *kn = filp->f_path.dentry->d_fsdata;
 	struct kernfs_open_file *of = kernfs_of(filp);
 
-	kernfs_release_file(kn, of);
 	kernfs_put_open_node(kn, of);
 	seq_release(inode, filp);
 	kfree(of->prealloc_buf);
@@ -776,12 +745,12 @@ static int kernfs_fop_release(struct inode *inode, struct file *filp)
 	return 0;
 }
 
-void kernfs_drain_open_files(struct kernfs_node *kn)
+void kernfs_unmap_bin_file(struct kernfs_node *kn)
 {
 	struct kernfs_open_node *on;
 	struct kernfs_open_file *of;
 
-	if (!(kn->flags & (KERNFS_HAS_MMAP | KERNFS_HAS_RELEASE)))
+	if (!(kn->flags & KERNFS_HAS_MMAP))
 		return;
 
 	spin_lock_irq(&kernfs_open_node_lock);
@@ -793,16 +762,10 @@ void kernfs_drain_open_files(struct kernfs_node *kn)
 		return;
 
 	mutex_lock(&kernfs_open_file_mutex);
-
 	list_for_each_entry(of, &on->files, list) {
 		struct inode *inode = file_inode(of->file);
-
-		if (kn->flags & KERNFS_HAS_MMAP)
-			unmap_mapping_range(inode->i_mapping, 0, 0, 1);
-
-		kernfs_release_file(kn, of);
+		unmap_mapping_range(inode->i_mapping, 0, 0, 1);
 	}
-
 	mutex_unlock(&kernfs_open_file_mutex);
 
 	kernfs_put_open_node(kn, NULL);
@@ -822,35 +785,26 @@ void kernfs_drain_open_files(struct kernfs_node *kn)
  * to see if it supports poll (Neither 'poll' nor 'select' return
  * an appropriate error code).  When in doubt, set a suitable timeout value.
  */
-unsigned int kernfs_generic_poll(struct kernfs_open_file *of, poll_table *wait)
-{
-	struct kernfs_node *kn = of->file->f_path.dentry->d_fsdata;
-	struct kernfs_open_node *on = kn->attr.open;
-
-	poll_wait(of->file, &on->poll, wait);
-
-	if (of->event != atomic_read(&on->event))
-		return DEFAULT_POLLMASK|POLLERR|POLLPRI;
-
-	return DEFAULT_POLLMASK;
-}
-
 static unsigned int kernfs_fop_poll(struct file *filp, poll_table *wait)
 {
 	struct kernfs_open_file *of = kernfs_of(filp);
 	struct kernfs_node *kn = filp->f_path.dentry->d_fsdata;
-	unsigned int ret;
+	struct kernfs_open_node *on = kn->attr.open;
 
 	if (!kernfs_get_active(kn))
-		return DEFAULT_POLLMASK|POLLERR|POLLPRI;
+		goto trigger;
 
-	if (kn->attr.ops->poll)
-		ret = kn->attr.ops->poll(of, wait);
-	else
-		ret = kernfs_generic_poll(of, wait);
+	poll_wait(filp, &on->poll, wait);
 
 	kernfs_put_active(kn);
-	return ret;
+
+	if (of->event != atomic_read(&on->event))
+		goto trigger;
+
+	return DEFAULT_POLLMASK;
+
+ trigger:
+	return DEFAULT_POLLMASK|POLLERR|POLLPRI;
 }
 
 static void kernfs_notify_workfn(struct work_struct *work)
@@ -1009,8 +963,6 @@ struct kernfs_node *__kernfs_create_file(struct kernfs_node *parent,
 		kn->flags |= KERNFS_HAS_SEQ_SHOW;
 	if (ops->mmap)
 		kn->flags |= KERNFS_HAS_MMAP;
-	if (ops->release)
-		kn->flags |= KERNFS_HAS_RELEASE;
 
 	rc = kernfs_add_one(kn);
 	if (rc) {
diff --git a/fs/kernfs/kernfs-internal.h b/fs/kernfs/kernfs-internal.h
index 34d5a59ebd41..6762bfbd8207 100644
--- a/fs/kernfs/kernfs-internal.h
+++ b/fs/kernfs/kernfs-internal.h
@@ -108,7 +108,7 @@ struct kernfs_node *kernfs_new_node(struct kernfs_node *parent,
  */
 extern const struct file_operations kernfs_file_fops;
 
-void kernfs_drain_open_files(struct kernfs_node *kn);
+void kernfs_unmap_bin_file(struct kernfs_node *kn);
 
 /*
  * symlink.c
diff --git a/fs/kernfs/mount.c b/fs/kernfs/mount.c
index ef34e31a9d57..8eaf417187f1 100644
--- a/fs/kernfs/mount.c
+++ b/fs/kernfs/mount.c
@@ -14,8 +14,6 @@
 #include <linux/magic.h>
 #include <linux/slab.h>
 #include <linux/pagemap.h>
-#include <linux/namei.h>
-#include <linux/seq_file.h>
 
 #include "kernfs-internal.h"
 
@@ -41,18 +39,6 @@ static int kernfs_sop_show_options(struct seq_file *sf, struct dentry *dentry)
 	return 0;
 }
 
-static int kernfs_sop_show_path(struct seq_file *sf, struct dentry *dentry)
-{
-	struct kernfs_node *node = dentry->d_fsdata;
-	struct kernfs_root *root = kernfs_root(node);
-	struct kernfs_syscall_ops *scops = root->syscall_ops;
-
-	if (scops && scops->show_path)
-		return scops->show_path(sf, node, root);
-
-	return seq_dentry(sf, dentry, " \t\n\\");
-}
-
 const struct super_operations kernfs_sops = {
 	.statfs		= simple_statfs,
 	.drop_inode	= generic_delete_inode,
@@ -60,7 +46,6 @@ const struct super_operations kernfs_sops = {
 
 	.remount_fs	= kernfs_sop_remount_fs,
 	.show_options	= kernfs_sop_show_options,
-	.show_path	= kernfs_sop_show_path,
 };
 
 /**
@@ -77,74 +62,6 @@ struct kernfs_root *kernfs_root_from_sb(struct super_block *sb)
 	return NULL;
 }
 
-/*
- * find the next ancestor in the path down to @child, where @parent was the
- * ancestor whose descendant we want to find.
- *
- * Say the path is /a/b/c/d.  @child is d, @parent is NULL.  We return the root
- * node.  If @parent is b, then we return the node for c.
- * Passing in d as @parent is not ok.
- */
-static struct kernfs_node *find_next_ancestor(struct kernfs_node *child,
-					      struct kernfs_node *parent)
-{
-	if (child == parent) {
-		pr_crit_once("BUG in find_next_ancestor: called with parent == child");
-		return NULL;
-	}
-
-	while (child->parent != parent) {
-		if (!child->parent)
-			return NULL;
-		child = child->parent;
-	}
-
-	return child;
-}
-
-/**
- * kernfs_node_dentry - get a dentry for the given kernfs_node
- * @kn: kernfs_node for which a dentry is needed
- * @sb: the kernfs super_block
- */
-struct dentry *kernfs_node_dentry(struct kernfs_node *kn,
-				  struct super_block *sb)
-{
-	struct dentry *dentry;
-	struct kernfs_node *knparent = NULL;
-
-	BUG_ON(sb->s_op != &kernfs_sops);
-
-	dentry = dget(sb->s_root);
-
-	/* Check if this is the root kernfs_node */
-	if (!kn->parent)
-		return dentry;
-
-	knparent = find_next_ancestor(kn, NULL);
-	if (WARN_ON(!knparent))
-		return ERR_PTR(-EINVAL);
-
-	do {
-		struct dentry *dtmp;
-		struct kernfs_node *kntmp;
-
-		if (kn == knparent)
-			return dentry;
-		kntmp = find_next_ancestor(kn, knparent);
-		if (WARN_ON(!kntmp))
-			return ERR_PTR(-EINVAL);
-		mutex_lock(&d_inode(dentry)->i_mutex);
-		dtmp = lookup_one_len(kntmp->name, dentry, strlen(kntmp->name));
-		mutex_unlock(&d_inode(dentry)->i_mutex);
-		dput(dentry);
-		if (IS_ERR(dtmp))
-			return dtmp;
-		knparent = kntmp;
-		dentry = dtmp;
-	} while (true);
-}
-
 static int kernfs_fill_super(struct super_block *sb, unsigned long magic)
 {
 	struct kernfs_super_info *info = kernfs_info(sb);
@@ -241,8 +158,7 @@ struct dentry *kernfs_mount_ns(struct file_system_type *fs_type, int flags,
 	info->root = root;
 	info->ns = ns;
 
-	sb = sget_userns(fs_type, kernfs_test_super, kernfs_set_super, flags,
-			 &init_user_ns, info);
+	sb = sget(fs_type, kernfs_test_super, kernfs_set_super, flags, info);
 	if (IS_ERR(sb) || sb->s_fs_info != info)
 		kfree(info);
 	if (IS_ERR(sb))
diff --git a/fs/namespace.c b/fs/namespace.c
index 2443cdb9ce86..58c6f27b141d 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -3503,16 +3503,10 @@ static int mntns_install(struct nsproxy *nsproxy, struct ns_common *ns)
 	return 0;
 }
 
-static struct user_namespace *mntns_owner(struct ns_common *ns)
-{
-	return to_mnt_ns(ns)->user_ns;
-}
-
 const struct proc_ns_operations mntns_operations = {
 	.name		= "mnt",
 	.type		= CLONE_NEWNS,
 	.get		= mntns_get,
 	.put		= mntns_put,
 	.install	= mntns_install,
-	.owner		= mntns_owner,
 };
diff --git a/fs/nfsd/nfsctl.c b/fs/nfsd/nfsctl.c
index 4d816b64dafc..dfd1949b31ea 100644
--- a/fs/nfsd/nfsctl.c
+++ b/fs/nfsd/nfsctl.c
@@ -1159,15 +1159,20 @@ static int nfsd_fill_super(struct super_block * sb, void * data, int silent)
 #endif
 		/* last one */ {""}
 	};
-	get_net(sb->s_fs_info);
-	return simple_fill_super(sb, 0x6e667364, nfsd_files);
+	struct net *net = data;
+	int ret;
+
+	ret = simple_fill_super(sb, 0x6e667364, nfsd_files);
+	if (ret)
+		return ret;
+	sb->s_fs_info = get_net(net);
+	return 0;
 }
 
 static struct dentry *nfsd_mount(struct file_system_type *fs_type,
 	int flags, const char *dev_name, void *data)
 {
-	struct net *net = current->nsproxy->net_ns;
-	return mount_ns(fs_type, flags, data, net, net->user_ns, nfsd_fill_super);
+	return mount_ns(fs_type, flags, current->nsproxy->net_ns, nfsd_fill_super);
 }
 
 static void nfsd_umount(struct super_block *sb)
diff --git a/fs/proc/namespaces.c b/fs/proc/namespaces.c
index b46274600f37..1b0ea4a5d89e 100644
--- a/fs/proc/namespaces.c
+++ b/fs/proc/namespaces.c
@@ -28,9 +28,6 @@ static const struct proc_ns_operations *ns_entries[] = {
 	&userns_operations,
 #endif
 	&mntns_operations,
-#ifdef CONFIG_CGROUPS
-	&cgroupns_operations,
-#endif
 };
 
 static const char *proc_ns_follow_link(struct dentry *dentry, void **cookie)
diff --git a/fs/super.c b/fs/super.c
index 34f1dc72064d..689ec96c43f8 100644
--- a/fs/super.c
+++ b/fs/super.c
@@ -33,7 +33,6 @@
 #include <linux/cleancache.h>
 #include <linux/fsnotify.h>
 #include <linux/lockdep.h>
-#include <linux/user_namespace.h>
 #include "internal.h"
 
 
@@ -176,7 +175,6 @@ static void destroy_super(struct super_block *s)
 	list_lru_destroy(&s->s_inode_lru);
 	security_sb_free(s);
 	WARN_ON(!list_empty(&s->s_mounts));
-	put_user_ns(s->s_user_ns);
 	kfree(s->s_subtype);
 	kfree(s->s_options);
 	call_rcu(&s->rcu, destroy_super_rcu);
@@ -186,13 +184,11 @@ static void destroy_super(struct super_block *s)
  *	alloc_super	-	create new superblock
  *	@type:	filesystem type superblock should belong to
  *	@flags: the mount flags
- *	@user_ns: User namespace for the super_block
  *
  *	Allocates and initializes a new &struct super_block.  alloc_super()
  *	returns a pointer new superblock or %NULL if allocation had failed.
  */
-static struct super_block *alloc_super(struct file_system_type *type, int flags,
-				       struct user_namespace *user_ns)
+static struct super_block *alloc_super(struct file_system_type *type, int flags)
 {
 	struct super_block *s = kzalloc(sizeof(struct super_block),  GFP_USER);
 	static const struct super_operations default_op;
@@ -202,7 +198,6 @@ static struct super_block *alloc_super(struct file_system_type *type, int flags,
 		return NULL;
 
 	INIT_LIST_HEAD(&s->s_mounts);
-	s->s_user_ns = get_user_ns(user_ns);
 
 	if (security_sb_alloc(s))
 		goto fail;
@@ -458,18 +453,17 @@ void generic_shutdown_super(struct super_block *sb)
 EXPORT_SYMBOL(generic_shutdown_super);
 
 /**
- *	sget_userns -	find or create a superblock
+ *	sget	-	find or create a superblock
  *	@type:	filesystem type superblock should belong to
  *	@test:	comparison callback
  *	@set:	setup callback
  *	@flags:	mount flags
- *	@user_ns: User namespace for the super_block
  *	@data:	argument to each of them
  */
-struct super_block *sget_userns(struct file_system_type *type,
+struct super_block *sget(struct file_system_type *type,
 			int (*test)(struct super_block *,void *),
 			int (*set)(struct super_block *,void *),
-			int flags, struct user_namespace *user_ns,
+			int flags,
 			void *data)
 {
 	struct super_block *s = NULL;
@@ -482,14 +476,6 @@ retry:
 		hlist_for_each_entry(old, &type->fs_supers, s_instances) {
 			if (!test(old, data))
 				continue;
-			if (user_ns != old->s_user_ns) {
-				spin_unlock(&sb_lock);
-				if (s) {
-					up_write(&s->s_umount);
-					destroy_super(s);
-				}
-				return ERR_PTR(-EBUSY);
-			}
 			if (!grab_super(old))
 				goto retry;
 			if (s) {
@@ -502,7 +488,7 @@ retry:
 	}
 	if (!s) {
 		spin_unlock(&sb_lock);
-		s = alloc_super(type, flags, user_ns);
+		s = alloc_super(type, flags);
 		if (!s)
 			return ERR_PTR(-ENOMEM);
 		goto retry;
@@ -529,31 +515,6 @@ retry:
 	return s;
 }
 
-EXPORT_SYMBOL(sget_userns);
-
-/**
- *	sget	-	find or create a superblock
- *	@type:	  filesystem type superblock should belong to
- *	@test:	  comparison callback
- *	@set:	  setup callback
- *	@flags:	  mount flags
- *	@data:	  argument to each of them
- */
-struct super_block *sget(struct file_system_type *type,
-			int (*test)(struct super_block *,void *),
-			int (*set)(struct super_block *,void *),
-			int flags,
-			void *data)
-{
-	struct user_namespace *user_ns = current_user_ns();
-
-	/* Ensure the requestor has permissions over the target filesystem */
-	if (!(flags & MS_KERNMOUNT) && !ns_capable(user_ns, CAP_SYS_ADMIN))
-		return ERR_PTR(-EPERM);
-
-	return sget_userns(type, test, set, flags, user_ns, data);
-}
-
 EXPORT_SYMBOL(sget);
 
 void drop_super(struct super_block *sb)
@@ -986,20 +947,12 @@ static int ns_set_super(struct super_block *sb, void *data)
 	return set_anon_super(sb, NULL);
 }
 
-struct dentry *mount_ns(struct file_system_type *fs_type,
-	int flags, void *data, void *ns, struct user_namespace *user_ns,
-	int (*fill_super)(struct super_block *, void *, int))
+struct dentry *mount_ns(struct file_system_type *fs_type, int flags,
+	void *data, int (*fill_super)(struct super_block *, void *, int))
 {
 	struct super_block *sb;
 
-	/* Don't allow mounting unless the caller has CAP_SYS_ADMIN
-	 * over the namespace.
-	 */
-	if (!(flags & MS_KERNMOUNT) && !ns_capable(user_ns, CAP_SYS_ADMIN))
-		return ERR_PTR(-EPERM);
-
-	sb = sget_userns(fs_type, ns_test_super, ns_set_super, flags,
-			 user_ns, ns);
+	sb = sget(fs_type, ns_test_super, ns_set_super, flags, data);
 	if (IS_ERR(sb))
 		return ERR_CAST(sb);
 
diff --git a/fs/sysfs/dir.c b/fs/sysfs/dir.c
index 2b67bda2021b..94374e435025 100644
--- a/fs/sysfs/dir.c
+++ b/fs/sysfs/dir.c
@@ -21,14 +21,14 @@ DEFINE_SPINLOCK(sysfs_symlink_target_lock);
 
 void sysfs_warn_dup(struct kernfs_node *parent, const char *name)
 {
-	char *buf;
+	char *buf, *path = NULL;
 
 	buf = kzalloc(PATH_MAX, GFP_KERNEL);
 	if (buf)
-		kernfs_path(parent, buf, PATH_MAX);
+		path = kernfs_path(parent, buf, PATH_MAX);
 
 	WARN(1, KERN_WARNING "sysfs: cannot create duplicate filename '%s/%s'\n",
-	     buf, name);
+	     path, name);
 
 	kfree(buf);
 }
diff --git a/include/linux/blk-cgroup.h b/include/linux/blk-cgroup.h
index 217879e49dbc..c02e669945e9 100644
--- a/include/linux/blk-cgroup.h
+++ b/include/linux/blk-cgroup.h
@@ -343,7 +343,16 @@ static inline struct blkcg *cpd_to_blkcg(struct blkcg_policy_data *cpd)
  */
 static inline int blkg_path(struct blkcg_gq *blkg, char *buf, int buflen)
 {
-	return cgroup_path(blkg->blkcg->css.cgroup, buf, buflen);
+	char *p;
+
+	p = cgroup_path(blkg->blkcg->css.cgroup, buf, buflen);
+	if (!p) {
+		strncpy(buf, "<unavailable>", buflen);
+		return -ENAMETOOLONG;
+	}
+
+	memmove(buf, p, buf + buflen - p);
+	return 0;
 }
 
 /**
diff --git a/include/linux/bpf-cgroup.h b/include/linux/bpf-cgroup.h
deleted file mode 100644
index d169d274e31b..000000000000
--- a/include/linux/bpf-cgroup.h
+++ /dev/null
@@ -1,92 +0,0 @@
-#ifndef _BPF_CGROUP_H
-#define _BPF_CGROUP_H
-
-#include <linux/bpf.h>
-#include <linux/jump_label.h>
-#include <uapi/linux/bpf.h>
-
-struct sock;
-struct cgroup;
-struct sk_buff;
-
-#ifdef CONFIG_CGROUP_BPF
-
-extern struct static_key_false cgroup_bpf_enabled_key;
-#define cgroup_bpf_enabled static_branch_unlikely(&cgroup_bpf_enabled_key)
-
-struct bpf_prog_list {
-	struct list_head node;
-	struct bpf_prog *prog;
-};
-
-struct bpf_prog_array;
-
-struct cgroup_bpf {
-	/* array of effective progs in this cgroup */
-	struct bpf_prog_array __rcu *effective[MAX_BPF_ATTACH_TYPE];
-
-	/* attached progs to this cgroup and attach flags
-	 * when flags == 0 or BPF_F_ALLOW_OVERRIDE the progs list will
-	 * have either zero or one element
-	 * when BPF_F_ALLOW_MULTI the list can have up to BPF_CGROUP_MAX_PROGS
-	 */
-	struct list_head progs[MAX_BPF_ATTACH_TYPE];
-	u32 flags[MAX_BPF_ATTACH_TYPE];
-
-	/* temp storage for effective prog array used by prog_attach/detach */
-	struct bpf_prog_array __rcu *inactive;
-};
-
-void cgroup_bpf_put(struct cgroup *cgrp);
-int cgroup_bpf_inherit(struct cgroup *cgrp);
-
-int __cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
-			enum bpf_attach_type type, u32 flags);
-int __cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
-			enum bpf_attach_type type, u32 flags);
-
-/* Wrapper for __cgroup_bpf_*() protected by cgroup_mutex */
-int cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
-		      enum bpf_attach_type type, u32 flags);
-int cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
-		      enum bpf_attach_type type, u32 flags);
-
-int __cgroup_bpf_run_filter(struct sock *sk,
-			    struct sk_buff *skb,
-			    enum bpf_attach_type type);
-
-/* Wrappers for __cgroup_bpf_run_filter() guarded by cgroup_bpf_enabled. */
-#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb)			\
-({									\
-	int __ret = 0;							\
-	if (cgroup_bpf_enabled)						\
-		__ret = __cgroup_bpf_run_filter(sk, skb,		\
-						BPF_CGROUP_INET_INGRESS); \
-									\
-	__ret;								\
-})
-
-#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb)				\
-({									\
-	int __ret = 0;							\
-	if (cgroup_bpf_enabled && sk && sk == skb->sk) {		\
-		typeof(sk) __sk = sk_to_full_sk(sk);			\
-		if (sk_fullsock(__sk))					\
-			__ret = __cgroup_bpf_run_filter(__sk, skb,	\
-						BPF_CGROUP_INET_EGRESS); \
-	}								\
-	__ret;								\
-})
-
-#else
-
-struct cgroup_bpf {};
-static inline void cgroup_bpf_put(struct cgroup *cgrp) {}
-static inline int cgroup_bpf_inherit(struct cgroup *cgrp) { return 0; }
-
-#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb) ({ 0; })
-#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb) ({ 0; })
-
-#endif /* CONFIG_CGROUP_BPF */
-
-#endif /* _BPF_CGROUP_H */
diff --git a/include/linux/bpf.h b/include/linux/bpf.h
index 438efe7ed053..bae3da5bcda0 100644
--- a/include/linux/bpf.h
+++ b/include/linux/bpf.h
@@ -10,17 +10,14 @@
 #include <uapi/linux/bpf.h>
 #include <linux/workqueue.h>
 #include <linux/file.h>
-#include <linux/percpu.h>
 
-struct perf_event;
 struct bpf_map;
 
 /* map is generic key/value storage optionally accesible by eBPF programs */
 struct bpf_map_ops {
 	/* funcs callable from userspace (via syscall) */
 	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
-	void (*map_release)(struct bpf_map *map, struct file *map_file);
-	void (*map_free)(struct bpf_map *map);
+	void (*map_free)(struct bpf_map *);
 	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
 
 	/* funcs callable from userspace and from eBPF programs */
@@ -29,27 +26,30 @@ struct bpf_map_ops {
 	int (*map_delete_elem)(struct bpf_map *map, void *key);
 
 	/* funcs called by prog_array and perf_event_array map */
-	void *(*map_fd_get_ptr)(struct bpf_map *map, struct file *map_file,
-				int fd);
-	void (*map_fd_put_ptr)(void *ptr);
+	void *(*map_fd_get_ptr) (struct bpf_map *map, int fd);
+	void (*map_fd_put_ptr) (void *ptr);
 };
 
 struct bpf_map {
-	atomic_t refcnt;
+	/* 1st cacheline with read-mostly members of which some
+	 * are also accessed in fast-path (e.g. ops, max_entries).
+	 */
+	const struct bpf_map_ops *ops ____cacheline_aligned;
 	enum bpf_map_type map_type;
 	u32 key_size;
 	u32 value_size;
 	u32 max_entries;
-	u32 map_flags;
 	u32 pages;
 	bool unpriv_array;
-	struct user_struct *user;
-	const struct bpf_map_ops *ops;
-	struct work_struct work;
+	/* 7 bytes hole */
+
+	/* 2nd cacheline with misc members to avoid false sharing
+	 * particularly with refcounting.
+	 */
+	struct user_struct *user ____cacheline_aligned;
+	atomic_t refcnt;
 	atomic_t usercnt;
-#ifdef CONFIG_SECURITY
-	void *security;
-#endif
+	struct work_struct work;
 };
 
 struct bpf_map_type_list {
@@ -73,13 +73,7 @@ enum bpf_arg_type {
 	 * functions that access data on eBPF program stack
 	 */
 	ARG_PTR_TO_STACK,	/* any pointer to eBPF program stack */
-	ARG_PTR_TO_RAW_STACK,	/* any pointer to eBPF program stack, area does not
-				 * need to be initialized, helper function must fill
-				 * all bytes or clear them in error case.
-				 */
-
 	ARG_CONST_STACK_SIZE,	/* number of bytes accessed from stack */
-	ARG_CONST_STACK_SIZE_OR_ZERO, /* number of bytes accessed from stack or 0 */
 
 	ARG_PTR_TO_CTX,		/* pointer to context */
 	ARG_ANYTHING,		/* any (initialized) argument is ok */
@@ -99,7 +93,6 @@ enum bpf_return_type {
 struct bpf_func_proto {
 	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
 	bool gpl_only;
-	bool pkt_access;
 	enum bpf_return_type ret_type;
 	enum bpf_arg_type arg1_type;
 	enum bpf_arg_type arg2_type;
@@ -119,38 +112,6 @@ enum bpf_access_type {
 	BPF_WRITE = 2
 };
 
-/* types of values stored in eBPF registers */
-enum bpf_reg_type {
-	NOT_INIT = 0,		 /* nothing was written into register */
-	UNKNOWN_VALUE,		 /* reg doesn't contain a valid pointer */
-	PTR_TO_CTX,		 /* reg points to bpf_context */
-	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
-	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
-	PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
-	FRAME_PTR,		 /* reg == frame_pointer */
-	PTR_TO_STACK,		 /* reg == frame_pointer + imm */
-	CONST_IMM,		 /* constant integer value */
-
-	/* PTR_TO_PACKET represents:
-	 * skb->data
-	 * skb->data + imm
-	 * skb->data + (u16) var
-	 * skb->data + (u16) var + imm
-	 * if (range > 0) then [ptr, ptr + range - off) is safe to access
-	 * if (id > 0) means that some 'var' was added
-	 * if (off > 0) menas that 'imm' was added
-	 */
-	PTR_TO_PACKET,
-	PTR_TO_PACKET_END,	 /* skb->data + headlen */
-
-	/* PTR_TO_MAP_VALUE_ADJ is used for doing pointer math inside of a map
-	 * elem value.  We only allow this if we can statically verify that
-	 * access from this register are going to fall within the size of the
-	 * map element.
-	 */
-	PTR_TO_MAP_VALUE_ADJ,
-};
-
 struct bpf_prog;
 
 struct bpf_verifier_ops {
@@ -160,10 +121,8 @@ struct bpf_verifier_ops {
 	/* return true if 'size' wide access at offset 'off' within bpf_context
 	 * with 'type' (read or write) is allowed
 	 */
-	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
-				enum bpf_reg_type *reg_type);
-	int (*gen_prologue)(struct bpf_insn *insn, bool direct_write,
-			    const struct bpf_prog *prog);
+	bool (*is_valid_access)(int off, int size, enum bpf_access_type type);
+
 	u32 (*convert_ctx_access)(enum bpf_access_type type, int dst_reg,
 				  int src_reg, int ctx_off,
 				  struct bpf_insn *insn, struct bpf_prog *prog);
@@ -178,14 +137,10 @@ struct bpf_prog_type_list {
 struct bpf_prog_aux {
 	atomic_t refcnt;
 	u32 used_map_cnt;
-	u32 max_ctx_offset;
 	const struct bpf_verifier_ops *ops;
 	struct bpf_map **used_maps;
 	struct bpf_prog *prog;
 	struct user_struct *user;
-#ifdef CONFIG_SECURITY
-	void *security;
-#endif
 	union {
 		struct work_struct work;
 		struct rcu_head	rcu;
@@ -206,96 +161,20 @@ struct bpf_array {
 	union {
 		char value[0] __aligned(8);
 		void *ptrs[0] __aligned(8);
-		void __percpu *pptrs[0] __aligned(8);
 	};
 };
-
 #define MAX_TAIL_CALL_CNT 32
 
-struct bpf_event_entry {
-	struct perf_event *event;
-	struct file *perf_file;
-	struct file *map_file;
-	struct rcu_head rcu;
-};
-
 u64 bpf_tail_call(u64 ctx, u64 r2, u64 index, u64 r4, u64 r5);
-u64 bpf_get_stackid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
-
+void bpf_fd_array_map_clear(struct bpf_map *map);
 bool bpf_prog_array_compatible(struct bpf_array *array, const struct bpf_prog *fp);
-
 const struct bpf_func_proto *bpf_get_trace_printk_proto(void);
 
-typedef unsigned long (*bpf_ctx_copy_t)(void *dst, const void *src,
-					unsigned long len);
-
-u64 bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
-		     void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy);
-
-/* an array of programs to be executed under rcu_lock.
- *
- * Typical usage:
- * ret = BPF_PROG_RUN_ARRAY(&bpf_prog_array, ctx, BPF_PROG_RUN);
- *
- * the structure returned by bpf_prog_array_alloc() should be populated
- * with program pointers and the last pointer must be NULL.
- * The user has to keep refcnt on the program and make sure the program
- * is removed from the array before bpf_prog_put().
- * The 'struct bpf_prog_array *' should only be replaced with xchg()
- * since other cpus are walking the array of pointers in parallel.
- */
-struct bpf_prog_array {
-	struct rcu_head rcu;
-	struct bpf_prog *progs[0];
-};
-
-struct bpf_prog_array __rcu *bpf_prog_array_alloc(u32 prog_cnt, gfp_t flags);
-void bpf_prog_array_free(struct bpf_prog_array __rcu *progs);
-
-void bpf_prog_array_delete_safe(struct bpf_prog_array __rcu *progs,
-				struct bpf_prog *old_prog);
-int bpf_prog_array_copy(struct bpf_prog_array __rcu *old_array,
-			struct bpf_prog *exclude_prog,
-			struct bpf_prog *include_prog,
-			struct bpf_prog_array **new_array);
-
-#define __BPF_PROG_RUN_ARRAY(array, ctx, func, check_non_null)	\
-	({						\
-		struct bpf_prog **_prog, *__prog;	\
-		struct bpf_prog_array *_array;		\
-		u32 _ret = 1;				\
-		rcu_read_lock();			\
-		_array = rcu_dereference(array);	\
-		if (unlikely(check_non_null && !_array))\
-			goto _out;			\
-		_prog = _array->progs;			\
-		while ((__prog = READ_ONCE(*_prog))) {	\
-			_ret &= func(__prog, ctx);	\
-			_prog++;			\
-		}					\
-_out:							\
-		rcu_read_unlock();			\
-		_ret;					\
-	 })
-
-#define BPF_PROG_RUN_ARRAY(array, ctx, func)		\
-	__BPF_PROG_RUN_ARRAY(array, ctx, func, false)
-
-#define BPF_PROG_RUN_ARRAY_CHECK(array, ctx, func)	\
-	__BPF_PROG_RUN_ARRAY(array, ctx, func, true)
-
 #ifdef CONFIG_BPF_SYSCALL
-DECLARE_PER_CPU(int, bpf_prog_active);
-
 void bpf_register_prog_type(struct bpf_prog_type_list *tl);
 void bpf_register_map_type(struct bpf_map_type_list *tl);
 
-extern const struct file_operations bpf_map_fops;
-extern const struct file_operations bpf_prog_fops;
-
 struct bpf_prog *bpf_prog_get(u32 ufd);
-struct bpf_prog *bpf_prog_get_type(u32 ufd, enum bpf_prog_type type);
-struct bpf_prog *bpf_prog_add(struct bpf_prog *prog, int i);
 struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog);
 void bpf_prog_put(struct bpf_prog *prog);
 
@@ -304,54 +183,17 @@ struct bpf_map *__bpf_map_get(struct fd f);
 struct bpf_map *bpf_map_inc(struct bpf_map *map, bool uref);
 void bpf_map_put_with_uref(struct bpf_map *map);
 void bpf_map_put(struct bpf_map *map);
-int bpf_map_precharge_memlock(u32 pages);
-void *bpf_map_area_alloc(size_t size);
-void bpf_map_area_free(void *base);
 
 extern int sysctl_unprivileged_bpf_disabled;
 
-int bpf_map_new_fd(struct bpf_map *map, int flags);
+int bpf_map_new_fd(struct bpf_map *map);
 int bpf_prog_new_fd(struct bpf_prog *prog);
 
 int bpf_obj_pin_user(u32 ufd, const char __user *pathname);
-int bpf_obj_get_user(const char __user *pathname, int flags);
-
-int bpf_percpu_hash_copy(struct bpf_map *map, void *key, void *value);
-int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value);
-int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
-			   u64 flags);
-int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
-			    u64 flags);
-
-int bpf_stackmap_copy(struct bpf_map *map, void *key, void *value);
-
-int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
-				 void *key, void *value, u64 map_flags);
-void bpf_fd_array_map_clear(struct bpf_map *map);
-
-int bpf_get_file_flag(int flags);
-
-/* memcpy that is used with 8-byte aligned pointers, power-of-8 size and
- * forced to use 'long' read/writes to try to atomically copy long counters.
- * Best-effort only.  No barriers here, since it _will_ race with concurrent
- * updates from BPF programs. Called from bpf syscall and mostly used with
- * size 8 or 16 bytes, so ask compiler to inline it.
- */
-static inline void bpf_long_memcpy(void *dst, const void *src, u32 size)
-{
-	const long *lsrc = src;
-	long *ldst = dst;
-
-	size /= sizeof(long);
-	while (size--)
-		*ldst++ = *lsrc++;
-}
+int bpf_obj_get_user(const char __user *pathname);
 
 /* verify correctness of eBPF program */
 int bpf_check(struct bpf_prog **fp, union bpf_attr *attr);
-
-struct bpf_prog *bpf_prog_get_type_path(const char *name, enum bpf_prog_type type);
-
 #else
 static inline void bpf_register_prog_type(struct bpf_prog_type_list *tl)
 {
@@ -362,29 +204,9 @@ static inline struct bpf_prog *bpf_prog_get(u32 ufd)
 	return ERR_PTR(-EOPNOTSUPP);
 }
 
-static inline struct bpf_prog *bpf_prog_get_type(u32 ufd,
-						 enum bpf_prog_type type)
-{
-	return ERR_PTR(-EOPNOTSUPP);
-}
-
 static inline void bpf_prog_put(struct bpf_prog *prog)
 {
 }
-static inline struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog)
-{
-	return ERR_PTR(-EOPNOTSUPP);
-}
-static inline int bpf_obj_get_user(const char __user *pathname)
-{
-	return -EOPNOTSUPP;
-}
-
-static inline struct bpf_prog *bpf_prog_get_type_path(const char *name,
-				enum bpf_prog_type type)
-{
-	return ERR_PTR(-EOPNOTSUPP);
-}
 #endif /* CONFIG_BPF_SYSCALL */
 
 /* verifier prototypes for helper functions called from eBPF programs */
@@ -401,7 +223,6 @@ extern const struct bpf_func_proto bpf_get_current_uid_gid_proto;
 extern const struct bpf_func_proto bpf_get_current_comm_proto;
 extern const struct bpf_func_proto bpf_skb_vlan_push_proto;
 extern const struct bpf_func_proto bpf_skb_vlan_pop_proto;
-extern const struct bpf_func_proto bpf_get_stackid_proto;
 
 /* Shared helpers among cBPF and eBPF. */
 void bpf_user_rnd_init_once(void);
diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
deleted file mode 100644
index 5031defe59c5..000000000000
--- a/include/linux/bpf_verifier.h
+++ /dev/null
@@ -1,109 +0,0 @@
-/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#ifndef _LINUX_BPF_VERIFIER_H
-#define _LINUX_BPF_VERIFIER_H 1
-
-#include <linux/bpf.h> /* for enum bpf_reg_type */
-#include <linux/filter.h> /* for MAX_BPF_STACK */
-
- /* Just some arbitrary values so we can safely do math without overflowing and
-  * are obviously wrong for any sort of memory access.
-  */
-#define BPF_REGISTER_MAX_RANGE (1024 * 1024 * 1024)
-#define BPF_REGISTER_MIN_RANGE -1
-
-struct bpf_reg_state {
-	enum bpf_reg_type type;
-	union {
-		/* valid when type == CONST_IMM | PTR_TO_STACK | UNKNOWN_VALUE */
-		s64 imm;
-
-		/* valid when type == PTR_TO_PACKET* */
-		struct {
-			u16 off;
-			u16 range;
-		};
-
-		/* valid when type == CONST_PTR_TO_MAP | PTR_TO_MAP_VALUE |
-		 *   PTR_TO_MAP_VALUE_OR_NULL
-		 */
-		struct bpf_map *map_ptr;
-	};
-	u32 id;
-	/* Used to determine if any memory access using this register will
-	 * result in a bad access. These two fields must be last.
-	 * See states_equal()
-	 */
-	s64 min_value;
-	u64 max_value;
-	bool value_from_signed;
-};
-
-enum bpf_stack_slot_type {
-	STACK_INVALID,    /* nothing was stored in this stack slot */
-	STACK_SPILL,      /* register spilled into stack */
-	STACK_MISC	  /* BPF program wrote some data into this slot */
-};
-
-#define BPF_REG_SIZE 8	/* size of eBPF register in bytes */
-
-/* state of the program:
- * type of all registers and stack info
- */
-struct bpf_verifier_state {
-	struct bpf_reg_state regs[MAX_BPF_REG];
-	u8 stack_slot_type[MAX_BPF_STACK];
-	struct bpf_reg_state spilled_regs[MAX_BPF_STACK / BPF_REG_SIZE];
-};
-
-/* linked list of verifier states used to prune search */
-struct bpf_verifier_state_list {
-	struct bpf_verifier_state state;
-	struct bpf_verifier_state_list *next;
-};
-
-struct bpf_insn_aux_data {
-	union {
-		enum bpf_reg_type ptr_type;     /* pointer type for load/store insns */
-		struct bpf_map *map_ptr;        /* pointer for call insn into lookup_elem */
-	};
-	int sanitize_stack_off; /* stack slot to be cleared */
-	bool seen; /* this insn was processed by the verifier */
-};
-
-#define MAX_USED_MAPS 64 /* max number of maps accessed by one eBPF program */
-
-struct bpf_verifier_env;
-struct bpf_ext_analyzer_ops {
-	int (*insn_hook)(struct bpf_verifier_env *env,
-			 int insn_idx, int prev_insn_idx);
-};
-
-/* single container for all structs
- * one verifier_env per bpf_check() call
- */
-struct bpf_verifier_env {
-	struct bpf_prog *prog;		/* eBPF program being verified */
-	struct bpf_verifier_stack_elem *head; /* stack of verifier states to be processed */
-	int stack_size;			/* number of states to be processed */
-	struct bpf_verifier_state cur_state; /* current verifier state */
-	struct bpf_verifier_state_list **explored_states; /* search pruning optimization */
-	const struct bpf_ext_analyzer_ops *analyzer_ops; /* external analyzer ops */
-	void *analyzer_priv; /* pointer to external analyzer's private data */
-	struct bpf_map *used_maps[MAX_USED_MAPS]; /* array of map's used by eBPF program */
-	u32 used_map_cnt;		/* number of used maps */
-	u32 id_gen;			/* used to generate unique reg IDs */
-	bool allow_ptr_leaks;
-	bool seen_direct_write;
-	bool varlen_map_value_access;
-	struct bpf_insn_aux_data *insn_aux_data; /* array of per-insn state */
-};
-
-int bpf_analyzer(struct bpf_prog *prog, const struct bpf_ext_analyzer_ops *ops,
-		 void *priv);
-
-#endif /* _LINUX_BPF_VERIFIER_H */
diff --git a/include/linux/cgroup-defs.h b/include/linux/cgroup-defs.h
index ee2772f769c2..4cd5c95d1ca0 100644
--- a/include/linux/cgroup-defs.h
+++ b/include/linux/cgroup-defs.h
@@ -16,7 +16,6 @@
 #include <linux/percpu-refcount.h>
 #include <linux/percpu-rwsem.h>
 #include <linux/workqueue.h>
-#include <linux/bpf-cgroup.h>
 
 #ifdef CONFIG_CGROUPS
 
@@ -28,7 +27,6 @@ struct kernfs_node;
 struct kernfs_ops;
 struct kernfs_open_file;
 struct seq_file;
-struct poll_table_struct;
 
 #define MAX_CGROUP_TYPE_NAMELEN 32
 #define MAX_CGROUP_ROOT_NAMELEN 64
@@ -36,18 +34,22 @@ struct poll_table_struct;
 
 /* define the enumeration of all cgroup subsystems */
 #define SUBSYS(_x) _x ## _cgrp_id,
+#define SUBSYS_TAG(_t) CGROUP_ ## _t, \
+	__unused_tag_ ## _t = CGROUP_ ## _t - 1,
 enum cgroup_subsys_id {
 #include <linux/cgroup_subsys.h>
 	CGROUP_SUBSYS_COUNT,
 };
+#undef SUBSYS_TAG
 #undef SUBSYS
 
+#define CGROUP_CANFORK_COUNT (CGROUP_CANFORK_END - CGROUP_CANFORK_START)
+
 /* bits in struct cgroup_subsys_state flags field */
 enum {
 	CSS_NO_REF	= (1 << 0), /* no reference counting for this css */
 	CSS_ONLINE	= (1 << 1), /* between ->css_online() and ->css_offline() */
 	CSS_RELEASED	= (1 << 2), /* refcnt reached zero, released */
-	CSS_VISIBLE	= (1 << 3), /* css is visible to userland */
 };
 
 /* bits in struct cgroup flags field */
@@ -193,13 +195,12 @@ struct css_set {
 
 	/*
 	 * If this cset is acting as the source of migration the following
-	 * two fields are set.  mg_src_cgrp and mg_dst_cgrp are
-	 * respectively the source and destination cgroups of the on-going
-	 * migration.  mg_dst_cset is the destination cset the target tasks
-	 * on this cset should be migrated to.  Protected by cgroup_mutex.
+	 * two fields are set.  mg_src_cgrp is the source cgroup of the
+	 * on-going migration and mg_dst_cset is the destination cset the
+	 * target tasks on this cset should be migrated to.  Protected by
+	 * cgroup_mutex.
 	 */
 	struct cgroup *mg_src_cgrp;
-	struct cgroup *mg_dst_cgrp;
 	struct css_set *mg_dst_cset;
 
 	/*
@@ -237,14 +238,6 @@ struct cgroup {
 	 */
 	int id;
 
-	/*
-	 * The depth this cgroup is at.  The root is at depth zero and each
-	 * step down the hierarchy increments the level.  This along with
-	 * ancestor_ids[] can determine whether a given cgroup is a
-	 * descendant of another without traversing the hierarchy.
-	 */
-	int level;
-
 	/*
 	 * Each non-empty css_set associated with this cgroup contributes
 	 * one to populated_cnt.  All children with non-zero popuplated_cnt
@@ -260,14 +253,13 @@ struct cgroup {
 	/*
 	 * The bitmask of subsystems enabled on the child cgroups.
 	 * ->subtree_control is the one configured through
-	 * "cgroup.subtree_control" while ->child_ss_mask is the effective
-	 * one which may have more subsystems enabled.  Controller knobs
-	 * are made available iff it's enabled in ->subtree_control.
+	 * "cgroup.subtree_control" while ->child_subsys_mask is the
+	 * effective one which may have more subsystems enabled.
+	 * Controller knobs are made available iff it's enabled in
+	 * ->subtree_control.
 	 */
-	u16 subtree_control;
-	u16 subtree_ss_mask;
-	u16 old_subtree_control;
-	u16 old_subtree_ss_mask;
+	unsigned int subtree_control;
+	unsigned int child_subsys_mask;
 
 	/* Private pointers for each registered subsystem */
 	struct cgroup_subsys_state __rcu *subsys[CGROUP_SUBSYS_COUNT];
@@ -301,12 +293,6 @@ struct cgroup {
 
 	/* used to schedule release agent */
 	struct work_struct release_agent_work;
-
-	/* used to store eBPF programs */
-	struct cgroup_bpf bpf;
-
-	/* ids of the ancestors at each level including self */
-	int ancestor_ids[];
 };
 
 /*
@@ -326,9 +312,6 @@ struct cgroup_root {
 	/* The root cgroup.  Root is destroyed on its release. */
 	struct cgroup cgrp;
 
-	/* for cgrp->ancestor_ids[0] */
-	int cgrp_ancestor_id_storage;
-
 	/* Number of cgroups in the hierarchy, used only for /proc/cgroups */
 	atomic_t nr_cgrps;
 
@@ -389,9 +372,6 @@ struct cftype {
 	struct list_head node;		/* anchored at ss->cfts */
 	struct kernfs_ops *kf_ops;
 
-	int (*open)(struct kernfs_open_file *of);
-	void (*release)(struct kernfs_open_file *of);
-
 	/*
 	 * read_u64() is a shortcut for the common case of returning a
 	 * single integer. Use it in place of read()
@@ -432,9 +412,6 @@ struct cftype {
 	ssize_t (*write)(struct kernfs_open_file *of,
 			 char *buf, size_t nbytes, loff_t off);
 
-	unsigned int (*poll)(struct kernfs_open_file *of,
-			 struct poll_table_struct *pt);
-
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lock_class_key	lockdep_key;
 #endif
@@ -451,35 +428,21 @@ struct cgroup_subsys {
 	void (*css_released)(struct cgroup_subsys_state *css);
 	void (*css_free)(struct cgroup_subsys_state *css);
 	void (*css_reset)(struct cgroup_subsys_state *css);
+	void (*css_e_css_changed)(struct cgroup_subsys_state *css);
 
-	int (*allow_attach)(struct cgroup_subsys_state *css,
-			    struct cgroup_taskset *tset);
 	int (*can_attach)(struct cgroup_taskset *tset);
 	void (*cancel_attach)(struct cgroup_taskset *tset);
 	void (*attach)(struct cgroup_taskset *tset);
 	void (*post_attach)(void);
-	int (*can_fork)(struct task_struct *task);
-	void (*cancel_fork)(struct task_struct *task);
-	void (*fork)(struct task_struct *task);
+	int (*can_fork)(struct task_struct *task, void **priv_p);
+	void (*cancel_fork)(struct task_struct *task, void *priv);
+	void (*fork)(struct task_struct *task, void *priv);
 	void (*exit)(struct task_struct *task);
 	void (*free)(struct task_struct *task);
 	void (*bind)(struct cgroup_subsys_state *root_css);
 
 	int early_init;
 
-	/*
-	 * If %true, the controller, on the default hierarchy, doesn't show
-	 * up in "cgroup.controllers" or "cgroup.subtree_control", is
-	 * implicitly enabled on all cgroups on the default hierarchy, and
-	 * bypasses the "no internal process" constraint.  This is for
-	 * utility type controllers which is transparent to userland.
-	 *
-	 * An implicit controller can be stolen from the default hierarchy
-	 * anytime and thus must be okay with offline csses from previous
-	 * hierarchies coexisting with csses for the current one.
-	 */
-	bool implicit_on_dfl:1;
-
 	/*
 	 * If %false, this subsystem is properly hierarchical -
 	 * configuration, resource accounting and restriction on a parent
@@ -559,6 +522,7 @@ static inline void cgroup_threadgroup_change_end(struct task_struct *tsk)
 
 #else	/* CONFIG_CGROUPS */
 
+#define CGROUP_CANFORK_COUNT 0
 #define CGROUP_SUBSYS_COUNT 0
 
 static inline void cgroup_threadgroup_change_begin(struct task_struct *tsk) {}
@@ -566,118 +530,4 @@ static inline void cgroup_threadgroup_change_end(struct task_struct *tsk) {}
 
 #endif	/* CONFIG_CGROUPS */
 
-#ifdef CONFIG_SOCK_CGROUP_DATA
-
-/*
- * sock_cgroup_data is embedded at sock->sk_cgrp_data and contains
- * per-socket cgroup information except for memcg association.
- *
- * On legacy hierarchies, net_prio and net_cls controllers directly set
- * attributes on each sock which can then be tested by the network layer.
- * On the default hierarchy, each sock is associated with the cgroup it was
- * created in and the networking layer can match the cgroup directly.
- *
- * To avoid carrying all three cgroup related fields separately in sock,
- * sock_cgroup_data overloads (prioidx, classid) and the cgroup pointer.
- * On boot, sock_cgroup_data records the cgroup that the sock was created
- * in so that cgroup2 matches can be made; however, once either net_prio or
- * net_cls starts being used, the area is overriden to carry prioidx and/or
- * classid.  The two modes are distinguished by whether the lowest bit is
- * set.  Clear bit indicates cgroup pointer while set bit prioidx and
- * classid.
- *
- * While userland may start using net_prio or net_cls at any time, once
- * either is used, cgroup2 matching no longer works.  There is no reason to
- * mix the two and this is in line with how legacy and v2 compatibility is
- * handled.  On mode switch, cgroup references which are already being
- * pointed to by socks may be leaked.  While this can be remedied by adding
- * synchronization around sock_cgroup_data, given that the number of leaked
- * cgroups is bound and highly unlikely to be high, this seems to be the
- * better trade-off.
- */
-struct sock_cgroup_data {
-	union {
-#ifdef __LITTLE_ENDIAN
-		struct {
-			u8	is_data : 1;
-			u8	no_refcnt : 1;
-			u8	padding;
-			u16	prioidx;
-			u32	classid;
-		} __packed;
-#else
-		struct {
-			u32	classid;
-			u16	prioidx;
-			u8	padding;
-			u8	no_refcnt : 1;
-			u8	is_data : 1;
-		} __packed;
-#endif
-		u64		val;
-	};
-};
-
-/*
- * There's a theoretical window where the following accessors race with
- * updaters and return part of the previous pointer as the prioidx or
- * classid.  Such races are short-lived and the result isn't critical.
- */
-static inline u16 sock_cgroup_prioidx(struct sock_cgroup_data *skcd)
-{
-	/* fallback to 1 which is always the ID of the root cgroup */
-	return (skcd->is_data & 1) ? skcd->prioidx : 1;
-}
-
-static inline u32 sock_cgroup_classid(struct sock_cgroup_data *skcd)
-{
-	/* fallback to 0 which is the unconfigured default classid */
-	return (skcd->is_data & 1) ? skcd->classid : 0;
-}
-
-/*
- * If invoked concurrently, the updaters may clobber each other.  The
- * caller is responsible for synchronization.
- */
-static inline void sock_cgroup_set_prioidx(struct sock_cgroup_data *skcd,
-					   u16 prioidx)
-{
-	struct sock_cgroup_data skcd_buf = { .val = READ_ONCE(skcd->val) };
-
-	if (sock_cgroup_prioidx(&skcd_buf) == prioidx)
-		return;
-
-	if (!(skcd_buf.is_data & 1)) {
-		skcd_buf.val = 0;
-		skcd_buf.is_data = 1;
-	}
-
-	skcd_buf.prioidx = prioidx;
-	WRITE_ONCE(skcd->val, skcd_buf.val);	/* see sock_cgroup_ptr() */
-}
-
-static inline void sock_cgroup_set_classid(struct sock_cgroup_data *skcd,
-					   u32 classid)
-{
-	struct sock_cgroup_data skcd_buf = { .val = READ_ONCE(skcd->val) };
-
-	if (sock_cgroup_classid(&skcd_buf) == classid)
-		return;
-
-	if (!(skcd_buf.is_data & 1)) {
-		skcd_buf.val = 0;
-		skcd_buf.is_data = 1;
-	}
-
-	skcd_buf.classid = classid;
-	WRITE_ONCE(skcd->val, skcd_buf.val);	/* see sock_cgroup_ptr() */
-}
-
-#else	/* CONFIG_SOCK_CGROUP_DATA */
-
-struct sock_cgroup_data {
-};
-
-#endif	/* CONFIG_SOCK_CGROUP_DATA */
-
 #endif	/* _LINUX_CGROUP_DEFS_H */
diff --git a/include/linux/cgroup.h b/include/linux/cgroup.h
index e6ab2f1e6f8b..8607c937145f 100644
--- a/include/linux/cgroup.h
+++ b/include/linux/cgroup.h
@@ -17,11 +17,6 @@
 #include <linux/seq_file.h>
 #include <linux/kernfs.h>
 #include <linux/jump_label.h>
-#include <linux/nsproxy.h>
-#include <linux/types.h>
-#include <linux/ns_common.h>
-#include <linux/nsproxy.h>
-#include <linux/user_namespace.h>
 
 #include <linux/cgroup-defs.h>
 
@@ -86,9 +81,7 @@ struct cgroup_subsys_state *cgroup_get_e_css(struct cgroup *cgroup,
 struct cgroup_subsys_state *css_tryget_online_from_dir(struct dentry *dentry,
 						       struct cgroup_subsys *ss);
 
-struct cgroup *cgroup_get_from_path(const char *path);
-struct cgroup *cgroup_get_from_fd(int fd);
-
+bool cgroup_is_descendant(struct cgroup *cgrp, struct cgroup *ancestor);
 int cgroup_attach_task_all(struct task_struct *from, struct task_struct *);
 int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from);
 
@@ -97,15 +90,18 @@ int cgroup_add_legacy_cftypes(struct cgroup_subsys *ss, struct cftype *cfts);
 int cgroup_rm_cftypes(struct cftype *cfts);
 void cgroup_file_notify(struct cgroup_file *cfile);
 
-int task_cgroup_path(struct task_struct *task, char *buf, size_t buflen);
+char *task_cgroup_path(struct task_struct *task, char *buf, size_t buflen);
 int cgroupstats_build(struct cgroupstats *stats, struct dentry *dentry);
 int proc_cgroup_show(struct seq_file *m, struct pid_namespace *ns,
 		     struct pid *pid, struct task_struct *tsk);
 
 void cgroup_fork(struct task_struct *p);
-extern int cgroup_can_fork(struct task_struct *p);
-extern void cgroup_cancel_fork(struct task_struct *p);
-extern void cgroup_post_fork(struct task_struct *p);
+extern int cgroup_can_fork(struct task_struct *p,
+			   void *ss_priv[CGROUP_CANFORK_COUNT]);
+extern void cgroup_cancel_fork(struct task_struct *p,
+			       void *ss_priv[CGROUP_CANFORK_COUNT]);
+extern void cgroup_post_fork(struct task_struct *p,
+			     void *old_ss_priv[CGROUP_CANFORK_COUNT]);
 void cgroup_exit(struct task_struct *p);
 void cgroup_free(struct task_struct *p);
 
@@ -388,21 +384,6 @@ static inline void css_put_many(struct cgroup_subsys_state *css, unsigned int n)
 		percpu_ref_put_many(&css->refcnt, n);
 }
 
-static inline void cgroup_get(struct cgroup *cgrp)
-{
-	css_get(&cgrp->self);
-}
-
-static inline bool cgroup_tryget(struct cgroup *cgrp)
-{
-	return css_tryget(&cgrp->self);
-}
-
-static inline void cgroup_put(struct cgroup *cgrp)
-{
-	css_put(&cgrp->self);
-}
-
 /**
  * task_css_set_check - obtain a task's css_set with extra access conditions
  * @task: the task to obtain css_set for
@@ -516,37 +497,6 @@ static inline struct cgroup *task_cgroup(struct task_struct *task,
 	return task_css(task, subsys_id)->cgroup;
 }
 
-static inline struct cgroup *task_dfl_cgroup(struct task_struct *task)
-{
-	return task_css_set(task)->dfl_cgrp;
-}
-
-static inline struct cgroup *cgroup_parent(struct cgroup *cgrp)
-{
-	struct cgroup_subsys_state *parent_css = cgrp->self.parent;
-
-	if (parent_css)
-		return container_of(parent_css, struct cgroup, self);
-	return NULL;
-}
-
-/**
- * cgroup_is_descendant - test ancestry
- * @cgrp: the cgroup to be tested
- * @ancestor: possible ancestor of @cgrp
- *
- * Test whether @cgrp is a descendant of @ancestor.  It also returns %true
- * if @cgrp == @ancestor.  This function is safe to call as long as @cgrp
- * and @ancestor are accessible.
- */
-static inline bool cgroup_is_descendant(struct cgroup *cgrp,
-					struct cgroup *ancestor)
-{
-	if (cgrp->root != ancestor->root || cgrp->level < ancestor->level)
-		return false;
-	return cgrp->ancestor_ids[ancestor->level] == ancestor->id;
-}
-
 /* no synchronization, the result can only be used as a hint */
 static inline bool cgroup_is_populated(struct cgroup *cgrp)
 {
@@ -588,9 +538,9 @@ static inline int cgroup_name(struct cgroup *cgrp, char *buf, size_t buflen)
 	return kernfs_name(cgrp->kn, buf, buflen);
 }
 
-static inline int cgroup_path(struct cgroup *cgrp, char *buf, size_t buflen)
+static inline char * __must_check cgroup_path(struct cgroup *cgrp, char *buf,
+					      size_t buflen)
 {
-
 	return kernfs_path(cgrp->kn, buf, buflen);
 }
 
@@ -623,17 +573,6 @@ static inline void cgroup_kthread_ready(void)
 	current->no_cgroup_migration = 0;
 }
 
-/*
- * Default Android check for whether the current process is allowed to move a
- * task across cgroups, either because CAP_SYS_NICE is set or because the uid
- * of the calling process is the same as the moved task or because we are
- * running as root.
- * Returns 0 if this is allowed, or -EACCES otherwise.
- */
-int subsys_cgroup_allow_attach(struct cgroup_subsys_state *css,
-			       struct cgroup_taskset *tset);
-
-
 #else /* !CONFIG_CGROUPS */
 
 struct cgroup_subsys_state;
@@ -645,9 +584,13 @@ static inline int cgroupstats_build(struct cgroupstats *stats,
 				    struct dentry *dentry) { return -EINVAL; }
 
 static inline void cgroup_fork(struct task_struct *p) {}
-static inline int cgroup_can_fork(struct task_struct *p) { return 0; }
-static inline void cgroup_cancel_fork(struct task_struct *p) {}
-static inline void cgroup_post_fork(struct task_struct *p) {}
+static inline int cgroup_can_fork(struct task_struct *p,
+				  void *ss_priv[CGROUP_CANFORK_COUNT])
+{ return 0; }
+static inline void cgroup_cancel_fork(struct task_struct *p,
+				      void *ss_priv[CGROUP_CANFORK_COUNT]) {}
+static inline void cgroup_post_fork(struct task_struct *p,
+				    void *ss_priv[CGROUP_CANFORK_COUNT]) {}
 static inline void cgroup_exit(struct task_struct *p) {}
 static inline void cgroup_free(struct task_struct *p) {}
 
@@ -656,98 +599,6 @@ static inline int cgroup_init(void) { return 0; }
 static inline void cgroup_init_kthreadd(void) {}
 static inline void cgroup_kthread_ready(void) {}
 
-static inline int subsys_cgroup_allow_attach(struct cgroup_subsys_state *css,
-					     struct cgroup_taskset *tset)
-{
-	return 0;
-}
-#endif /* !CONFIG_CGROUPS */
-
-/*
- * sock->sk_cgrp_data handling.  For more info, see sock_cgroup_data
- * definition in cgroup-defs.h.
- */
-#ifdef CONFIG_SOCK_CGROUP_DATA
-
-#if defined(CONFIG_CGROUP_NET_PRIO) || defined(CONFIG_CGROUP_NET_CLASSID)
-extern spinlock_t cgroup_sk_update_lock;
-#endif
-
-void cgroup_sk_alloc_disable(void);
-void cgroup_sk_alloc(struct sock_cgroup_data *skcd);
-void cgroup_sk_clone(struct sock_cgroup_data *skcd);
-void cgroup_sk_free(struct sock_cgroup_data *skcd);
-
-static inline struct cgroup *sock_cgroup_ptr(struct sock_cgroup_data *skcd)
-{
-#if defined(CONFIG_CGROUP_NET_PRIO) || defined(CONFIG_CGROUP_NET_CLASSID)
-	unsigned long v;
-
-	/*
-	 * @skcd->val is 64bit but the following is safe on 32bit too as we
-	 * just need the lower ulong to be written and read atomically.
-	 */
-	v = READ_ONCE(skcd->val);
-
-	if (v & 3)
-		return &cgrp_dfl_root.cgrp;
-
-	return (struct cgroup *)(unsigned long)v ?: &cgrp_dfl_root.cgrp;
-#else
-	return (struct cgroup *)(unsigned long)skcd->val;
-#endif
-}
-
-#else	/* CONFIG_CGROUP_DATA */
-
-static inline void cgroup_sk_alloc(struct sock_cgroup_data *skcd) {}
-static inline void cgroup_sk_clone(struct sock_cgroup_data *skcd) {}
-static inline void cgroup_sk_free(struct sock_cgroup_data *skcd) {}
-
-#endif	/* CONFIG_CGROUP_DATA */
-
-struct cgroup_namespace {
-	atomic_t		count;
-	struct ns_common	ns;
-	struct user_namespace	*user_ns;
-	struct css_set          *root_cset;
-};
-
-extern struct cgroup_namespace init_cgroup_ns;
-
-#ifdef CONFIG_CGROUPS
-
-void free_cgroup_ns(struct cgroup_namespace *ns);
-
-struct cgroup_namespace *copy_cgroup_ns(unsigned long flags,
-					struct user_namespace *user_ns,
-					struct cgroup_namespace *old_ns);
-
-int cgroup_path_ns(struct cgroup *cgrp, char *buf, size_t buflen,
-		   struct cgroup_namespace *ns);
-
-#else /* !CONFIG_CGROUPS */
-
-static inline void free_cgroup_ns(struct cgroup_namespace *ns) { }
-static inline struct cgroup_namespace *
-copy_cgroup_ns(unsigned long flags, struct user_namespace *user_ns,
-	       struct cgroup_namespace *old_ns)
-{
-	return old_ns;
-}
-
 #endif /* !CONFIG_CGROUPS */
 
-static inline void get_cgroup_ns(struct cgroup_namespace *ns)
-{
-	if (ns)
-		atomic_inc(&ns->count);
-}
-
-static inline void put_cgroup_ns(struct cgroup_namespace *ns)
-{
-	if (ns && atomic_dec_and_test(&ns->count))
-		free_cgroup_ns(ns);
-}
-
 #endif /* _LINUX_CGROUP_H */
diff --git a/include/linux/cgroup_subsys.h b/include/linux/cgroup_subsys.h
index 7f4a2a5a2a77..e133705d794a 100644
--- a/include/linux/cgroup_subsys.h
+++ b/include/linux/cgroup_subsys.h
@@ -6,8 +6,14 @@
 
 /*
  * This file *must* be included with SUBSYS() defined.
+ * SUBSYS_TAG() is a noop if undefined.
  */
 
+#ifndef SUBSYS_TAG
+#define __TMP_SUBSYS_TAG
+#define SUBSYS_TAG(_x)
+#endif
+
 #if IS_ENABLED(CONFIG_CPUSETS)
 SUBSYS(cpuset)
 #endif
@@ -56,10 +62,17 @@ SUBSYS(net_prio)
 SUBSYS(hugetlb)
 #endif
 
+/*
+ * Subsystems that implement the can_fork() family of callbacks.
+ */
+SUBSYS_TAG(CANFORK_START)
+
 #if IS_ENABLED(CONFIG_CGROUP_PIDS)
 SUBSYS(pids)
 #endif
 
+SUBSYS_TAG(CANFORK_END)
+
 /*
  * The following subsystems are not supported on the default hierarchy.
  */
@@ -67,6 +80,11 @@ SUBSYS(pids)
 SUBSYS(debug)
 #endif
 
+#ifdef __TMP_SUBSYS_TAG
+#undef __TMP_SUBSYS_TAG
+#undef SUBSYS_TAG
+#endif
+
 /*
  * DO NOT ADD ANY SUBSYSTEM WITHOUT EXPLICIT ACKS FROM CGROUP MAINTAINERS.
  */
diff --git a/include/linux/filter.h b/include/linux/filter.h
index 69e8e1951eb2..677fa3b42194 100644
--- a/include/linux/filter.h
+++ b/include/linux/filter.h
@@ -13,8 +13,6 @@
 #include <linux/printk.h>
 #include <linux/workqueue.h>
 #include <linux/sched.h>
-#include <linux/capability.h>
-
 #include <net/sch_generic.h>
 
 #include <asm/cacheflush.h>
@@ -44,15 +42,6 @@ struct bpf_prog_aux;
 #define BPF_REG_X	BPF_REG_7
 #define BPF_REG_TMP	BPF_REG_8
 
-/* Kernel hidden auxiliary/helper register for hardening step.
- * Only used by eBPF JITs. It's nothing more than a temporary
- * register that JITs use internally, only that here it's part
- * of eBPF instructions that have been rewritten for blinding
- * constants. See JIT pre-step in bpf_jit_blind_constants().
- */
-#define BPF_REG_AX		MAX_BPF_REG
-#define MAX_BPF_JIT_REG		(MAX_BPF_REG + 1)
-
 /* BPF program can access up to 512 bytes of stack space. */
 #define MAX_BPF_STACK	512
 
@@ -314,70 +303,6 @@ struct bpf_prog_aux;
 	bpf_size;						\
 })
 
-#define BPF_SIZEOF(type)					\
-	({							\
-		const int __size = bytes_to_bpf_size(sizeof(type)); \
-		BUILD_BUG_ON(__size < 0);			\
-		__size;						\
-	})
-
-#define BPF_FIELD_SIZEOF(type, field)				\
-	({							\
-		const int __size = bytes_to_bpf_size(FIELD_SIZEOF(type, field)); \
-		BUILD_BUG_ON(__size < 0);			\
-		__size;						\
-	})
-
-#define __BPF_MAP_0(m, v, ...) v
-#define __BPF_MAP_1(m, v, t, a, ...) m(t, a)
-#define __BPF_MAP_2(m, v, t, a, ...) m(t, a), __BPF_MAP_1(m, v, __VA_ARGS__)
-#define __BPF_MAP_3(m, v, t, a, ...) m(t, a), __BPF_MAP_2(m, v, __VA_ARGS__)
-#define __BPF_MAP_4(m, v, t, a, ...) m(t, a), __BPF_MAP_3(m, v, __VA_ARGS__)
-#define __BPF_MAP_5(m, v, t, a, ...) m(t, a), __BPF_MAP_4(m, v, __VA_ARGS__)
-
-#define __BPF_REG_0(...) __BPF_PAD(5)
-#define __BPF_REG_1(...) __BPF_MAP(1, __VA_ARGS__), __BPF_PAD(4)
-#define __BPF_REG_2(...) __BPF_MAP(2, __VA_ARGS__), __BPF_PAD(3)
-#define __BPF_REG_3(...) __BPF_MAP(3, __VA_ARGS__), __BPF_PAD(2)
-#define __BPF_REG_4(...) __BPF_MAP(4, __VA_ARGS__), __BPF_PAD(1)
-#define __BPF_REG_5(...) __BPF_MAP(5, __VA_ARGS__)
-
-#define __BPF_MAP(n, ...) __BPF_MAP_##n(__VA_ARGS__)
-#define __BPF_REG(n, ...) __BPF_REG_##n(__VA_ARGS__)
-
-#define __BPF_CAST(t, a)						       \
-	(__force t)							       \
-	(__force							       \
-	 typeof(__builtin_choose_expr(sizeof(t) == sizeof(unsigned long),      \
-				      (unsigned long)0, (t)0))) a
-#define __BPF_V void
-#define __BPF_N
-
-#define __BPF_DECL_ARGS(t, a) t   a
-#define __BPF_DECL_REGS(t, a) u64 a
-
-#define __BPF_PAD(n)							       \
-	__BPF_MAP(n, __BPF_DECL_ARGS, __BPF_N, u64, __ur_1, u64, __ur_2,       \
-		  u64, __ur_3, u64, __ur_4, u64, __ur_5)
-
-#define BPF_CALL_x(x, name, ...)					       \
-	static __always_inline						       \
-	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));   \
-	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));	       \
-	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))	       \
-	{								       \
-		return ____##name(__BPF_MAP(x,__BPF_CAST,__BPF_N,__VA_ARGS__));\
-	}								       \
-	static __always_inline						       \
-	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))
-
-#define BPF_CALL_0(name, ...)	BPF_CALL_x(0, name, __VA_ARGS__)
-#define BPF_CALL_1(name, ...)	BPF_CALL_x(1, name, __VA_ARGS__)
-#define BPF_CALL_2(name, ...)	BPF_CALL_x(2, name, __VA_ARGS__)
-#define BPF_CALL_3(name, ...)	BPF_CALL_x(3, name, __VA_ARGS__)
-#define BPF_CALL_4(name, ...)	BPF_CALL_x(4, name, __VA_ARGS__)
-#define BPF_CALL_5(name, ...)	BPF_CALL_x(5, name, __VA_ARGS__)
-
 #ifdef CONFIG_COMPAT
 /* A struct sock_filter is architecture independent. */
 struct compat_sock_fprog {
@@ -423,66 +348,27 @@ struct sk_filter {
 	struct bpf_prog	*prog;
 };
 
-#define BPF_PROG_RUN(filter, ctx)  (*(filter)->bpf_func)(ctx, (filter)->insnsi)
-
-#define BPF_SKB_CB_LEN QDISC_CB_PRIV_LEN
-
-struct bpf_skb_data_end {
-	struct qdisc_skb_cb qdisc_cb;
-	void *data_end;
-};
-
-struct xdp_buff {
-	void *data;
-	void *data_end;
-};
-
-/* compute the linear packet data range [data, data_end) which
- * will be accessed by cls_bpf and act_bpf programs
- */
-static inline void bpf_compute_data_end(struct sk_buff *skb)
-{
-	struct bpf_skb_data_end *cb = (struct bpf_skb_data_end *)skb->cb;
-
-	BUILD_BUG_ON(sizeof(*cb) > FIELD_SIZEOF(struct sk_buff, cb));
-	cb->data_end = skb->data + skb_headlen(skb);
-}
-
-static inline u8 *bpf_skb_cb(struct sk_buff *skb)
-{
-	/* eBPF programs may read/write skb->cb[] area to transfer meta
-	 * data between tail calls. Since this also needs to work with
-	 * tc, that scratch memory is mapped to qdisc_skb_cb's data area.
-	 *
-	 * In some socket filter cases, the cb unfortunately needs to be
-	 * saved/restored so that protocol specific skb->cb[] data won't
-	 * be lost. In any case, due to unpriviledged eBPF programs
-	 * attached to sockets, we need to clear the bpf_skb_cb() area
-	 * to not leak previous contents to user space.
-	 */
-	BUILD_BUG_ON(FIELD_SIZEOF(struct __sk_buff, cb) != BPF_SKB_CB_LEN);
-	BUILD_BUG_ON(FIELD_SIZEOF(struct __sk_buff, cb) !=
-		     FIELD_SIZEOF(struct qdisc_skb_cb, data));
-
-	return qdisc_skb_cb(skb)->data;
-}
+#define BPF_PROG_RUN(filter, ctx)  (*filter->bpf_func)(ctx, filter->insnsi)
 
 static inline u32 bpf_prog_run_save_cb(const struct bpf_prog *prog,
 				       struct sk_buff *skb)
 {
-	u8 *cb_data = bpf_skb_cb(skb);
-	u8 cb_saved[BPF_SKB_CB_LEN];
+	u8 *cb_data = qdisc_skb_cb(skb)->data;
+	u8 saved_cb[QDISC_CB_PRIV_LEN];
 	u32 res;
 
+	BUILD_BUG_ON(FIELD_SIZEOF(struct __sk_buff, cb) !=
+		     QDISC_CB_PRIV_LEN);
+
 	if (unlikely(prog->cb_access)) {
-		memcpy(cb_saved, cb_data, sizeof(cb_saved));
-		memset(cb_data, 0, sizeof(cb_saved));
+		memcpy(saved_cb, cb_data, sizeof(saved_cb));
+		memset(cb_data, 0, sizeof(saved_cb));
 	}
 
 	res = BPF_PROG_RUN(prog, skb);
 
 	if (unlikely(prog->cb_access))
-		memcpy(cb_data, cb_saved, sizeof(cb_saved));
+		memcpy(cb_data, saved_cb, sizeof(saved_cb));
 
 	return res;
 }
@@ -490,26 +376,13 @@ static inline u32 bpf_prog_run_save_cb(const struct bpf_prog *prog,
 static inline u32 bpf_prog_run_clear_cb(const struct bpf_prog *prog,
 					struct sk_buff *skb)
 {
-	u8 *cb_data = bpf_skb_cb(skb);
+	u8 *cb_data = qdisc_skb_cb(skb)->data;
 
 	if (unlikely(prog->cb_access))
-		memset(cb_data, 0, BPF_SKB_CB_LEN);
-
+		memset(cb_data, 0, QDISC_CB_PRIV_LEN);
 	return BPF_PROG_RUN(prog, skb);
 }
 
-static inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog,
-				   struct xdp_buff *xdp)
-{
-	u32 ret;
-
-	rcu_read_lock();
-	ret = BPF_PROG_RUN(prog, (void *)xdp);
-	rcu_read_unlock();
-
-	return ret;
-}
-
 static inline unsigned int bpf_prog_size(unsigned int proglen)
 {
 	return max(sizeof(struct bpf_prog),
@@ -554,7 +427,7 @@ static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
 	return sk_filter_trim_cap(sk, skb, 1);
 }
 
-struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err);
+int bpf_prog_select_runtime(struct bpf_prog *fp);
 void bpf_prog_free(struct bpf_prog *fp);
 
 struct bpf_prog *bpf_prog_alloc(unsigned int size, gfp_t gfp_extra_flags);
@@ -577,10 +450,12 @@ int bpf_prog_create_from_user(struct bpf_prog **pfp, struct sock_fprog *fprog,
 void bpf_prog_destroy(struct bpf_prog *fp);
 
 int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk);
+int __sk_attach_filter(struct sock_fprog *fprog, struct sock *sk,
+		       bool locked);
 int sk_attach_bpf(u32 ufd, struct sock *sk);
-int sk_reuseport_attach_filter(struct sock_fprog *fprog, struct sock *sk);
-int sk_reuseport_attach_bpf(u32 ufd, struct sock *sk);
 int sk_detach_filter(struct sock *sk);
+int __sk_detach_filter(struct sock *sk, bool locked);
+
 int sk_get_filter(struct sock *sk, struct sock_filter __user *filter,
 		  unsigned int len);
 
@@ -588,19 +463,13 @@ bool sk_filter_charge(struct sock *sk, struct sk_filter *fp);
 void sk_filter_uncharge(struct sock *sk, struct sk_filter *fp);
 
 u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
-
-struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);
+void bpf_int_jit_compile(struct bpf_prog *fp);
 bool bpf_helper_changes_skb_data(void *func);
 
 struct bpf_prog *bpf_patch_insn_single(struct bpf_prog *prog, u32 off,
 				       const struct bpf_insn *patch, u32 len);
-void bpf_warn_invalid_xdp_action(u32 act);
 
 #ifdef CONFIG_BPF_JIT
-extern int bpf_jit_enable;
-extern int bpf_jit_harden;
-extern long bpf_jit_limit;
-
 typedef void (*bpf_jit_fill_hole_t)(void *area, unsigned int size);
 
 struct bpf_binary_header *
@@ -612,9 +481,6 @@ void bpf_jit_binary_free(struct bpf_binary_header *hdr);
 void bpf_jit_compile(struct bpf_prog *fp);
 void bpf_jit_free(struct bpf_prog *fp);
 
-struct bpf_prog *bpf_jit_blind_constants(struct bpf_prog *fp);
-void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other);
-
 static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
 				u32 pass, void *image)
 {
@@ -625,33 +491,6 @@ static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
 		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET,
 			       16, 1, image, proglen, false);
 }
-
-static inline bool bpf_jit_is_ebpf(void)
-{
-# ifdef CONFIG_HAVE_EBPF_JIT
-	return true;
-# else
-	return false;
-# endif
-}
-
-static inline bool bpf_jit_blinding_enabled(void)
-{
-	/* These are the prerequisites, should someone ever have the
-	 * idea to call blinding outside of them, we make sure to
-	 * bail out.
-	 */
-	if (!bpf_jit_is_ebpf())
-		return false;
-	if (!bpf_jit_enable)
-		return false;
-	if (!bpf_jit_harden)
-		return false;
-	if (bpf_jit_harden == 1 && capable(CAP_SYS_ADMIN))
-		return false;
-
-	return true;
-}
 #else
 static inline void bpf_jit_compile(struct bpf_prog *fp)
 {
diff --git a/include/linux/frame.h b/include/linux/frame.h
deleted file mode 100644
index d772c61c31da..000000000000
--- a/include/linux/frame.h
+++ /dev/null
@@ -1,23 +0,0 @@
-#ifndef _LINUX_FRAME_H
-#define _LINUX_FRAME_H
-
-#ifdef CONFIG_STACK_VALIDATION
-/*
- * This macro marks the given function's stack frame as "non-standard", which
- * tells objtool to ignore the function when doing stack metadata validation.
- * It should only be used in special cases where you're 100% sure it won't
- * affect the reliability of frame pointers and kernel stack traces.
- *
- * For more information, see tools/objtool/Documentation/stack-validation.txt.
- */
-#define STACK_FRAME_NON_STANDARD(func) \
-	static void __used __section(.discard.func_stack_frame_non_standard) \
-		*__func_stack_frame_non_standard_##func = func
-
-#else /* !CONFIG_STACK_VALIDATION */
-
-#define STACK_FRAME_NON_STANDARD(func)
-
-#endif /* CONFIG_STACK_VALIDATION */
-
-#endif /* _LINUX_FRAME_H */
diff --git a/include/linux/fs.h b/include/linux/fs.h
index 42ac99e898a4..077f8390fd81 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -1442,13 +1442,6 @@ struct super_block {
 	struct workqueue_struct *s_dio_done_wq;
 	struct hlist_head s_pins;
 
-	/*
-	 * Owning user namespace and default context in which to
-	 * interpret filesystem uids, gids, quotas, device nodes,
-	 * xattrs and security labels.
-	 */
-	struct user_namespace *s_user_ns;
-
 	/*
 	 * Keep the lru lists last in the structure so they always sit on their
 	 * own individual cachelines.
@@ -2066,9 +2059,8 @@ struct file_system_type {
 
 #define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)
 
-extern struct dentry *mount_ns(struct file_system_type *fs_type,
-	int flags, void *data, void *ns, struct user_namespace *user_ns,
-	int (*fill_super)(struct super_block *, void *, int));
+extern struct dentry *mount_ns(struct file_system_type *fs_type, int flags,
+	void *data, int (*fill_super)(struct super_block *, void *, int));
 extern struct dentry *mount_bdev(struct file_system_type *fs_type,
 	int flags, const char *dev_name, void *data,
 	int (*fill_super)(struct super_block *, void *, int));
@@ -2088,11 +2080,6 @@ void deactivate_locked_super(struct super_block *sb);
 int set_anon_super(struct super_block *s, void *data);
 int get_anon_bdev(dev_t *);
 void free_anon_bdev(dev_t);
-struct super_block *sget_userns(struct file_system_type *type,
-			int (*test)(struct super_block *,void *),
-			int (*set)(struct super_block *,void *),
-			int flags, struct user_namespace *user_ns,
-			void *data);
 struct super_block *sget(struct file_system_type *type,
 			int (*test)(struct super_block *,void *),
 			int (*set)(struct super_block *,void *),
diff --git a/include/linux/kernfs.h b/include/linux/kernfs.h
index 4389b3157168..5d4e9c4b821d 100644
--- a/include/linux/kernfs.h
+++ b/include/linux/kernfs.h
@@ -24,7 +24,6 @@ struct seq_file;
 struct vm_area_struct;
 struct super_block;
 struct file_system_type;
-struct poll_table_struct;
 
 struct kernfs_open_node;
 struct kernfs_iattrs;
@@ -47,7 +46,6 @@ enum kernfs_node_flag {
 	KERNFS_SUICIDAL		= 0x0400,
 	KERNFS_SUICIDED		= 0x0800,
 	KERNFS_EMPTY_DIR	= 0x1000,
-	KERNFS_HAS_RELEASE	= 0x2000,
 };
 
 /* @flags for kernfs_create_root() */
@@ -154,8 +152,6 @@ struct kernfs_syscall_ops {
 	int (*rmdir)(struct kernfs_node *kn);
 	int (*rename)(struct kernfs_node *kn, struct kernfs_node *new_parent,
 		      const char *new_name);
-	int (*show_path)(struct seq_file *sf, struct kernfs_node *kn,
-			 struct kernfs_root *root);
 };
 
 struct kernfs_root {
@@ -177,7 +173,6 @@ struct kernfs_open_file {
 	/* published fields */
 	struct kernfs_node	*kn;
 	struct file		*file;
-	struct seq_file		*seq_file;
 	void			*priv;
 
 	/* private fields, do not use outside kernfs proper */
@@ -188,18 +183,10 @@ struct kernfs_open_file {
 
 	size_t			atomic_write_len;
 	bool			mmapped;
-	bool			released:1;
 	const struct vm_operations_struct *vm_ops;
 };
 
 struct kernfs_ops {
-	/*
-	 * Optional open/release methods.  Both are called with
-	 * @of->seq_file populated.
-	 */
-	int (*open)(struct kernfs_open_file *of);
-	void (*release)(struct kernfs_open_file *of);
-
 	/*
 	 * Read is handled by either seq_file or raw_read().
 	 *
@@ -238,9 +225,6 @@ struct kernfs_ops {
 	ssize_t (*write)(struct kernfs_open_file *of, char *buf, size_t bytes,
 			 loff_t off);
 
-	unsigned int (*poll)(struct kernfs_open_file *of,
-			     struct poll_table_struct *pt);
-
 	int (*mmap)(struct kernfs_open_file *of, struct vm_area_struct *vma);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
@@ -283,15 +267,13 @@ static inline bool kernfs_ns_enabled(struct kernfs_node *kn)
 
 int kernfs_name(struct kernfs_node *kn, char *buf, size_t buflen);
 size_t kernfs_path_len(struct kernfs_node *kn);
-int kernfs_path_from_node(struct kernfs_node *root_kn, struct kernfs_node *kn,
-			  char *buf, size_t buflen);
+char * __must_check kernfs_path(struct kernfs_node *kn, char *buf,
+				size_t buflen);
 void pr_cont_kernfs_name(struct kernfs_node *kn);
 void pr_cont_kernfs_path(struct kernfs_node *kn);
 struct kernfs_node *kernfs_get_parent(struct kernfs_node *kn);
 struct kernfs_node *kernfs_find_and_get_ns(struct kernfs_node *parent,
 					   const char *name, const void *ns);
-struct kernfs_node *kernfs_walk_and_get_ns(struct kernfs_node *parent,
-					   const char *path, const void *ns);
 void kernfs_get(struct kernfs_node *kn);
 void kernfs_put(struct kernfs_node *kn);
 
@@ -299,8 +281,6 @@ struct kernfs_node *kernfs_node_from_dentry(struct dentry *dentry);
 struct kernfs_root *kernfs_root_from_sb(struct super_block *sb);
 struct inode *kernfs_get_inode(struct super_block *sb, struct kernfs_node *kn);
 
-struct dentry *kernfs_node_dentry(struct kernfs_node *kn,
-				  struct super_block *sb);
 struct kernfs_root *kernfs_create_root(struct kernfs_syscall_ops *scops,
 				       unsigned int flags, void *priv);
 void kernfs_destroy_root(struct kernfs_root *root);
@@ -329,8 +309,6 @@ int kernfs_remove_by_name_ns(struct kernfs_node *parent, const char *name,
 int kernfs_rename_ns(struct kernfs_node *kn, struct kernfs_node *new_parent,
 		     const char *new_name, const void *new_ns);
 int kernfs_setattr(struct kernfs_node *kn, const struct iattr *iattr);
-unsigned int kernfs_generic_poll(struct kernfs_open_file *of,
-				 struct poll_table_struct *pt);
 void kernfs_notify(struct kernfs_node *kn);
 
 const void *kernfs_super_ns(struct super_block *sb);
@@ -358,10 +336,9 @@ static inline int kernfs_name(struct kernfs_node *kn, char *buf, size_t buflen)
 static inline size_t kernfs_path_len(struct kernfs_node *kn)
 { return 0; }
 
-static inline int kernfs_path_from_node(struct kernfs_node *root_kn,
-					struct kernfs_node *kn,
-					char *buf, size_t buflen)
-{ return -ENOSYS; }
+static inline char * __must_check kernfs_path(struct kernfs_node *kn, char *buf,
+					      size_t buflen)
+{ return NULL; }
 
 static inline void pr_cont_kernfs_name(struct kernfs_node *kn) { }
 static inline void pr_cont_kernfs_path(struct kernfs_node *kn) { }
@@ -373,10 +350,6 @@ static inline struct kernfs_node *
 kernfs_find_and_get_ns(struct kernfs_node *parent, const char *name,
 		       const void *ns)
 { return NULL; }
-static inline struct kernfs_node *
-kernfs_walk_and_get_ns(struct kernfs_node *parent, const char *path,
-		       const void *ns)
-{ return NULL; }
 
 static inline void kernfs_get(struct kernfs_node *kn) { }
 static inline void kernfs_put(struct kernfs_node *kn) { }
@@ -451,34 +424,12 @@ static inline void kernfs_init(void) { }
 
 #endif	/* CONFIG_KERNFS */
 
-/**
- * kernfs_path - build full path of a given node
- * @kn: kernfs_node of interest
- * @buf: buffer to copy @kn's name into
- * @buflen: size of @buf
- *
- * Builds and returns the full path of @kn in @buf of @buflen bytes.  The
- * path is built from the end of @buf so the returned pointer usually
- * doesn't match @buf.  If @buf isn't long enough, @buf is nul terminated
- * and %NULL is returned.
- */
-static inline int kernfs_path(struct kernfs_node *kn, char *buf, size_t buflen)
-{
-	return kernfs_path_from_node(kn, NULL, buf, buflen);
-}
-
 static inline struct kernfs_node *
 kernfs_find_and_get(struct kernfs_node *kn, const char *name)
 {
 	return kernfs_find_and_get_ns(kn, name, NULL);
 }
 
-static inline struct kernfs_node *
-kernfs_walk_and_get(struct kernfs_node *kn, const char *path)
-{
-	return kernfs_walk_and_get_ns(kn, path, NULL);
-}
-
 static inline struct kernfs_node *
 kernfs_create_dir(struct kernfs_node *parent, const char *name, umode_t mode,
 		  void *priv)
diff --git a/include/linux/list_nulls.h b/include/linux/list_nulls.h
index 302999e75470..703928e4fd42 100644
--- a/include/linux/list_nulls.h
+++ b/include/linux/list_nulls.h
@@ -29,11 +29,6 @@ struct hlist_nulls_node {
 	((ptr)->first = (struct hlist_nulls_node *) NULLS_MARKER(nulls))
 
 #define hlist_nulls_entry(ptr, type, member) container_of(ptr,type,member)
-
-#define hlist_nulls_entry_safe(ptr, type, member) \
-	({ typeof(ptr) ____ptr = (ptr); \
-	   !is_a_nulls(____ptr) ? hlist_nulls_entry(____ptr, type, member) : NULL; \
-	})
 /**
  * ptr_is_a_nulls - Test if a ptr is a nulls
  * @ptr: ptr to be tested
diff --git a/include/linux/lsm_hooks.h b/include/linux/lsm_hooks.h
index 479ddf6811f5..8a9bffb2dac4 100644
--- a/include/linux/lsm_hooks.h
+++ b/include/linux/lsm_hooks.h
@@ -1297,40 +1297,7 @@
  *	@inode we wish to get the security context of.
  *	@ctx is a pointer in which to place the allocated security context.
  *	@ctxlen points to the place to put the length of @ctx.
- *
- * Security hooks for using the eBPF maps and programs functionalities through
- * eBPF syscalls.
- *
- * @bpf:
- *	Do a initial check for all bpf syscalls after the attribute is copied
- *	into the kernel. The actual security module can implement their own
- *	rules to check the specific cmd they need.
- *
- * @bpf_map:
- *	Do a check when the kernel generate and return a file descriptor for
- *	eBPF maps.
- *
- *	@map: bpf map that we want to access
- *	@mask: the access flags
- *
- * @bpf_prog:
- *	Do a check when the kernel generate and return a file descriptor for
- *	eBPF programs.
- *
- *	@prog: bpf prog that userspace want to use.
- *
- * @bpf_map_alloc_security:
- *	Initialize the security field inside bpf map.
- *
- * @bpf_map_free_security:
- *	Clean up the security information stored inside bpf map.
- *
- * @bpf_prog_alloc_security:
- *	Initialize the security field inside bpf program.
- *
- * @bpf_prog_free_security:
- *	Clean up the security information stored inside bpf prog.
- *
+ * This is the main security structure.
  */
 
 union security_list_options {
@@ -1649,17 +1616,6 @@ union security_list_options {
 				struct audit_context *actx);
 	void (*audit_rule_free)(void *lsmrule);
 #endif /* CONFIG_AUDIT */
-
-#ifdef CONFIG_BPF_SYSCALL
-	int (*bpf)(int cmd, union bpf_attr *attr,
-				 unsigned int size);
-	int (*bpf_map)(struct bpf_map *map, fmode_t fmode);
-	int (*bpf_prog)(struct bpf_prog *prog);
-	int (*bpf_map_alloc_security)(struct bpf_map *map);
-	void (*bpf_map_free_security)(struct bpf_map *map);
-	int (*bpf_prog_alloc_security)(struct bpf_prog_aux *aux);
-	void (*bpf_prog_free_security)(struct bpf_prog_aux *aux);
-#endif /* CONFIG_BPF_SYSCALL */
 };
 
 struct security_hook_heads {
@@ -1873,15 +1829,6 @@ struct security_hook_heads {
 	struct list_head audit_rule_match;
 	struct list_head audit_rule_free;
 #endif /* CONFIG_AUDIT */
-#ifdef CONFIG_BPF_SYSCALL
-	struct list_head bpf;
-	struct list_head bpf_map;
-	struct list_head bpf_prog;
-	struct list_head bpf_map_alloc_security;
-	struct list_head bpf_map_free_security;
-	struct list_head bpf_prog_alloc_security;
-	struct list_head bpf_prog_free_security;
-#endif /* CONFIG_BPF_SYSCALL */
 };
 
 /*
diff --git a/include/linux/netdevice.h b/include/linux/netdevice.h
index 03388967ac74..0555d5a4448e 100644
--- a/include/linux/netdevice.h
+++ b/include/linux/netdevice.h
@@ -2304,8 +2304,6 @@ void synchronize_net(void);
 int init_dummy_netdev(struct net_device *dev);
 
 DECLARE_PER_CPU(int, xmit_recursion);
-#define XMIT_RECURSION_LIMIT	10
-
 static inline int dev_recursion_level(void)
 {
 	return this_cpu_read(xmit_recursion);
@@ -3633,6 +3631,7 @@ void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
 extern int		netdev_max_backlog;
 extern int		netdev_tstamp_prequeue;
 extern int		weight_p;
+extern int		bpf_jit_enable;
 
 bool netdev_has_upper_dev(struct net_device *dev, struct net_device *upper_dev);
 struct net_device *netdev_upper_get_next_dev_rcu(struct net_device *dev,
diff --git a/include/linux/nsproxy.h b/include/linux/nsproxy.h
index ac0d65bef5d0..35fa08fd7739 100644
--- a/include/linux/nsproxy.h
+++ b/include/linux/nsproxy.h
@@ -8,7 +8,6 @@ struct mnt_namespace;
 struct uts_namespace;
 struct ipc_namespace;
 struct pid_namespace;
-struct cgroup_namespace;
 struct fs_struct;
 
 /*
@@ -34,7 +33,6 @@ struct nsproxy {
 	struct mnt_namespace *mnt_ns;
 	struct pid_namespace *pid_ns_for_children;
 	struct net 	     *net_ns;
-	struct cgroup_namespace *cgroup_ns;
 };
 extern struct nsproxy init_nsproxy;
 
diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 423df8161c81..efce166a9f17 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -58,12 +58,7 @@ struct perf_guest_info_callbacks {
 
 struct perf_callchain_entry {
 	__u64				nr;
-	__u64				ip[0]; /* /proc/sys/kernel/perf_event_max_stack */
-};
-
-struct perf_callchain_entry_ctx {
-	struct perf_callchain_entry *entry;
-	u32			    max_stack;
+	__u64				ip[PERF_MAX_STACK_DEPTH];
 };
 
 struct perf_raw_record {
@@ -591,10 +586,6 @@ struct perf_event {
 	u64				(*clock)(void);
 	perf_overflow_handler_t		overflow_handler;
 	void				*overflow_handler_context;
-#ifdef CONFIG_BPF_SYSCALL
-	perf_overflow_handler_t		orig_overflow_handler;
-	struct bpf_prog			*prog;
-#endif
 
 #ifdef CONFIG_EVENT_TRACING
 	struct trace_event_call		*tp_event;
@@ -702,11 +693,6 @@ struct perf_output_handle {
 	int				page;
 };
 
-struct bpf_perf_event_data_kern {
-	struct pt_regs *regs;
-	struct perf_sample_data *data;
-};
-
 #ifdef CONFIG_CGROUP_PERF
 
 /*
@@ -761,7 +747,7 @@ extern int perf_event_init_task(struct task_struct *child);
 extern void perf_event_exit_task(struct task_struct *child);
 extern void perf_event_free_task(struct task_struct *task);
 extern void perf_event_delayed_put(struct task_struct *task);
-extern struct file *perf_event_get(unsigned int fd);
+extern struct perf_event *perf_event_get(unsigned int fd);
 extern const struct perf_event_attr *perf_event_attrs(struct perf_event *event);
 extern void perf_event_print_debug(void);
 extern void perf_pmu_disable(struct pmu *pmu);
@@ -867,12 +853,6 @@ extern void perf_event_output(struct perf_event *event,
 				struct perf_sample_data *data,
 				struct pt_regs *regs);
 
-static inline bool
-is_default_overflow_handler(struct perf_event *event)
-{
-	return (event->overflow_handler == perf_event_output);
-}
-
 extern void
 perf_event_header__init_id(struct perf_event_header *header,
 			   struct perf_sample_data *data,
@@ -1004,25 +984,13 @@ extern void perf_event_fork(struct task_struct *tsk);
 /* Callchains */
 DECLARE_PER_CPU(struct perf_callchain_entry, perf_callchain_entry);
 
-extern void perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs);
-extern void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs);
-extern struct perf_callchain_entry *
-get_perf_callchain(struct pt_regs *regs, u32 init_nr, bool kernel, bool user,
-		   u32 max_stack, bool crosstask, bool add_mark);
-extern int get_callchain_buffers(int max_stack);
-extern void put_callchain_buffers(void);
+extern void perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs);
+extern void perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs);
 
-extern int sysctl_perf_event_max_stack;
-
-static inline int perf_callchain_store(struct perf_callchain_entry_ctx *ctx, u64 ip)
+static inline void perf_callchain_store(struct perf_callchain_entry *entry, u64 ip)
 {
-	struct perf_callchain_entry *entry = ctx->entry;
-	if (entry->nr < ctx->max_stack) {
+	if (entry->nr < PERF_MAX_STACK_DEPTH)
 		entry->ip[entry->nr++] = ip;
-		return 0;
-	} else {
-		return -1; /* no more room, stop walking the stack */
-	}
 }
 
 extern int sysctl_perf_event_paranoid;
@@ -1039,8 +1007,6 @@ extern int perf_cpu_time_max_percent_handler(struct ctl_table *table, int write,
 		void __user *buffer, size_t *lenp,
 		loff_t *ppos);
 
-int perf_event_max_stack_handler(struct ctl_table *table, int write,
-				 void __user *buffer, size_t *lenp, loff_t *ppos);
 
 static inline bool perf_paranoid_any(void)
 {
@@ -1063,7 +1029,7 @@ static inline bool perf_paranoid_kernel(void)
 }
 
 extern void perf_event_init(void);
-extern void perf_tp_event(u16 event_type, u64 count, void *record,
+extern void perf_tp_event(u64 addr, u64 count, void *record,
 			  int entry_size, struct pt_regs *regs,
 			  struct hlist_head *head, int rctx,
 			  struct task_struct *task);
@@ -1128,7 +1094,7 @@ static inline int perf_event_init_task(struct task_struct *child)	{ return 0; }
 static inline void perf_event_exit_task(struct task_struct *child)	{ }
 static inline void perf_event_free_task(struct task_struct *task)	{ }
 static inline void perf_event_delayed_put(struct task_struct *task)	{ }
-static inline struct file *perf_event_get(unsigned int fd)	{ return ERR_PTR(-EINVAL); }
+static inline struct perf_event *perf_event_get(unsigned int fd)	{ return ERR_PTR(-EINVAL); }
 static inline const struct perf_event_attr *perf_event_attrs(struct perf_event *event)
 {
 	return ERR_PTR(-EINVAL);
diff --git a/include/linux/proc_ns.h b/include/linux/proc_ns.h
index ca85a4348ffc..42dfc615dbf8 100644
--- a/include/linux/proc_ns.h
+++ b/include/linux/proc_ns.h
@@ -9,8 +9,6 @@
 struct pid_namespace;
 struct nsproxy;
 struct path;
-struct task_struct;
-struct inode;
 
 struct proc_ns_operations {
 	const char *name;
@@ -18,7 +16,6 @@ struct proc_ns_operations {
 	struct ns_common *(*get)(struct task_struct *task);
 	void (*put)(struct ns_common *ns);
 	int (*install)(struct nsproxy *nsproxy, struct ns_common *ns);
-	struct user_namespace *(*owner)(struct ns_common *ns);
 };
 
 extern const struct proc_ns_operations netns_operations;
@@ -27,7 +24,6 @@ extern const struct proc_ns_operations ipcns_operations;
 extern const struct proc_ns_operations pidns_operations;
 extern const struct proc_ns_operations userns_operations;
 extern const struct proc_ns_operations mntns_operations;
-extern const struct proc_ns_operations cgroupns_operations;
 
 /*
  * We always define these enumerators
@@ -38,7 +34,6 @@ enum {
 	PROC_UTS_INIT_INO	= 0xEFFFFFFEU,
 	PROC_USER_INIT_INO	= 0xEFFFFFFDU,
 	PROC_PID_INIT_INO	= 0xEFFFFFFCU,
-	PROC_CGROUP_INIT_INO	= 0xEFFFFFFBU,
 };
 
 #ifdef CONFIG_PROC_FS
diff --git a/include/linux/rculist_nulls.h b/include/linux/rculist_nulls.h
index 19bac77f81b1..f35dc0a1d6eb 100644
--- a/include/linux/rculist_nulls.h
+++ b/include/linux/rculist_nulls.h
@@ -117,19 +117,5 @@ static inline void hlist_nulls_add_head_rcu(struct hlist_nulls_node *n,
 		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1; }); \
 		pos = rcu_dereference_raw(hlist_nulls_next_rcu(pos)))
 
-/**
- * hlist_nulls_for_each_entry_safe -
- *   iterate over list of given type safe against removal of list entry
- * @tpos:	the type * to use as a loop cursor.
- * @pos:	the &struct hlist_nulls_node to use as a loop cursor.
- * @head:	the head for your list.
- * @member:	the name of the hlist_nulls_node within the struct.
- */
-#define hlist_nulls_for_each_entry_safe(tpos, pos, head, member)		\
-	for (({barrier();}),							\
-	     pos = rcu_dereference_raw(hlist_nulls_first_rcu(head));		\
-		(!is_a_nulls(pos)) &&						\
-		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member);	\
-		   pos = rcu_dereference_raw(hlist_nulls_next_rcu(pos)); 1; });)
 #endif
 #endif
diff --git a/include/linux/security.h b/include/linux/security.h
index 11a06d0c9dad..96eacf534163 100644
--- a/include/linux/security.h
+++ b/include/linux/security.h
@@ -29,7 +29,6 @@
 #include <linux/string.h>
 #include <linux/mm.h>
 #include <linux/bio.h>
-#include <linux/bpf.h>
 
 struct linux_binprm;
 struct cred;
@@ -1624,50 +1623,6 @@ static inline void securityfs_remove(struct dentry *dentry)
 
 #endif
 
-#ifdef CONFIG_BPF_SYSCALL
-#ifdef CONFIG_SECURITY
-extern int security_bpf(int cmd, union bpf_attr *attr, unsigned int size);
-extern int security_bpf_map(struct bpf_map *map, fmode_t fmode);
-extern int security_bpf_prog(struct bpf_prog *prog);
-extern int security_bpf_map_alloc(struct bpf_map *map);
-extern void security_bpf_map_free(struct bpf_map *map);
-extern int security_bpf_prog_alloc(struct bpf_prog_aux *aux);
-extern void security_bpf_prog_free(struct bpf_prog_aux *aux);
-#else
-static inline int security_bpf(int cmd, union bpf_attr *attr,
-					     unsigned int size)
-{
-	return 0;
-}
-
-static inline int security_bpf_map(struct bpf_map *map, fmode_t fmode)
-{
-	return 0;
-}
-
-static inline int security_bpf_prog(struct bpf_prog *prog)
-{
-	return 0;
-}
-
-static inline int security_bpf_map_alloc(struct bpf_map *map)
-{
-	return 0;
-}
-
-static inline void security_bpf_map_free(struct bpf_map *map)
-{ }
-
-static inline int security_bpf_prog_alloc(struct bpf_prog_aux *aux)
-{
-	return 0;
-}
-
-static inline void security_bpf_prog_free(struct bpf_prog_aux *aux)
-{ }
-#endif /* CONFIG_SECURITY */
-#endif /* CONFIG_BPF_SYSCALL */
-
 #ifdef CONFIG_SECURITY
 
 static inline char *alloc_secdata(void)
diff --git a/include/linux/skbuff.h b/include/linux/skbuff.h
index 4c787097c96b..5436e629259d 100644
--- a/include/linux/skbuff.h
+++ b/include/linux/skbuff.h
@@ -37,7 +37,6 @@
 #include <net/flow_dissector.h>
 #include <linux/splice.h>
 #include <linux/in6.h>
-#include <linux/if_packet.h>
 #include <net/flow.h>
 
 /* A. Checksumming of received packets by device.
@@ -596,16 +595,6 @@ struct sk_buff {
 	 */
 	kmemcheck_bitfield_begin(flags1);
 	__u16			queue_mapping;
-
-/* if you move cloned around you also must adapt those constants */
-#ifdef __BIG_ENDIAN_BITFIELD
-#define CLONED_MASK	(1 << 7)
-#else
-#define CLONED_MASK	1
-#endif
-#define CLONED_OFFSET()		offsetof(struct sk_buff, __cloned_offset)
-
-	__u8			__cloned_offset[0];
 	__u8			cloned:1,
 				nohdr:1,
 				fclone:2,
@@ -810,15 +799,6 @@ static inline struct rtable *skb_rtable(const struct sk_buff *skb)
 	return (struct rtable *)skb_dst(skb);
 }
 
-/* For mangling skb->pkt_type from user space side from applications
- * such as nft, tc, etc, we only allow a conservative subset of
- * possible pkt_types to be set.
-*/
-static inline bool skb_pkt_type_ok(u32 ptype)
-{
-	return ptype <= PACKET_OTHERHOST;
-}
-
 void kfree_skb(struct sk_buff *skb);
 void kfree_skb_list(struct sk_buff *segs);
 void skb_tx_error(struct sk_buff *skb);
@@ -2220,7 +2200,7 @@ static inline int pskb_network_may_pull(struct sk_buff *skb, unsigned int len)
 
 int ___pskb_trim(struct sk_buff *skb, unsigned int len);
 
-static inline void __skb_set_length(struct sk_buff *skb, unsigned int len)
+static inline void __skb_trim(struct sk_buff *skb, unsigned int len)
 {
 	if (unlikely(skb_is_nonlinear(skb))) {
 		WARN_ON(1);
@@ -2230,11 +2210,6 @@ static inline void __skb_set_length(struct sk_buff *skb, unsigned int len)
 	skb_set_tail_pointer(skb, len);
 }
 
-static inline void __skb_trim(struct sk_buff *skb, unsigned int len)
-{
-	__skb_set_length(skb, len);
-}
-
 void skb_trim(struct sk_buff *skb, unsigned int len);
 
 static inline int __pskb_trim(struct sk_buff *skb, unsigned int len)
@@ -2265,20 +2240,6 @@ static inline void pskb_trim_unique(struct sk_buff *skb, unsigned int len)
 	BUG_ON(err);
 }
 
-static inline int __skb_grow(struct sk_buff *skb, unsigned int len)
-{
-	unsigned int diff = len - skb->len;
-
-	if (skb_tailroom(skb) < diff) {
-		int ret = pskb_expand_head(skb, 0, diff - skb_tailroom(skb),
-					   GFP_ATOMIC);
-		if (ret)
-			return ret;
-	}
-	__skb_set_length(skb, len);
-	return 0;
-}
-
 /**
  *	skb_orphan - orphan a buffer
  *	@skb: buffer to orphan
@@ -2789,18 +2750,6 @@ static inline int skb_linearize_cow(struct sk_buff *skb)
 	       __skb_linearize(skb) : 0;
 }
 
-static __always_inline void
-__skb_postpull_rcsum(struct sk_buff *skb, const void *start, unsigned int len,
-		     unsigned int off)
-{
-	if (skb->ip_summed == CHECKSUM_COMPLETE)
-		skb->csum = csum_block_sub(skb->csum,
-					   csum_partial(start, len, 0), off);
-	else if (skb->ip_summed == CHECKSUM_PARTIAL &&
-		 skb_checksum_start_offset(skb) < 0)
-		skb->ip_summed = CHECKSUM_NONE;
-}
-
 /**
  *	skb_postpull_rcsum - update checksum for received skb after pull
  *	@skb: buffer to update
@@ -2811,38 +2760,36 @@ __skb_postpull_rcsum(struct sk_buff *skb, const void *start, unsigned int len,
  *	update the CHECKSUM_COMPLETE checksum, or set ip_summed to
  *	CHECKSUM_NONE so that it can be recomputed from scratch.
  */
+
 static inline void skb_postpull_rcsum(struct sk_buff *skb,
 				      const void *start, unsigned int len)
-{
-	__skb_postpull_rcsum(skb, start, len, 0);
-}
-
-static __always_inline void
-__skb_postpush_rcsum(struct sk_buff *skb, const void *start, unsigned int len,
-		     unsigned int off)
 {
 	if (skb->ip_summed == CHECKSUM_COMPLETE)
-		skb->csum = csum_block_add(skb->csum,
-					   csum_partial(start, len, 0), off);
+		skb->csum = csum_sub(skb->csum, csum_partial(start, len, 0));
+	else if (skb->ip_summed == CHECKSUM_PARTIAL &&
+		 skb_checksum_start_offset(skb) < 0)
+		skb->ip_summed = CHECKSUM_NONE;
 }
 
-/**
- *	skb_postpush_rcsum - update checksum for received skb after push
- *	@skb: buffer to update
- *	@start: start of data after push
- *	@len: length of data pushed
- *
- *	After doing a push on a received packet, you need to call this to
- *	update the CHECKSUM_COMPLETE checksum.
- */
+unsigned char *skb_pull_rcsum(struct sk_buff *skb, unsigned int len);
+
 static inline void skb_postpush_rcsum(struct sk_buff *skb,
 				      const void *start, unsigned int len)
 {
-	__skb_postpush_rcsum(skb, start, len, 0);
+	/* For performing the reverse operation to skb_postpull_rcsum(),
+	 * we can instead of ...
+	 *
+	 *   skb->csum = csum_add(skb->csum, csum_partial(start, len, 0));
+	 *
+	 * ... just use this equivalent version here to save a few
+	 * instructions. Feeding csum of 0 in csum_partial() and later
+	 * on adding skb->csum is equivalent to feed skb->csum in the
+	 * first place.
+	 */
+	if (skb->ip_summed == CHECKSUM_COMPLETE)
+		skb->csum = csum_partial(start, len, skb->csum);
 }
 
-unsigned char *skb_pull_rcsum(struct sk_buff *skb, unsigned int len);
-
 /**
  *	skb_push_rcsum - push skb and update receive checksum
  *	@skb: buffer to update
@@ -2886,21 +2833,6 @@ static inline int pskb_trim_rcsum(struct sk_buff *skb, unsigned int len)
 #define skb_rb_next(skb)   rb_to_skb(rb_next(&(skb)->rbnode))
 #define skb_rb_prev(skb)   rb_to_skb(rb_prev(&(skb)->rbnode))
 
-static inline int __skb_trim_rcsum(struct sk_buff *skb, unsigned int len)
-{
-	if (skb->ip_summed == CHECKSUM_COMPLETE)
-		skb->ip_summed = CHECKSUM_NONE;
-	__skb_trim(skb, len);
-	return 0;
-}
-
-static inline int __skb_grow_rcsum(struct sk_buff *skb, unsigned int len)
-{
-	if (skb->ip_summed == CHECKSUM_COMPLETE)
-		skb->ip_summed = CHECKSUM_NONE;
-	return __skb_grow(skb, len);
-}
-
 #define skb_queue_walk(queue, skb) \
 		for (skb = (queue)->next;					\
 		     skb != (struct sk_buff *)(queue);				\
@@ -3669,13 +3601,6 @@ static inline bool skb_is_gso_v6(const struct sk_buff *skb)
 	return skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6;
 }
 
-static inline void skb_gso_reset(struct sk_buff *skb)
-{
-	skb_shinfo(skb)->gso_size = 0;
-	skb_shinfo(skb)->gso_segs = 0;
-	skb_shinfo(skb)->gso_type = 0;
-}
-
 void __skb_warn_lro_forwarding(const struct sk_buff *skb);
 
 static inline bool skb_warn_if_lro(const struct sk_buff *skb)
diff --git a/include/linux/sock_diag.h b/include/linux/sock_diag.h
index a2f8109bb215..a0596ca0e80a 100644
--- a/include/linux/sock_diag.h
+++ b/include/linux/sock_diag.h
@@ -24,7 +24,6 @@ void sock_diag_unregister(const struct sock_diag_handler *h);
 void sock_diag_register_inet_compat(int (*fn)(struct sk_buff *skb, struct nlmsghdr *nlh));
 void sock_diag_unregister_inet_compat(int (*fn)(struct sk_buff *skb, struct nlmsghdr *nlh));
 
-u64 sock_gen_cookie(struct sock *sk);
 int sock_diag_check_cookie(struct sock *sk, const __u32 *cookie);
 void sock_diag_save_cookie(struct sock *sk, __u32 *cookie);
 
diff --git a/include/linux/trace_events.h b/include/linux/trace_events.h
index 17fe42e836b4..2181ae5db42e 100644
--- a/include/linux/trace_events.h
+++ b/include/linux/trace_events.h
@@ -302,37 +302,14 @@ struct trace_event_call {
 #ifdef CONFIG_PERF_EVENTS
 	int				perf_refcount;
 	struct hlist_head __percpu	*perf_events;
-	struct bpf_prog_array __rcu	*prog_array;
+	struct bpf_prog			*prog;
+	struct perf_event		*bpf_prog_owner;
 
 	int	(*perf_perm)(struct trace_event_call *,
 			     struct perf_event *);
 #endif
 };
 
-#ifdef CONFIG_PERF_EVENTS
-static inline bool bpf_prog_array_valid(struct trace_event_call *call)
-{
-	/*
-	 * This inline function checks whether call->prog_array
-	 * is valid or not. The function is called in various places,
-	 * outside rcu_read_lock/unlock, as a heuristic to speed up execution.
-	 *
-	 * If this function returns true, and later call->prog_array
-	 * becomes false inside rcu_read_lock/unlock region,
-	 * we bail out then. If this function return false,
-	 * there is a risk that we might miss a few events if the checking
-	 * were delayed until inside rcu_read_lock/unlock region and
-	 * call->prog_array happened to become non-NULL then.
-	 *
-	 * Here, READ_ONCE() is used instead of rcu_access_pointer().
-	 * rcu_access_pointer() requires the actual definition of
-	 * "struct bpf_prog_array" while READ_ONCE() only needs
-	 * a declaration of the same type.
-	 */
-	return !!READ_ONCE(call->prog_array);
-}
-#endif
-
 static inline const char *
 trace_event_name(struct trace_event_call *call)
 {
@@ -585,23 +562,12 @@ event_trigger_unlock_commit_regs(struct trace_event_file *file,
 }
 
 #ifdef CONFIG_BPF_EVENTS
-unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx);
-int perf_event_attach_bpf_prog(struct perf_event *event, struct bpf_prog *prog);
-void perf_event_detach_bpf_prog(struct perf_event *event);
+unsigned int trace_call_bpf(struct bpf_prog *prog, void *ctx);
 #else
-static inline unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx)
+static inline unsigned int trace_call_bpf(struct bpf_prog *prog, void *ctx)
 {
 	return 1;
 }
-
-static inline int
-perf_event_attach_bpf_prog(struct perf_event *event, struct bpf_prog *prog)
-{
-	return -EOPNOTSUPP;
-}
-
-static inline void perf_event_detach_bpf_prog(struct perf_event *event) { }
-
 #endif
 
 enum {
@@ -620,7 +586,6 @@ extern int trace_define_field(struct trace_event_call *call, const char *type,
 			      int is_signed, int filter_type);
 extern int trace_add_event_call(struct trace_event_call *call);
 extern int trace_remove_event_call(struct trace_event_call *call);
-extern int trace_event_get_offsets(struct trace_event_call *call);
 
 #define is_signed_type(type)	(((type)(-1)) < (type)1)
 
@@ -657,22 +622,16 @@ extern void perf_trace_del(struct perf_event *event, int flags);
 extern int  ftrace_profile_set_filter(struct perf_event *event, int event_id,
 				     char *filter_str);
 extern void ftrace_profile_free_filter(struct perf_event *event);
-void perf_trace_buf_update(void *record, u16 type);
-void *perf_trace_buf_alloc(int size, struct pt_regs **regs, int *rctxp);
-
-void perf_trace_run_bpf_submit(void *raw_data, int size, int rctx,
-			       struct trace_event_call *call, u64 count,
-			       struct pt_regs *regs, struct hlist_head *head,
-			       struct task_struct *task);
+extern void *perf_trace_buf_prepare(int size, unsigned short type,
+				    struct pt_regs **regs, int *rctxp);
 
 static inline void
-perf_trace_buf_submit(void *raw_data, int size, int rctx, u16 type,
+perf_trace_buf_submit(void *raw_data, int size, int rctx, u64 addr,
 		       u64 count, struct pt_regs *regs, void *head,
 		       struct task_struct *task)
 {
-	perf_tp_event(type, count, raw_data, size, regs, head, rctx, task);
+	perf_tp_event(addr, count, raw_data, size, regs, head, rctx, task);
 }
-
 #endif
 
 #endif /* _LINUX_TRACE_EVENT_H */
diff --git a/include/linux/user_namespace.h b/include/linux/user_namespace.h
index 190cf0760815..8297e5b341d8 100644
--- a/include/linux/user_namespace.h
+++ b/include/linux/user_namespace.h
@@ -72,9 +72,6 @@ extern ssize_t proc_projid_map_write(struct file *, const char __user *, size_t,
 extern ssize_t proc_setgroups_write(struct file *, const char __user *, size_t, loff_t *);
 extern int proc_setgroups_show(struct seq_file *m, void *v);
 extern bool userns_may_setgroups(const struct user_namespace *ns);
-extern bool current_in_userns(const struct user_namespace *target_ns);
-
-struct ns_common *ns_get_owner(struct ns_common *ns);
 #else
 
 static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
@@ -103,16 +100,6 @@ static inline bool userns_may_setgroups(const struct user_namespace *ns)
 {
 	return true;
 }
-
-static inline bool current_in_userns(const struct user_namespace *target_ns)
-{
-	return true;
-}
-
-static inline struct ns_common *ns_get_owner(struct ns_common *ns)
-{
-	return ERR_PTR(-EPERM);
-}
 #endif
 
 #endif /* _LINUX_USER_H */
diff --git a/include/net/addrconf.h b/include/net/addrconf.h
index 07aed691fe00..23003261a5c4 100644
--- a/include/net/addrconf.h
+++ b/include/net/addrconf.h
@@ -90,8 +90,7 @@ int __ipv6_get_lladdr(struct inet6_dev *idev, struct in6_addr *addr,
 		      u32 banned_flags);
 int ipv6_get_lladdr(struct net_device *dev, struct in6_addr *addr,
 		    u32 banned_flags);
-int ipv6_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2,
-			 bool match_wildcard);
+int ipv6_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2);
 void addrconf_join_solict(struct net_device *dev, const struct in6_addr *addr);
 void addrconf_leave_solict(struct inet6_dev *idev, const struct in6_addr *addr);
 
diff --git a/include/net/checksum.h b/include/net/checksum.h
index c5b95e8fcd16..9fcaedf994ee 100644
--- a/include/net/checksum.h
+++ b/include/net/checksum.h
@@ -120,11 +120,6 @@ static inline __wsum csum_partial_ext(const void *buff, int len, __wsum sum)
 
 #define CSUM_MANGLED_0 ((__force __sum16)0xffff)
 
-static inline void csum_replace_by_diff(__sum16 *sum, __wsum diff)
-{
-	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
-}
-
 static inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
 {
 	__wsum tmp = csum_sub(~csum_unfold(*sum), (__force __wsum)from);
diff --git a/include/net/cls_cgroup.h b/include/net/cls_cgroup.h
index c0a92e2c286d..ccd6d8bffa4d 100644
--- a/include/net/cls_cgroup.h
+++ b/include/net/cls_cgroup.h
@@ -41,12 +41,13 @@ static inline u32 task_cls_classid(struct task_struct *p)
 	return classid;
 }
 
-static inline void sock_update_classid(struct sock_cgroup_data *skcd)
+static inline void sock_update_classid(struct sock *sk)
 {
 	u32 classid;
 
 	classid = task_cls_classid(current);
-	sock_cgroup_set_classid(skcd, classid);
+	if (classid != sk->sk_classid)
+		sk->sk_classid = classid;
 }
 
 static inline u32 task_get_classid(const struct sk_buff *skb)
@@ -63,17 +64,17 @@ static inline u32 task_get_classid(const struct sk_buff *skb)
 	 * softirqs always disables bh.
 	 */
 	if (in_serving_softirq()) {
-		/* If there is an sock_cgroup_classid we'll use that. */
+		/* If there is an sk_classid we'll use that. */
 		if (!skb->sk)
 			return 0;
 
-		classid = sock_cgroup_classid(&skb->sk->sk_cgrp_data);
+		classid = skb->sk->sk_classid;
 	}
 
 	return classid;
 }
 #else /* !CONFIG_CGROUP_NET_CLASSID */
-static inline void sock_update_classid(struct sock_cgroup_data *skcd)
+static inline void sock_update_classid(struct sock *sk)
 {
 }
 
diff --git a/include/net/dst.h b/include/net/dst.h
index 1daa9e2a1b46..dc1f26da3c61 100644
--- a/include/net/dst.h
+++ b/include/net/dst.h
@@ -404,18 +404,6 @@ static inline void skb_tunnel_rx(struct sk_buff *skb, struct net_device *dev,
 	__skb_tunnel_rx(skb, dev, net);
 }
 
-static inline u32 dst_tclassid(const struct sk_buff *skb)
-{
-#ifdef CONFIG_IP_ROUTE_CLASSID
-	const struct dst_entry *dst;
-
-	dst = skb_dst(skb);
-	if (dst)
-		return dst->tclassid;
-#endif
-	return 0;
-}
-
 int dst_discard_out(struct net *net, struct sock *sk, struct sk_buff *skb);
 static inline int dst_discard(struct sk_buff *skb)
 {
diff --git a/include/net/dst_metadata.h b/include/net/dst_metadata.h
index b55d2e854bf3..4cee368cb91c 100644
--- a/include/net/dst_metadata.h
+++ b/include/net/dst_metadata.h
@@ -127,7 +127,7 @@ static inline struct metadata_dst *ip_tun_rx_dst(struct sk_buff *skb,
 
 	ip_tunnel_key_init(&tun_dst->u.tun_info.key,
 			   iph->saddr, iph->daddr, iph->tos, iph->ttl,
-			   0, 0, 0, tunnel_id, flags);
+			   0, 0, tunnel_id, flags);
 	return tun_dst;
 }
 
@@ -153,11 +153,8 @@ static inline struct metadata_dst *ipv6_tun_rx_dst(struct sk_buff *skb,
 
 	info->key.u.ipv6.src = ip6h->saddr;
 	info->key.u.ipv6.dst = ip6h->daddr;
-
 	info->key.tos = ipv6_get_dsfield(ip6h);
 	info->key.ttl = ip6h->hop_limit;
-	info->key.label = ip6_flowlabel(ip6h);
-
 	return tun_dst;
 }
 
diff --git a/include/net/ip_tunnels.h b/include/net/ip_tunnels.h
index 3d4fb0e2a3bf..74bc08d82e14 100644
--- a/include/net/ip_tunnels.h
+++ b/include/net/ip_tunnels.h
@@ -7,8 +7,6 @@
 #include <linux/socket.h>
 #include <linux/types.h>
 #include <linux/u64_stats_sync.h>
-#include <linux/bitops.h>
-
 #include <net/dsfield.h>
 #include <net/gro_cells.h>
 #include <net/inet_ecn.h>
@@ -50,7 +48,6 @@ struct ip_tunnel_key {
 	__be16			tun_flags;
 	u8			tos;		/* TOS for IPv4, TC for IPv6 */
 	u8			ttl;		/* TTL for IPv4, HL for IPv6 */
-	__be32			label;		/* Flow Label for IPv6 */
 	__be16			tp_src;
 	__be16			tp_dst;
 };
@@ -59,11 +56,6 @@ struct ip_tunnel_key {
 #define IP_TUNNEL_INFO_TX	0x01	/* represents tx tunnel parameters */
 #define IP_TUNNEL_INFO_IPV6	0x02	/* key contains IPv6 addresses */
 
-/* Maximum tunnel options length. */
-#define IP_TUNNEL_OPTS_MAX					\
-	GENMASK((FIELD_SIZEOF(struct ip_tunnel_info,		\
-			      options_len) * BITS_PER_BYTE) - 1, 0)
-
 struct ip_tunnel_info {
 	struct ip_tunnel_key	key;
 	u8			options_len;
@@ -185,7 +177,7 @@ int ip_tunnel_encap_del_ops(const struct ip_tunnel_encap_ops *op,
 
 static inline void ip_tunnel_key_init(struct ip_tunnel_key *key,
 				      __be32 saddr, __be32 daddr,
-				      u8 tos, u8 ttl, __be32 label,
+				      u8 tos, u8 ttl,
 				      __be16 tp_src, __be16 tp_dst,
 				      __be64 tun_id, __be16 tun_flags)
 {
@@ -196,7 +188,6 @@ static inline void ip_tunnel_key_init(struct ip_tunnel_key *key,
 	       0, IP_TUNNEL_KEY_IPV4_PAD_LEN);
 	key->tos = tos;
 	key->ttl = ttl;
-	key->label = label;
 	key->tun_flags = tun_flags;
 
 	/* For the tunnel types on the top of IPsec, the tp_src and tp_dst of
diff --git a/include/net/netprio_cgroup.h b/include/net/netprio_cgroup.h
index 604190596cde..f2a9597ff53c 100644
--- a/include/net/netprio_cgroup.h
+++ b/include/net/netprio_cgroup.h
@@ -25,6 +25,8 @@ struct netprio_map {
 	u32 priomap[];
 };
 
+void sock_update_netprioidx(struct sock *sk);
+
 static inline u32 task_netprioidx(struct task_struct *p)
 {
 	struct cgroup_subsys_state *css;
@@ -36,25 +38,13 @@ static inline u32 task_netprioidx(struct task_struct *p)
 	rcu_read_unlock();
 	return idx;
 }
-
-static inline void sock_update_netprioidx(struct sock_cgroup_data *skcd)
-{
-	if (in_interrupt())
-		return;
-
-	sock_cgroup_set_prioidx(skcd, task_netprioidx(current));
-}
-
 #else /* !CONFIG_CGROUP_NET_PRIO */
-
 static inline u32 task_netprioidx(struct task_struct *p)
 {
 	return 0;
 }
 
-static inline void sock_update_netprioidx(struct sock_cgroup_data *skcd)
-{
-}
+#define sock_update_netprioidx(sk)
 
 #endif /* CONFIG_CGROUP_NET_PRIO */
 #endif  /* _NET_CLS_CGROUP_H */
diff --git a/include/net/sock.h b/include/net/sock.h
index cde6bd01fc4c..788a26c1202f 100644
--- a/include/net/sock.h
+++ b/include/net/sock.h
@@ -58,7 +58,6 @@
 #include <linux/memcontrol.h>
 #include <linux/static_key.h>
 #include <linux/sched.h>
-#include <linux/cgroup-defs.h>
 
 #include <linux/filter.h>
 #include <linux/rculist_nulls.h>
@@ -288,6 +287,7 @@ struct cg_proto;
   *	@sk_ack_backlog: current listen backlog
   *	@sk_max_ack_backlog: listen backlog set in listen()
   *	@sk_priority: %SO_PRIORITY setting
+  *	@sk_cgrp_prioidx: socket group's priority map index
   *	@sk_type: socket type (%SOCK_STREAM, etc)
   *	@sk_protocol: which protocol this socket belongs in this network family
   *	@sk_peer_pid: &struct pid for this socket's peer
@@ -309,7 +309,7 @@ struct cg_proto;
   *	@sk_send_head: front of stuff to transmit
   *	@sk_security: used by security modules
   *	@sk_mark: generic packet mark
-  *	@sk_cgrp_data: cgroup data for this cgroup
+  *	@sk_classid: this socket's cgroup classid
   *	@sk_cgrp: this socket's cgroup-specific proto data
   *	@sk_write_pending: a write to stream socket waits to start
   *	@sk_state_change: callback to indicate change in the state of the sock
@@ -318,7 +318,6 @@ struct cg_proto;
   *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
   *	@sk_backlog_rcv: callback to process the backlog
   *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
-  *	@sk_reuseport_cb: reuseport group container
  */
 struct sock {
 	/*
@@ -431,7 +430,6 @@ struct sock {
 	__u32			sk_cgrp_prioidx;
 #endif
 	spinlock_t		sk_peer_lock;
-	__u32			sk_mark;
 	struct pid		*sk_peer_pid;
 	const struct cred	*sk_peer_cred;
 
@@ -453,8 +451,11 @@ struct sock {
 #ifdef CONFIG_SECURITY
 	void			*sk_security;
 #endif
+	__u32			sk_mark;
 	kuid_t			sk_uid;
-	struct sock_cgroup_data	sk_cgrp_data;
+#ifdef CONFIG_CGROUP_NET_CLASSID
+	u32			sk_classid;
+#endif
 	struct cg_proto		*sk_cgrp;
 	void			(*sk_state_change)(struct sock *sk);
 	void			(*sk_data_ready)(struct sock *sk);
@@ -464,7 +465,6 @@ struct sock {
 						  struct sk_buff *skb);
 	void                    (*sk_destruct)(struct sock *sk);
 	struct rcu_head		sk_rcu;
-	struct sock_reuseport __rcu	*sk_reuseport_cb;
 };
 
 #define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))
@@ -1149,16 +1149,6 @@ static inline bool sk_stream_is_writeable(const struct sock *sk)
 	       sk_stream_memory_free(sk);
 }
 
-static inline int sk_under_cgroup_hierarchy(struct sock *sk,
-					    struct cgroup *ancestor)
-{
-#ifdef CONFIG_SOCK_CGROUP_DATA
-	return cgroup_is_descendant(sock_cgroup_ptr(&sk->sk_cgrp_data),
-				    ancestor);
-#else
-	return -ENOTSUPP;
-#endif
-}
 
 static inline bool sk_has_memory_pressure(const struct sock *sk)
 {
diff --git a/include/net/sock_reuseport.h b/include/net/sock_reuseport.h
deleted file mode 100644
index 7dda3d7adba8..000000000000
--- a/include/net/sock_reuseport.h
+++ /dev/null
@@ -1,28 +0,0 @@
-#ifndef _SOCK_REUSEPORT_H
-#define _SOCK_REUSEPORT_H
-
-#include <linux/filter.h>
-#include <linux/skbuff.h>
-#include <linux/types.h>
-#include <net/sock.h>
-
-struct sock_reuseport {
-	struct rcu_head		rcu;
-
-	u16			max_socks;	/* length of socks */
-	u16			num_socks;	/* elements in socks */
-	struct bpf_prog __rcu	*prog;		/* optional BPF sock selector */
-	struct sock		*socks[0];	/* array of sock pointers */
-};
-
-extern int reuseport_alloc(struct sock *sk);
-extern int reuseport_add_sock(struct sock *sk, const struct sock *sk2);
-extern void reuseport_detach_sock(struct sock *sk);
-extern struct sock *reuseport_select_sock(struct sock *sk,
-					  u32 hash,
-					  struct sk_buff *skb,
-					  int hdr_len);
-extern struct bpf_prog *reuseport_attach_prog(struct sock *sk,
-					      struct bpf_prog *prog);
-
-#endif  /* _SOCK_REUSEPORT_H */
diff --git a/include/net/udp.h b/include/net/udp.h
index 13bd641be453..e57f50258cda 100644
--- a/include/net/udp.h
+++ b/include/net/udp.h
@@ -191,7 +191,7 @@ static inline void udp_lib_close(struct sock *sk, long timeout)
 }
 
 int udp_lib_get_port(struct sock *sk, unsigned short snum,
-		     int (*)(const struct sock *, const struct sock *, bool),
+		     int (*)(const struct sock *, const struct sock *),
 		     unsigned int hash2_nulladdr);
 
 u32 udp_flow_hashrnd(void);
@@ -259,7 +259,7 @@ struct sock *udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
 			     __be32 daddr, __be16 dport, int dif);
 struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
 			       __be32 daddr, __be16 dport, int dif,
-			       struct udp_table *tbl, struct sk_buff *skb);
+			       struct udp_table *tbl);
 struct sock *udp6_lib_lookup(struct net *net,
 			     const struct in6_addr *saddr, __be16 sport,
 			     const struct in6_addr *daddr, __be16 dport,
@@ -267,8 +267,7 @@ struct sock *udp6_lib_lookup(struct net *net,
 struct sock *__udp6_lib_lookup(struct net *net,
 			       const struct in6_addr *saddr, __be16 sport,
 			       const struct in6_addr *daddr, __be16 dport,
-			       int dif, struct udp_table *tbl,
-			       struct sk_buff *skb);
+			       int dif, struct udp_table *tbl);
 
 /*
  * 	SNMP statistics for UDP and UDP-Lite
diff --git a/include/net/udp_tunnel.h b/include/net/udp_tunnel.h
index c020d3389a21..cb2f89f20f5c 100644
--- a/include/net/udp_tunnel.h
+++ b/include/net/udp_tunnel.h
@@ -88,8 +88,8 @@ int udp_tunnel6_xmit_skb(struct dst_entry *dst, struct sock *sk,
 			 struct sk_buff *skb,
 			 struct net_device *dev, struct in6_addr *saddr,
 			 struct in6_addr *daddr,
-			 __u8 prio, __u8 ttl, __be32 label,
-			 __be16 src_port, __be16 dst_port, bool nocheck);
+			 __u8 prio, __u8 ttl, __be16 src_port,
+			 __be16 dst_port, bool nocheck);
 #endif
 
 void udp_tunnel_sock_release(struct socket *sock);
diff --git a/include/trace/events/cgroup.h b/include/trace/events/cgroup.h
deleted file mode 100644
index ab68640a18d0..000000000000
--- a/include/trace/events/cgroup.h
+++ /dev/null
@@ -1,163 +0,0 @@
-#undef TRACE_SYSTEM
-#define TRACE_SYSTEM cgroup
-
-#if !defined(_TRACE_CGROUP_H) || defined(TRACE_HEADER_MULTI_READ)
-#define _TRACE_CGROUP_H
-
-#include <linux/cgroup.h>
-#include <linux/tracepoint.h>
-
-DECLARE_EVENT_CLASS(cgroup_root,
-
-	TP_PROTO(struct cgroup_root *root),
-
-	TP_ARGS(root),
-
-	TP_STRUCT__entry(
-		__field(	int,		root			)
-		__field(	u16,		ss_mask			)
-		__string(	name,		root->name		)
-	),
-
-	TP_fast_assign(
-		__entry->root = root->hierarchy_id;
-		__entry->ss_mask = root->subsys_mask;
-		__assign_str(name, root->name);
-	),
-
-	TP_printk("root=%d ss_mask=%#x name=%s",
-		  __entry->root, __entry->ss_mask, __get_str(name))
-);
-
-DEFINE_EVENT(cgroup_root, cgroup_setup_root,
-
-	TP_PROTO(struct cgroup_root *root),
-
-	TP_ARGS(root)
-);
-
-DEFINE_EVENT(cgroup_root, cgroup_destroy_root,
-
-	TP_PROTO(struct cgroup_root *root),
-
-	TP_ARGS(root)
-);
-
-DEFINE_EVENT(cgroup_root, cgroup_remount,
-
-	TP_PROTO(struct cgroup_root *root),
-
-	TP_ARGS(root)
-);
-
-DECLARE_EVENT_CLASS(cgroup,
-
-	TP_PROTO(struct cgroup *cgrp),
-
-	TP_ARGS(cgrp),
-
-	TP_STRUCT__entry(
-		__field(	int,		root			)
-		__field(	int,		id			)
-		__field(	int,		level			)
-		__dynamic_array(char,		path,
-				cgrp->kn ? cgroup_path(cgrp, NULL, 0) + 1
-					 : strlen("(null)"))
-	),
-
-	TP_fast_assign(
-		__entry->root = cgrp->root->hierarchy_id;
-		__entry->id = cgrp->id;
-		__entry->level = cgrp->level;
-		if (cgrp->kn)
-			cgroup_path(cgrp, __get_dynamic_array(path),
-				    __get_dynamic_array_len(path));
-		else
-			__assign_str(path, "(null)");
-	),
-
-	TP_printk("root=%d id=%d level=%d path=%s",
-		  __entry->root, __entry->id, __entry->level, __get_str(path))
-);
-
-DEFINE_EVENT(cgroup, cgroup_mkdir,
-
-	TP_PROTO(struct cgroup *cgroup),
-
-	TP_ARGS(cgroup)
-);
-
-DEFINE_EVENT(cgroup, cgroup_rmdir,
-
-	TP_PROTO(struct cgroup *cgroup),
-
-	TP_ARGS(cgroup)
-);
-
-DEFINE_EVENT(cgroup, cgroup_release,
-
-	TP_PROTO(struct cgroup *cgroup),
-
-	TP_ARGS(cgroup)
-);
-
-DEFINE_EVENT(cgroup, cgroup_rename,
-
-	TP_PROTO(struct cgroup *cgroup),
-
-	TP_ARGS(cgroup)
-);
-
-DECLARE_EVENT_CLASS(cgroup_migrate,
-
-	TP_PROTO(struct cgroup *dst_cgrp, struct task_struct *task, bool threadgroup),
-
-	TP_ARGS(dst_cgrp, task, threadgroup),
-
-	TP_STRUCT__entry(
-		__field(	int,		dst_root		)
-		__field(	int,		dst_id			)
-		__field(	int,		dst_level		)
-		__dynamic_array(char,		dst_path,
-				dst_cgrp->kn ? cgroup_path(dst_cgrp, NULL, 0) + 1
-					     : strlen("(null)"))
-		__field(	int,		pid			)
-		__string(	comm,		task->comm		)
-	),
-
-	TP_fast_assign(
-		__entry->dst_root = dst_cgrp->root->hierarchy_id;
-		__entry->dst_id = dst_cgrp->id;
-		__entry->dst_level = dst_cgrp->level;
-		if (dst_cgrp->kn)
-			cgroup_path(dst_cgrp, __get_dynamic_array(dst_path),
-				    __get_dynamic_array_len(dst_path));
-		else
-			__assign_str(dst_path, "(null)");
-		__entry->pid = task->pid;
-		__assign_str(comm, task->comm);
-	),
-
-	TP_printk("dst_root=%d dst_id=%d dst_level=%d dst_path=%s pid=%d comm=%s",
-		  __entry->dst_root, __entry->dst_id, __entry->dst_level,
-		  __get_str(dst_path), __entry->pid, __get_str(comm))
-);
-
-DEFINE_EVENT(cgroup_migrate, cgroup_attach_task,
-
-	TP_PROTO(struct cgroup *dst_cgrp, struct task_struct *task, bool threadgroup),
-
-	TP_ARGS(dst_cgrp, task, threadgroup)
-);
-
-DEFINE_EVENT(cgroup_migrate, cgroup_transfer_tasks,
-
-	TP_PROTO(struct cgroup *dst_cgrp, struct task_struct *task, bool threadgroup),
-
-	TP_ARGS(dst_cgrp, task, threadgroup)
-);
-
-#endif /* _TRACE_CGROUP_H */
-
-/* This part must be outside protection */
-#include <trace/define_trace.h>
diff --git a/include/trace/perf.h b/include/trace/perf.h
index 31b8d276a993..26486fcd74ce 100644
--- a/include/trace/perf.h
+++ b/include/trace/perf.h
@@ -20,6 +20,9 @@
 #undef __get_bitmask
 #define __get_bitmask(field) (char *)__get_dynamic_array(field)
 
+#undef __perf_addr
+#define __perf_addr(a)	(__addr = (a))
+
 #undef __perf_count
 #define __perf_count(c)	(__count = (c))
 
@@ -35,7 +38,7 @@ perf_trace_##call(void *__data, proto)					\
 	struct trace_event_data_offsets_##call __maybe_unused __data_offsets;\
 	struct trace_event_raw_##call *entry;				\
 	struct pt_regs *__regs;						\
-	u64 __count = 1;						\
+	u64 __addr = 0, __count = 1;					\
 	struct task_struct *__task = NULL;				\
 	struct hlist_head *head;					\
 	int __entry_size;						\
@@ -45,16 +48,16 @@ perf_trace_##call(void *__data, proto)					\
 	__data_size = trace_event_get_offsets_##call(&__data_offsets, args); \
 									\
 	head = this_cpu_ptr(event_call->perf_events);			\
-	if (!bpf_prog_array_valid(event_call) &&			\
-	    __builtin_constant_p(!__task) && !__task &&			\
-	    hlist_empty(head))						\
+	if (__builtin_constant_p(!__task) && !__task &&			\
+				hlist_empty(head))			\
 		return;							\
 									\
 	__entry_size = ALIGN(__data_size + sizeof(*entry) + sizeof(u32),\
 			     sizeof(u64));				\
 	__entry_size -= sizeof(u32);					\
 									\
-	entry = perf_trace_buf_alloc(__entry_size, &__regs, &rctx);	\
+	entry = perf_trace_buf_prepare(__entry_size,			\
+			event_call->event.type, &__regs, &rctx);	\
 	if (!entry)							\
 		return;							\
 									\
@@ -64,9 +67,8 @@ perf_trace_##call(void *__data, proto)					\
 									\
 	{ assign; }							\
 									\
-	perf_trace_run_bpf_submit(entry, __entry_size, rctx,		\
-				  event_call, __count, __regs,		\
-				  head, __task);			\
+	perf_trace_buf_submit(entry, __entry_size, rctx, __addr,	\
+		__count, __regs, head, __task);				\
 }
 
 /*
diff --git a/include/trace/trace_events.h b/include/trace/trace_events.h
index f7d93efd5c8f..af0cb7907922 100644
--- a/include/trace/trace_events.h
+++ b/include/trace/trace_events.h
@@ -646,6 +646,9 @@ static inline notrace int trace_event_get_offsets_##call(		\
 #undef TP_fast_assign
 #define TP_fast_assign(args...) args
 
+#undef __perf_addr
+#define __perf_addr(a)	(a)
+
 #undef __perf_count
 #define __perf_count(c)	(c)
 
diff --git a/include/uapi/asm-generic/socket.h b/include/uapi/asm-generic/socket.h
index fb8a41668382..5c15c2a5c123 100644
--- a/include/uapi/asm-generic/socket.h
+++ b/include/uapi/asm-generic/socket.h
@@ -87,7 +87,4 @@
 #define SO_ATTACH_BPF		50
 #define SO_DETACH_BPF		SO_DETACH_FILTER
 
-#define SO_ATTACH_REUSEPORT_CBPF	51
-#define SO_ATTACH_REUSEPORT_EBPF	52
-
 #endif /* __ASM_GENERIC_SOCKET_H */
diff --git a/include/uapi/linux/bpf.h b/include/uapi/linux/bpf.h
index 5bac307880a6..9ea2d22fa2cb 100644
--- a/include/uapi/linux/bpf.h
+++ b/include/uapi/linux/bpf.h
@@ -73,8 +73,6 @@ enum bpf_cmd {
 	BPF_PROG_LOAD,
 	BPF_OBJ_PIN,
 	BPF_OBJ_GET,
-	BPF_PROG_ATTACH,
-	BPF_PROG_DETACH,
 };
 
 enum bpf_map_type {
@@ -83,10 +81,6 @@ enum bpf_map_type {
 	BPF_MAP_TYPE_ARRAY,
 	BPF_MAP_TYPE_PROG_ARRAY,
 	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
-	BPF_MAP_TYPE_PERCPU_HASH,
-	BPF_MAP_TYPE_PERCPU_ARRAY,
-	BPF_MAP_TYPE_STACK_TRACE,
-	BPF_MAP_TYPE_CGROUP_ARRAY,
 };
 
 enum bpf_prog_type {
@@ -95,62 +89,8 @@ enum bpf_prog_type {
 	BPF_PROG_TYPE_KPROBE,
 	BPF_PROG_TYPE_SCHED_CLS,
 	BPF_PROG_TYPE_SCHED_ACT,
-	BPF_PROG_TYPE_TRACEPOINT,
-	BPF_PROG_TYPE_XDP,
-	BPF_PROG_TYPE_PERF_EVENT,
-	BPF_PROG_TYPE_CGROUP_SKB,
 };
 
-enum bpf_attach_type {
-	BPF_CGROUP_INET_INGRESS,
-	BPF_CGROUP_INET_EGRESS,
-	__MAX_BPF_ATTACH_TYPE
-};
-
-#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
-
-/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
- *
- * NONE(default): No further bpf programs allowed in the subtree.
- *
- * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
- * the program in this cgroup yields to sub-cgroup program.
- *
- * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
- * that cgroup program gets run in addition to the program in this cgroup.
- *
- * Only one program is allowed to be attached to a cgroup with
- * NONE or BPF_F_ALLOW_OVERRIDE flag.
- * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
- * release old program and attach the new one. Attach flags has to match.
- *
- * Multiple programs are allowed to be attached to a cgroup with
- * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
- * (those that were attached first, run first)
- * The programs of sub-cgroup are executed first, then programs of
- * this cgroup and then programs of parent cgroup.
- * When children program makes decision (like picking TCP CA or sock bind)
- * parent program has a chance to override it.
- *
- * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
- * A cgroup with NONE doesn't allow any programs in sub-cgroups.
- * Ex1:
- * cgrp1 (MULTI progs A, B) ->
- *    cgrp2 (OVERRIDE prog C) ->
- *      cgrp3 (MULTI prog D) ->
- *        cgrp4 (OVERRIDE prog E) ->
- *          cgrp5 (NONE prog F)
- * the event in cgrp5 triggers execution of F,D,A,B in that order.
- * if prog F is detached, the execution is E,D,A,B
- * if prog F and D are detached, the execution is E,A,B
- * if prog F, E and D are detached, the execution is C,A,B
- *
- * All eligible programs are executed regardless of return code from
- * earlier programs.
- */
-#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
-#define BPF_F_ALLOW_MULTI	(1U << 1)
-
 #define BPF_PSEUDO_MAP_FD	1
 
 /* flags for BPF_MAP_UPDATE_ELEM command */
@@ -158,19 +98,12 @@ enum bpf_attach_type {
 #define BPF_NOEXIST	1 /* create new element if it didn't exist */
 #define BPF_EXIST	2 /* update existing element */
 
-#define BPF_F_NO_PREALLOC	(1U << 0)
-
-/* Flags for accessing BPF object */
-#define BPF_F_RDONLY		(1U << 3)
-#define BPF_F_WRONLY		(1U << 4)
-
 union bpf_attr {
 	struct { /* anonymous struct used by BPF_MAP_CREATE command */
 		__u32	map_type;	/* one of enum bpf_map_type */
 		__u32	key_size;	/* size of key in bytes */
 		__u32	value_size;	/* size of value in bytes */
 		__u32	max_entries;	/* max number of entries in a map */
-		__u32	map_flags;	/* prealloc or not */
 	};
 
 	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
@@ -197,14 +130,6 @@ union bpf_attr {
 	struct { /* anonymous struct used by BPF_OBJ_* commands */
 		__aligned_u64	pathname;
 		__u32		bpf_fd;
-		__u32		file_flags;
-	};
-
-	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
-		__u32		target_fd;	/* container object to attach to */
-		__u32		attach_bpf_fd;	/* eBPF program to attach */
-		__u32		attach_type;
-		__u32		attach_flags;
 	};
 } __attribute__((aligned(8)));
 
@@ -344,254 +269,9 @@ enum bpf_func_id {
 	 * Return: 0 on success
 	 */
 	BPF_FUNC_perf_event_output,
-	BPF_FUNC_skb_load_bytes,
-
-	/**
-	 * bpf_get_stackid(ctx, map, flags) - walk user or kernel stack and return id
-	 * @ctx: struct pt_regs*
-	 * @map: pointer to stack_trace map
-	 * @flags: bits 0-7 - numer of stack frames to skip
-	 *         bit 8 - collect user stack instead of kernel
-	 *         bit 9 - compare stacks by hash only
-	 *         bit 10 - if two different stacks hash into the same stackid
-	 *                  discard old
-	 *         other bits - reserved
-	 * Return: >= 0 stackid on success or negative error
-	 */
-	BPF_FUNC_get_stackid,
-
-	/**
-	 * bpf_csum_diff(from, from_size, to, to_size, seed) - calculate csum diff
-	 * @from: raw from buffer
-	 * @from_size: length of from buffer
-	 * @to: raw to buffer
-	 * @to_size: length of to buffer
-	 * @seed: optional seed
-	 * Return: csum result
-	 */
-	BPF_FUNC_csum_diff,
-
-	/**
-	 * bpf_skb_[gs]et_tunnel_opt(skb, opt, size)
-	 * retrieve or populate tunnel options metadata
-	 * @skb: pointer to skb
-	 * @opt: pointer to raw tunnel option data
-	 * @size: size of @opt
-	 * Return: 0 on success for set, option size for get
-	 */
-	BPF_FUNC_skb_get_tunnel_opt,
-	BPF_FUNC_skb_set_tunnel_opt,
-
-	/**
-	 * bpf_skb_change_proto(skb, proto, flags)
-	 * Change protocol of the skb. Currently supported is
-	 * v4 -> v6, v6 -> v4 transitions. The helper will also
-	 * resize the skb. eBPF program is expected to fill the
-	 * new headers via skb_store_bytes and lX_csum_replace.
-	 * @skb: pointer to skb
-	 * @proto: new skb->protocol type
-	 * @flags: reserved
-	 * Return: 0 on success or negative error
-	 */
-	BPF_FUNC_skb_change_proto,
-
-	/**
-	 * bpf_skb_change_type(skb, type)
-	 * Change packet type of skb.
-	 * @skb: pointer to skb
-	 * @type: new skb->pkt_type type
-	 * Return: 0 on success or negative error
-	 */
-	BPF_FUNC_skb_change_type,
-
-	/**
-	 * bpf_skb_under_cgroup(skb, map, index) - Check cgroup2 membership of skb
-	 * @skb: pointer to skb
-	 * @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
-	 * @index: index of the cgroup in the bpf_map
-	 * Return:
-	 *   == 0 skb failed the cgroup2 descendant test
-	 *   == 1 skb succeeded the cgroup2 descendant test
-	 *    < 0 error
-	 */
-	BPF_FUNC_skb_under_cgroup,
-
-	/**
-	 * bpf_get_hash_recalc(skb)
-	 * Retrieve and possibly recalculate skb->hash.
-	 * @skb: pointer to skb
-	 * Return: hash
-	 */
-	BPF_FUNC_get_hash_recalc,
-
-	/**
-	 * u64 bpf_get_current_task(void)
-	 * Returns current task_struct
-	 * Return: current
-	 */
-	BPF_FUNC_get_current_task,
-
-	/**
-	 * bpf_probe_write_user(void *dst, void *src, int len)
-	 * safely attempt to write to a location
-	 * @dst: destination address in userspace
-	 * @src: source address on stack
-	 * @len: number of bytes to copy
-	 * Return: 0 on success or negative error
-	 */
-	BPF_FUNC_probe_write_user,
-
-	/**
-	 * bpf_current_task_under_cgroup(map, index) - Check cgroup2 membership of current task
-	 * @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
-	 * @index: index of the cgroup in the bpf_map
-	 * Return:
-	 *   == 0 current failed the cgroup2 descendant test
-	 *   == 1 current succeeded the cgroup2 descendant test
-	 *    < 0 error
-	 */
-	BPF_FUNC_current_task_under_cgroup,
-
-	/**
-	 * bpf_skb_change_tail(skb, len, flags)
-	 * The helper will resize the skb to the given new size,
-	 * to be used f.e. with control messages.
-	 * @skb: pointer to skb
-	 * @len: new skb length
-	 * @flags: reserved
-	 * Return: 0 on success or negative error
-	 */
-	BPF_FUNC_skb_change_tail,
-
-	/**
-	 * bpf_skb_pull_data(skb, len)
-	 * The helper will pull in non-linear data in case the
-	 * skb is non-linear and not all of len are part of the
-	 * linear section. Only needed for read/write with direct
-	 * packet access.
-	 * @skb: pointer to skb
-	 * @len: len to make read/writeable
-	 * Return: 0 on success or negative error
-	 */
-	BPF_FUNC_skb_pull_data,
-
-	/**
-	 * bpf_csum_update(skb, csum)
-	 * Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
-	 * @skb: pointer to skb
-	 * @csum: csum to add
-	 * Return: csum on success or negative error
-	 */
-	BPF_FUNC_csum_update,
-
-	/**
-	 * bpf_set_hash_invalid(skb)
-	 * Invalidate current skb>hash.
-	 * @skb: pointer to skb
-	 */
-	BPF_FUNC_set_hash_invalid,
-
-	/**
-	 * int bpf_get_numa_node_id()
-	 *     Return: Id of current NUMA node.
-	 */
-	BPF_FUNC_get_numa_node_id,
-
-	/**
-	 * int bpf_skb_change_head()
-	 *     Grows headroom of skb and adjusts MAC header offset accordingly.
-	 *     Will extends/reallocae as required automatically.
-	 *     May change skb data pointer and will thus invalidate any check
-	 *     performed for direct packet access.
-	 *     @skb: pointer to skb
-	 *     @len: length of header to be pushed in front
-	 *     @flags: Flags (unused for now)
-	 *     Return: 0 on success or negative error
-	 */
-	BPF_FUNC_skb_change_head,
-
-	/**
-	 * int bpf_xdp_adjust_head(xdp_md, delta)
-	 *     Adjust the xdp_md.data by delta
-	 *     @xdp_md: pointer to xdp_md
-	 *     @delta: An positive/negative integer to be added to xdp_md.data
-	 *     Return: 0 on success or negative on error
-	 */
-	BPF_FUNC_xdp_adjust_head,
-
-	/**
-	 * int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
-	 *     Copy a NUL terminated string from unsafe address. In case the string
-	 *     length is smaller than size, the target is not padded with further NUL
-	 *     bytes. In case the string length is larger than size, just count-1
-	 *     bytes are copied and the last byte is set to NUL.
-	 *     @dst: destination address
-	 *     @size: maximum number of bytes to copy, including the trailing NUL
-	 *     @unsafe_ptr: unsafe address
-	 *     Return:
-	 *       > 0 length of the string including the trailing NUL on success
-	 *       < 0 error
-	 */
-	BPF_FUNC_probe_read_str,
-
-	/**
-	 * u64 bpf_bpf_get_socket_cookie(skb)
-	 *     Get the cookie for the socket stored inside sk_buff.
-	 *     @skb: pointer to skb
-	 *     Return: 8 Bytes non-decreasing number on success or 0 if the socket
-	 *     field is missing inside sk_buff
-	 */
-	BPF_FUNC_get_socket_cookie,
-
-	/**
-	 * u32 bpf_get_socket_uid(skb)
-	 *     Get the owner uid of the socket stored inside sk_buff.
-	 *     @skb: pointer to skb
-	 *     Return: uid of the socket owner on success or 0 if the socket pointer
-	 *     inside sk_buff is NULL
-	 */
-	BPF_FUNC_get_socket_uid,
-
 	__BPF_FUNC_MAX_ID,
 };
 
-/* All flags used by eBPF helper functions, placed here. */
-
-/* BPF_FUNC_skb_store_bytes flags. */
-#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)
-#define BPF_F_INVALIDATE_HASH		(1ULL << 1)
-
-/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
- * First 4 bits are for passing the header field size.
- */
-#define BPF_F_HDR_FIELD_MASK		0xfULL
-
-/* BPF_FUNC_l4_csum_replace flags. */
-#define BPF_F_PSEUDO_HDR		(1ULL << 4)
-#define BPF_F_MARK_MANGLED_0		(1ULL << 5)
-
-/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
-#define BPF_F_INGRESS			(1ULL << 0)
-
-/* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
-#define BPF_F_TUNINFO_IPV6		(1ULL << 0)
-
-/* BPF_FUNC_skb_set_tunnel_key flags. */
-#define BPF_F_ZERO_CSUM_TX              (1ULL << 1)
-#define BPF_F_DONT_FRAGMENT             (1ULL << 2)
-
-/* BPF_FUNC_get_stackid flags. */
-#define BPF_F_SKIP_FIELD_MASK		0xffULL
-#define BPF_F_USER_STACK		(1ULL << 8)
-#define BPF_F_FAST_STACK_CMP		(1ULL << 9)
-#define BPF_F_REUSE_STACKID		(1ULL << 10)
-
-/* BPF_FUNC_perf_event_output flags. */
-#define BPF_F_INDEX_MASK		0xffffffffULL
-#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK
-/* BPF_FUNC_perf_event_output for sk_buff input context. */
-#define BPF_F_CTXLEN_MASK		(0xfffffULL << 32)
-
 /* user accessible mirror of in-kernel sk_buff.
  * new fields can only be added to the end of this structure
  */
@@ -611,39 +291,11 @@ struct __sk_buff {
 	__u32 cb[5];
 	__u32 hash;
 	__u32 tc_classid;
-	__u32 data;
-	__u32 data_end;
 };
 
 struct bpf_tunnel_key {
 	__u32 tunnel_id;
-	union {
-		__u32 remote_ipv4;
-		__u32 remote_ipv6[4];
-	};
-	__u8 tunnel_tos;
-	__u8 tunnel_ttl;
-	__u16 tunnel_ext;
-	__u32 tunnel_label;
-};
-
-/* User return codes for XDP prog type.
- * A valid XDP program must return one of these defined values. All other
- * return codes are reserved for future use. Unknown return codes will result
- * in packet drop.
- */
-enum xdp_action {
-	XDP_ABORTED = 0,
-	XDP_DROP,
-	XDP_PASS,
-};
-
-/* user accessible metadata for XDP packet hook
- * new fields must be added to the end of this structure
- */
-struct xdp_md {
-	__u32 data;
-	__u32 data_end;
+	__u32 remote_ipv4;
 };
 
 #endif /* _UAPI__LINUX_BPF_H__ */
diff --git a/include/uapi/linux/bpf_perf_event.h b/include/uapi/linux/bpf_perf_event.h
deleted file mode 100644
index 067427259820..000000000000
--- a/include/uapi/linux/bpf_perf_event.h
+++ /dev/null
@@ -1,18 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#ifndef _UAPI__LINUX_BPF_PERF_EVENT_H__
-#define _UAPI__LINUX_BPF_PERF_EVENT_H__
-
-#include <linux/types.h>
-#include <linux/ptrace.h>
-
-struct bpf_perf_event_data {
-	struct pt_regs regs;
-	__u64 sample_period;
-};
-
-#endif /* _UAPI__LINUX_BPF_PERF_EVENT_H__ */
diff --git a/include/uapi/linux/netfilter/xt_bpf.h b/include/uapi/linux/netfilter/xt_bpf.h
index da161b56c79e..1fad2c27ac32 100644
--- a/include/uapi/linux/netfilter/xt_bpf.h
+++ b/include/uapi/linux/netfilter/xt_bpf.h
@@ -2,11 +2,9 @@
 #define _XT_BPF_H
 
 #include <linux/filter.h>
-#include <linux/limits.h>
 #include <linux/types.h>
 
 #define XT_BPF_MAX_NUM_INSTR	64
-#define XT_BPF_PATH_MAX		(XT_BPF_MAX_NUM_INSTR * sizeof(struct sock_filter))
 
 struct bpf_prog;
 
@@ -18,24 +16,4 @@ struct xt_bpf_info {
 	struct bpf_prog *filter __attribute__((aligned(8)));
 };
 
-enum xt_bpf_modes {
-	XT_BPF_MODE_BYTECODE,
-	XT_BPF_MODE_FD_PINNED,
-	XT_BPF_MODE_FD_ELF,
-};
-#define XT_BPF_MODE_PATH_PINNED XT_BPF_MODE_FD_PINNED
-
-struct xt_bpf_info_v1 {
-	__u16 mode;
-	__u16 bpf_program_num_elem;
-	__s32 fd;
-	union {
-		struct sock_filter bpf_program[XT_BPF_MAX_NUM_INSTR];
-		char path[XT_BPF_PATH_MAX];
-	};
-
-	/* only used in the kernel */
-	struct bpf_prog *filter __attribute__((aligned(8)));
-};
-
 #endif /*_XT_BPF_H */
diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index a1cc04cb8d6e..686da166aeec 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -270,9 +270,6 @@ enum perf_event_read_format {
 
 /*
  * Hardware event_id to monitor via a performance monitoring event:
- *
- * @sample_max_stack: Max number of frame pointers in a callchain,
- *		      should be < /proc/sys/kernel/perf_event_max_stack
  */
 struct perf_event_attr {
 
@@ -383,8 +380,7 @@ struct perf_event_attr {
 	 * Wakeup watermark for AUX area
 	 */
 	__u32	aux_watermark;
-	__u16	sample_max_stack;
-	__u16	__reserved_2;	/* align to __u64 */
+	__u32	__reserved_2;	/* align to __u64 */
 };
 
 #define perf_flags(attr)	(*(&(attr)->read_format + 1))
diff --git a/include/uapi/linux/sched.h b/include/uapi/linux/sched.h
index 5f0fe019a720..cc89ddefa926 100644
--- a/include/uapi/linux/sched.h
+++ b/include/uapi/linux/sched.h
@@ -21,7 +21,8 @@
 #define CLONE_DETACHED		0x00400000	/* Unused, ignored */
 #define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
 #define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
-#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
+/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
+   and is now available for re-use. */
 #define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
 #define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
 #define CLONE_NEWUSER		0x10000000	/* New user namespace */
diff --git a/init/Kconfig b/init/Kconfig
index 6d56748742ba..3eef4e1ffeab 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -1247,28 +1247,11 @@ config DEBUG_BLK_CGROUP
 	Enable some debugging help. Currently it exports additional stat
 	files in a cgroup which can be useful for debugging.
 
-config CGROUP_BPF
-        bool "Support for eBPF programs attached to cgroups"
-        depends on BPF_SYSCALL
-        select SOCK_CGROUP_DATA
-        help
-          Allow attaching eBPF programs to a cgroup using the bpf(2)
-          syscall command BPF_PROG_ATTACH.
-
-          In which context these programs are accessed depends on the type
-          of attachment. For instance, programs that are attached using
-          BPF_CGROUP_INET_INGRESS will be executed on the ingress path of
-          inet sockets.
-
 config CGROUP_WRITEBACK
 	bool
 	depends on MEMCG && BLK_CGROUP
 	default y
 
-config SOCK_CGROUP_DATA
-	bool
-	default n
-
 endif # CGROUPS
 
 config CHECKPOINT_RESTORE
diff --git a/ipc/mqueue.c b/ipc/mqueue.c
index 0a1afa17bf5f..a94880dc9094 100644
--- a/ipc/mqueue.c
+++ b/ipc/mqueue.c
@@ -305,7 +305,7 @@ err:
 static int mqueue_fill_super(struct super_block *sb, void *data, int silent)
 {
 	struct inode *inode;
-	struct ipc_namespace *ns = sb->s_fs_info;
+	struct ipc_namespace *ns = data;
 
 	sb->s_blocksize = PAGE_CACHE_SIZE;
 	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
@@ -326,14 +326,17 @@ static struct dentry *mqueue_mount(struct file_system_type *fs_type,
 			 int flags, const char *dev_name,
 			 void *data)
 {
-	struct ipc_namespace *ns;
-	if (flags & MS_KERNMOUNT) {
-		ns = data;
-		data = NULL;
-	} else {
-		ns = current->nsproxy->ipc_ns;
+	if (!(flags & MS_KERNMOUNT)) {
+		struct ipc_namespace *ns = current->nsproxy->ipc_ns;
+		/* Don't allow mounting unless the caller has CAP_SYS_ADMIN
+		 * over the ipc namespace.
+		 */
+		if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN))
+			return ERR_PTR(-EPERM);
+
+		data = ns;
 	}
-	return mount_ns(fs_type, flags, data, ns, ns->user_ns, mqueue_fill_super);
+	return mount_ns(fs_type, flags, data, mqueue_fill_super);
 }
 
 static void init_once(void *foo)
diff --git a/ipc/namespace.c b/ipc/namespace.c
index 25b64530c042..068caf18d565 100644
--- a/ipc/namespace.c
+++ b/ipc/namespace.c
@@ -166,16 +166,10 @@ static int ipcns_install(struct nsproxy *nsproxy, struct ns_common *new)
 	return 0;
 }
 
-static struct user_namespace *ipcns_owner(struct ns_common *ns)
-{
-	return to_ipc_ns(ns)->user_ns;
-}
-
 const struct proc_ns_operations ipcns_operations = {
 	.name		= "ipc",
 	.type		= CLONE_NEWIPC,
 	.get		= ipcns_get,
 	.put		= ipcns_put,
 	.install	= ipcns_install,
-	.owner		= ipcns_owner,
 };
diff --git a/kernel/bpf/Makefile b/kernel/bpf/Makefile
index ad110b5aef69..677991f29d66 100644
--- a/kernel/bpf/Makefile
+++ b/kernel/bpf/Makefile
@@ -2,8 +2,4 @@ obj-y := core.o
 CFLAGS_core.o += $(call cc-disable-warning, override-init)
 
 obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o
-obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o
-ifeq ($(CONFIG_PERF_EVENTS),y)
-obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
-endif
-obj-$(CONFIG_CGROUP_BPF) += cgroup.o
+obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o
diff --git a/kernel/bpf/arraymap.c b/kernel/bpf/arraymap.c
index b30ca0f2fa41..daa4e0782cf7 100644
--- a/kernel/bpf/arraymap.c
+++ b/kernel/bpf/arraymap.c
@@ -11,57 +11,23 @@
  */
 #include <linux/bpf.h>
 #include <linux/err.h>
+#include <linux/vmalloc.h>
 #include <linux/slab.h>
 #include <linux/mm.h>
 #include <linux/filter.h>
 #include <linux/perf_event.h>
 
-#define ARRAY_CREATE_FLAG_MASK \
-	(BPF_F_RDONLY | BPF_F_WRONLY)
-
-static void bpf_array_free_percpu(struct bpf_array *array)
-{
-	int i;
-
-	for (i = 0; i < array->map.max_entries; i++) {
-		free_percpu(array->pptrs[i]);
-		cond_resched();
-	}
-}
-
-static int bpf_array_alloc_percpu(struct bpf_array *array)
-{
-	void __percpu *ptr;
-	int i;
-
-	for (i = 0; i < array->map.max_entries; i++) {
-		ptr = __alloc_percpu_gfp(array->elem_size, 8,
-					 GFP_USER | __GFP_NOWARN);
-		if (!ptr) {
-			bpf_array_free_percpu(array);
-			return -ENOMEM;
-		}
-		array->pptrs[i] = ptr;
-		cond_resched();
-	}
-
-	return 0;
-}
-
 /* Called from syscall */
 static struct bpf_map *array_map_alloc(union bpf_attr *attr)
 {
-	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
-	u32 elem_size, index_mask, max_entries;
+	u32 elem_size, array_size, index_mask, max_entries;
 	bool unpriv = !capable(CAP_SYS_ADMIN);
-	u64 cost, array_size, mask64;
 	struct bpf_array *array;
-	int ret;
+	u64 mask64;
 
 	/* check sanity of attributes */
 	if (attr->max_entries == 0 || attr->key_size != 4 ||
-	    attr->value_size == 0 ||
-	    attr->map_flags & ~ARRAY_CREATE_FLAG_MASK)
+	    attr->value_size == 0)
 		return ERR_PTR(-EINVAL);
 
 	if (attr->value_size >= 1 << (KMALLOC_SHIFT_MAX - 1))
@@ -93,50 +59,30 @@ static struct bpf_map *array_map_alloc(union bpf_attr *attr)
 			return ERR_PTR(-E2BIG);
 	}
 
-	array_size = sizeof(*array);
-	if (percpu)
-		array_size += (u64) max_entries * sizeof(void *);
-	else
-		array_size += (u64) max_entries * elem_size;
-
-	/* make sure there is no u32 overflow later in round_up() */
-	cost = array_size;
-	if (cost >= U32_MAX - PAGE_SIZE)
+	/* check round_up into zero and u32 overflow */
+	if (elem_size == 0 ||
+	    max_entries > (U32_MAX - PAGE_SIZE - sizeof(*array)) / elem_size)
 		return ERR_PTR(-ENOMEM);
-	if (percpu) {
-		cost += (u64)attr->max_entries * elem_size * num_possible_cpus();
-		if (cost >= U32_MAX - PAGE_SIZE)
-			return ERR_PTR(-ENOMEM);
-	}
-	cost = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
 
-	ret = bpf_map_precharge_memlock(cost);
-	if (ret < 0)
-		return ERR_PTR(ret);
+	array_size = sizeof(*array) + max_entries * elem_size;
 
 	/* allocate all map elements and zero-initialize them */
-	array = bpf_map_area_alloc(array_size);
-	if (!array)
-		return ERR_PTR(-ENOMEM);
+	array = kzalloc(array_size, GFP_USER | __GFP_NOWARN);
+	if (!array) {
+		array = vzalloc(array_size);
+		if (!array)
+			return ERR_PTR(-ENOMEM);
+	}
 	array->index_mask = index_mask;
 	array->map.unpriv_array = unpriv;
 
 	/* copy mandatory map attributes */
-	array->map.map_type = attr->map_type;
 	array->map.key_size = attr->key_size;
 	array->map.value_size = attr->value_size;
 	array->map.max_entries = attr->max_entries;
-	array->map.map_flags = attr->map_flags;
-	array->map.pages = cost;
+	array->map.pages = round_up(array_size, PAGE_SIZE) >> PAGE_SHIFT;
 	array->elem_size = elem_size;
 
-	if (percpu &&
-	    (elem_size > PCPU_MIN_UNIT_SIZE ||
-	     bpf_array_alloc_percpu(array))) {
-		bpf_map_area_free(array);
-		return ERR_PTR(-ENOMEM);
-	}
-
 	return &array->map;
 }
 
@@ -146,50 +92,12 @@ static void *array_map_lookup_elem(struct bpf_map *map, void *key)
 	struct bpf_array *array = container_of(map, struct bpf_array, map);
 	u32 index = *(u32 *)key;
 
-	if (unlikely(index >= array->map.max_entries))
+	if (index >= array->map.max_entries)
 		return NULL;
 
 	return array->value + array->elem_size * (index & array->index_mask);
 }
 
-/* Called from eBPF program */
-static void *percpu_array_map_lookup_elem(struct bpf_map *map, void *key)
-{
-	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	u32 index = *(u32 *)key;
-
-	if (unlikely(index >= array->map.max_entries))
-		return NULL;
-
-	return this_cpu_ptr(array->pptrs[index & array->index_mask]);
-}
-
-int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value)
-{
-	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	u32 index = *(u32 *)key;
-	void __percpu *pptr;
-	int cpu, off = 0;
-	u32 size;
-
-	if (unlikely(index >= array->map.max_entries))
-		return -ENOENT;
-
-	/* per_cpu areas are zero-filled and bpf programs can only
-	 * access 'value_size' of them, so copying rounded areas
-	 * will not leak any kernel data
-	 */
-	size = round_up(map->value_size, 8);
-	rcu_read_lock();
-	pptr = array->pptrs[index & array->index_mask];
-	for_each_possible_cpu(cpu) {
-		bpf_long_memcpy(value + off, per_cpu_ptr(pptr, cpu), size);
-		off += size;
-	}
-	rcu_read_unlock();
-	return 0;
-}
-
 /* Called from syscall */
 static int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
 {
@@ -216,63 +124,21 @@ static int array_map_update_elem(struct bpf_map *map, void *key, void *value,
 	struct bpf_array *array = container_of(map, struct bpf_array, map);
 	u32 index = *(u32 *)key;
 
-	if (unlikely(map_flags > BPF_EXIST))
+	if (map_flags > BPF_EXIST)
 		/* unknown flags */
 		return -EINVAL;
 
-	if (unlikely(index >= array->map.max_entries))
+	if (index >= array->map.max_entries)
 		/* all elements were pre-allocated, cannot insert a new one */
 		return -E2BIG;
 
-	if (unlikely(map_flags == BPF_NOEXIST))
+	if (map_flags == BPF_NOEXIST)
 		/* all elements already exist */
 		return -EEXIST;
 
-	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
-		memcpy(this_cpu_ptr(array->pptrs[index & array->index_mask]),
-		       value, map->value_size);
-	else
-		memcpy(array->value +
-		       array->elem_size * (index & array->index_mask),
-		       value, map->value_size);
-	return 0;
-}
-
-int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
-			    u64 map_flags)
-{
-	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	u32 index = *(u32 *)key;
-	void __percpu *pptr;
-	int cpu, off = 0;
-	u32 size;
-
-	if (unlikely(map_flags > BPF_EXIST))
-		/* unknown flags */
-		return -EINVAL;
-
-	if (unlikely(index >= array->map.max_entries))
-		/* all elements were pre-allocated, cannot insert a new one */
-		return -E2BIG;
-
-	if (unlikely(map_flags == BPF_NOEXIST))
-		/* all elements already exist */
-		return -EEXIST;
-
-	/* the user space will provide round_up(value_size, 8) bytes that
-	 * will be copied into per-cpu area. bpf programs can only access
-	 * value_size of it. During lookup the same extra bytes will be
-	 * returned or zeros which were zero-filled by percpu_alloc,
-	 * so no kernel data leaks possible
-	 */
-	size = round_up(map->value_size, 8);
-	rcu_read_lock();
-	pptr = array->pptrs[index & array->index_mask];
-	for_each_possible_cpu(cpu) {
-		bpf_long_memcpy(per_cpu_ptr(pptr, cpu), value + off, size);
-		off += size;
-	}
-	rcu_read_unlock();
+	memcpy(array->value +
+	       array->elem_size * (index & array->index_mask),
+	       value, map->value_size);
 	return 0;
 }
 
@@ -294,10 +160,7 @@ static void array_map_free(struct bpf_map *map)
 	 */
 	synchronize_rcu();
 
-	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
-		bpf_array_free_percpu(array);
-
-	bpf_map_area_free(array);
+	kvfree(array);
 }
 
 static const struct bpf_map_ops array_ops = {
@@ -314,24 +177,9 @@ static struct bpf_map_type_list array_type __read_mostly = {
 	.type = BPF_MAP_TYPE_ARRAY,
 };
 
-static const struct bpf_map_ops percpu_array_ops = {
-	.map_alloc = array_map_alloc,
-	.map_free = array_map_free,
-	.map_get_next_key = array_map_get_next_key,
-	.map_lookup_elem = percpu_array_map_lookup_elem,
-	.map_update_elem = array_map_update_elem,
-	.map_delete_elem = array_map_delete_elem,
-};
-
-static struct bpf_map_type_list percpu_array_type __read_mostly = {
-	.ops = &percpu_array_ops,
-	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
-};
-
 static int __init register_array_map(void)
 {
 	bpf_register_map_type(&array_type);
-	bpf_register_map_type(&percpu_array_type);
 	return 0;
 }
 late_initcall(register_array_map);
@@ -354,8 +202,7 @@ static void fd_array_map_free(struct bpf_map *map)
 	/* make sure it's empty */
 	for (i = 0; i < array->map.max_entries; i++)
 		BUG_ON(array->ptrs[i] != NULL);
-
-	bpf_map_area_free(array);
+	kvfree(array);
 }
 
 static void *fd_array_map_lookup_elem(struct bpf_map *map, void *key)
@@ -364,8 +211,8 @@ static void *fd_array_map_lookup_elem(struct bpf_map *map, void *key)
 }
 
 /* only called from syscall */
-int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
-				 void *key, void *value, u64 map_flags)
+static int fd_array_map_update_elem(struct bpf_map *map, void *key,
+				    void *value, u64 map_flags)
 {
 	struct bpf_array *array = container_of(map, struct bpf_array, map);
 	void *new_ptr, *old_ptr;
@@ -378,7 +225,7 @@ int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
 		return -E2BIG;
 
 	ufd = *(u32 *)value;
-	new_ptr = map->ops->map_fd_get_ptr(map, map_file, ufd);
+	new_ptr = map->ops->map_fd_get_ptr(map, ufd);
 	if (IS_ERR(new_ptr))
 		return PTR_ERR(new_ptr);
 
@@ -407,12 +254,10 @@ static int fd_array_map_delete_elem(struct bpf_map *map, void *key)
 	}
 }
 
-static void *prog_fd_array_get_ptr(struct bpf_map *map,
-				   struct file *map_file, int fd)
+static void *prog_fd_array_get_ptr(struct bpf_map *map, int fd)
 {
 	struct bpf_array *array = container_of(map, struct bpf_array, map);
 	struct bpf_prog *prog = bpf_prog_get(fd);
-
 	if (IS_ERR(prog))
 		return prog;
 
@@ -420,7 +265,6 @@ static void *prog_fd_array_get_ptr(struct bpf_map *map,
 		bpf_prog_put(prog);
 		return ERR_PTR(-EINVAL);
 	}
-
 	return prog;
 }
 
@@ -444,6 +288,7 @@ static const struct bpf_map_ops prog_array_ops = {
 	.map_free = fd_array_map_free,
 	.map_get_next_key = array_map_get_next_key,
 	.map_lookup_elem = fd_array_map_lookup_elem,
+	.map_update_elem = fd_array_map_update_elem,
 	.map_delete_elem = fd_array_map_delete_elem,
 	.map_fd_get_ptr = prog_fd_array_get_ptr,
 	.map_fd_put_ptr = prog_fd_array_put_ptr,
@@ -461,105 +306,58 @@ static int __init register_prog_array_map(void)
 }
 late_initcall(register_prog_array_map);
 
-static struct bpf_event_entry *bpf_event_entry_gen(struct file *perf_file,
-						   struct file *map_file)
+static void perf_event_array_map_free(struct bpf_map *map)
 {
-	struct bpf_event_entry *ee;
-
-	ee = kzalloc(sizeof(*ee), GFP_ATOMIC);
-	if (ee) {
-		ee->event = perf_file->private_data;
-		ee->perf_file = perf_file;
-		ee->map_file = map_file;
-	}
-
-	return ee;
+	bpf_fd_array_map_clear(map);
+	fd_array_map_free(map);
 }
 
-static void __bpf_event_entry_free(struct rcu_head *rcu)
+static void *perf_event_fd_array_get_ptr(struct bpf_map *map, int fd)
 {
-	struct bpf_event_entry *ee;
+	struct perf_event *event;
+	const struct perf_event_attr *attr;
 
-	ee = container_of(rcu, struct bpf_event_entry, rcu);
-	fput(ee->perf_file);
-	kfree(ee);
-}
+	event = perf_event_get(fd);
+	if (IS_ERR(event))
+		return event;
 
-static void bpf_event_entry_free_rcu(struct bpf_event_entry *ee)
-{
-	call_rcu(&ee->rcu, __bpf_event_entry_free);
-}
-
-static void *perf_event_fd_array_get_ptr(struct bpf_map *map,
-					 struct file *map_file, int fd)
-{
-	const struct perf_event_attr *attr;
-	struct bpf_event_entry *ee;
-	struct perf_event *event;
-	struct file *perf_file;
+	attr = perf_event_attrs(event);
+	if (IS_ERR(attr))
+		goto err;
 
-	perf_file = perf_event_get(fd);
-	if (IS_ERR(perf_file))
-		return perf_file;
+	if (attr->inherit)
+		goto err;
 
-	event = perf_file->private_data;
-	ee = ERR_PTR(-EINVAL);
+	if (attr->type == PERF_TYPE_RAW)
+		return event;
 
-	attr = perf_event_attrs(event);
-	if (IS_ERR(attr) || attr->inherit)
-		goto err_out;
-
-	switch (attr->type) {
-	case PERF_TYPE_SOFTWARE:
-		if (attr->config != PERF_COUNT_SW_BPF_OUTPUT)
-			goto err_out;
-		/* fall-through */
-	case PERF_TYPE_RAW:
-	case PERF_TYPE_HARDWARE:
-		ee = bpf_event_entry_gen(perf_file, map_file);
-		if (ee)
-			return ee;
-		ee = ERR_PTR(-ENOMEM);
-		/* fall-through */
-	default:
-		break;
-	}
+	if (attr->type == PERF_TYPE_HARDWARE)
+		return event;
 
-err_out:
-	fput(perf_file);
-	return ee;
+	if (attr->type == PERF_TYPE_SOFTWARE &&
+	    attr->config == PERF_COUNT_SW_BPF_OUTPUT)
+		return event;
+err:
+	perf_event_release_kernel(event);
+	return ERR_PTR(-EINVAL);
 }
 
 static void perf_event_fd_array_put_ptr(void *ptr)
 {
-	bpf_event_entry_free_rcu(ptr);
-}
-
-static void perf_event_fd_array_release(struct bpf_map *map,
-					struct file *map_file)
-{
-	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	struct bpf_event_entry *ee;
-	int i;
+	struct perf_event *event = ptr;
 
-	rcu_read_lock();
-	for (i = 0; i < array->map.max_entries; i++) {
-		ee = READ_ONCE(array->ptrs[i]);
-		if (ee && ee->map_file == map_file)
-			fd_array_map_delete_elem(map, &i);
-	}
-	rcu_read_unlock();
+	perf_event_release_kernel(event);
 }
 
 static const struct bpf_map_ops perf_event_array_ops = {
 	.map_alloc = fd_array_map_alloc,
-	.map_free = fd_array_map_free,
+	.map_free = perf_event_array_map_free,
 	.map_get_next_key = array_map_get_next_key,
 	.map_lookup_elem = fd_array_map_lookup_elem,
+	.map_update_elem = fd_array_map_update_elem,
 	.map_delete_elem = fd_array_map_delete_elem,
 	.map_fd_get_ptr = perf_event_fd_array_get_ptr,
 	.map_fd_put_ptr = perf_event_fd_array_put_ptr,
-	.map_release = perf_event_fd_array_release,
 };
 
 static struct bpf_map_type_list perf_event_array_type __read_mostly = {
@@ -573,46 +371,3 @@ static int __init register_perf_event_array_map(void)
 	return 0;
 }
 late_initcall(register_perf_event_array_map);
-
-#ifdef CONFIG_CGROUPS
-static void *cgroup_fd_array_get_ptr(struct bpf_map *map,
-				     struct file *map_file /* not used */,
-				     int fd)
-{
-	return cgroup_get_from_fd(fd);
-}
-
-static void cgroup_fd_array_put_ptr(void *ptr)
-{
-	/* cgroup_put free cgrp after a rcu grace period */
-	cgroup_put(ptr);
-}
-
-static void cgroup_fd_array_free(struct bpf_map *map)
-{
-	bpf_fd_array_map_clear(map);
-	fd_array_map_free(map);
-}
-
-static const struct bpf_map_ops cgroup_array_ops = {
-	.map_alloc = fd_array_map_alloc,
-	.map_free = cgroup_fd_array_free,
-	.map_get_next_key = array_map_get_next_key,
-	.map_lookup_elem = fd_array_map_lookup_elem,
-	.map_delete_elem = fd_array_map_delete_elem,
-	.map_fd_get_ptr = cgroup_fd_array_get_ptr,
-	.map_fd_put_ptr = cgroup_fd_array_put_ptr,
-};
-
-static struct bpf_map_type_list cgroup_array_type __read_mostly = {
-	.ops = &cgroup_array_ops,
-	.type = BPF_MAP_TYPE_CGROUP_ARRAY,
-};
-
-static int __init register_cgroup_array_map(void)
-{
-	bpf_register_map_type(&cgroup_array_type);
-	return 0;
-}
-late_initcall(register_cgroup_array_map);
-#endif
diff --git a/kernel/bpf/cgroup.c b/kernel/bpf/cgroup.c
deleted file mode 100644
index 54c47a93e86e..000000000000
--- a/kernel/bpf/cgroup.c
+++ /dev/null
@@ -1,427 +0,0 @@
-/*
- * Functions to manage eBPF programs attached to cgroups
- *
- * Copyright (c) 2016 Daniel Mack
- *
- * This file is subject to the terms and conditions of version 2 of the GNU
- * General Public License.  See the file COPYING in the main directory of the
- * Linux distribution for more details.
- */
-
-#include <linux/kernel.h>
-#include <linux/atomic.h>
-#include <linux/cgroup.h>
-#include <linux/slab.h>
-#include <linux/bpf.h>
-#include <linux/bpf-cgroup.h>
-#include <net/sock.h>
-
-DEFINE_STATIC_KEY_FALSE(cgroup_bpf_enabled_key);
-EXPORT_SYMBOL(cgroup_bpf_enabled_key);
-
-/**
- * cgroup_bpf_put() - put references of all bpf programs
- * @cgrp: the cgroup to modify
- */
-void cgroup_bpf_put(struct cgroup *cgrp)
-{
-	unsigned int type;
-
-	for (type = 0; type < ARRAY_SIZE(cgrp->bpf.progs); type++) {
-		struct list_head *progs = &cgrp->bpf.progs[type];
-		struct bpf_prog_list *pl, *tmp;
-
-		list_for_each_entry_safe(pl, tmp, progs, node) {
-			list_del(&pl->node);
-			bpf_prog_put(pl->prog);
-			kfree(pl);
-			static_branch_dec(&cgroup_bpf_enabled_key);
-		}
-		bpf_prog_array_free(cgrp->bpf.effective[type]);
-	}
-}
-
-/* count number of elements in the list.
- * it's slow but the list cannot be long
- */
-static u32 prog_list_length(struct list_head *head)
-{
-	struct bpf_prog_list *pl;
-	u32 cnt = 0;
-
-	list_for_each_entry(pl, head, node) {
-		if (!pl->prog)
-			continue;
-		cnt++;
-	}
-	return cnt;
-}
-
-/* if parent has non-overridable prog attached,
- * disallow attaching new programs to the descendent cgroup.
- * if parent has overridable or multi-prog, allow attaching
- */
-static bool hierarchy_allows_attach(struct cgroup *cgrp,
-				    enum bpf_attach_type type,
-				    u32 new_flags)
-{
-	struct cgroup *p;
-
-	p = cgroup_parent(cgrp);
-	if (!p)
-		return true;
-	do {
-		u32 flags = p->bpf.flags[type];
-		u32 cnt;
-
-		if (flags & BPF_F_ALLOW_MULTI)
-			return true;
-		cnt = prog_list_length(&p->bpf.progs[type]);
-		WARN_ON_ONCE(cnt > 1);
-		if (cnt == 1)
-			return !!(flags & BPF_F_ALLOW_OVERRIDE);
-		p = cgroup_parent(p);
-	} while (p);
-	return true;
-}
-
-/* compute a chain of effective programs for a given cgroup:
- * start from the list of programs in this cgroup and add
- * all parent programs.
- * Note that parent's F_ALLOW_OVERRIDE-type program is yielding
- * to programs in this cgroup
- */
-static int compute_effective_progs(struct cgroup *cgrp,
-				   enum bpf_attach_type type,
-				   struct bpf_prog_array __rcu **array)
-{
-	struct bpf_prog_array __rcu *progs;
-	struct bpf_prog_list *pl;
-	struct cgroup *p = cgrp;
-	int cnt = 0;
-
-	/* count number of effective programs by walking parents */
-	do {
-		if (cnt == 0 || (p->bpf.flags[type] & BPF_F_ALLOW_MULTI))
-			cnt += prog_list_length(&p->bpf.progs[type]);
-		p = cgroup_parent(p);
-	} while (p);
-
-	progs = bpf_prog_array_alloc(cnt, GFP_KERNEL);
-	if (!progs)
-		return -ENOMEM;
-
-	/* populate the array with effective progs */
-	cnt = 0;
-	p = cgrp;
-	do {
-		if (cnt == 0 || (p->bpf.flags[type] & BPF_F_ALLOW_MULTI))
-			list_for_each_entry(pl,
-					    &p->bpf.progs[type], node) {
-				if (!pl->prog)
-					continue;
-				rcu_dereference_protected(progs, 1)->
-					progs[cnt++] = pl->prog;
-			}
-		p = cgroup_parent(p);
-	} while (p);
-
-	*array = progs;
-	return 0;
-}
-
-static void activate_effective_progs(struct cgroup *cgrp,
-				     enum bpf_attach_type type,
-				     struct bpf_prog_array __rcu *array)
-{
-	struct bpf_prog_array __rcu *old_array;
-
-	old_array = xchg(&cgrp->bpf.effective[type], array);
-	/* free prog array after grace period, since __cgroup_bpf_run_*()
-	 * might be still walking the array
-	 */
-	bpf_prog_array_free(old_array);
-}
-
-/**
- * cgroup_bpf_inherit() - inherit effective programs from parent
- * @cgrp: the cgroup to modify
- */
-int cgroup_bpf_inherit(struct cgroup *cgrp)
-{
-/* has to use marco instead of const int, since compiler thinks
- * that array below is variable length
- */
-#define	NR ARRAY_SIZE(cgrp->bpf.effective)
-	struct bpf_prog_array __rcu *arrays[NR] = {};
-	int i;
-
-	for (i = 0; i < NR; i++)
-		INIT_LIST_HEAD(&cgrp->bpf.progs[i]);
-
-	for (i = 0; i < NR; i++)
-		if (compute_effective_progs(cgrp, i, &arrays[i]))
-			goto cleanup;
-
-	for (i = 0; i < NR; i++)
-		activate_effective_progs(cgrp, i, arrays[i]);
-
-	return 0;
-cleanup:
-	for (i = 0; i < NR; i++)
-		bpf_prog_array_free(arrays[i]);
-	return -ENOMEM;
-}
-
-#define BPF_CGROUP_MAX_PROGS 64
-
-/**
- * __cgroup_bpf_attach() - Attach the program to a cgroup, and
- *                         propagate the change to descendants
- * @cgrp: The cgroup which descendants to traverse
- * @prog: A program to attach
- * @type: Type of attach operation
- *
- * Must be called with cgroup_mutex held.
- */
-int __cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
-			enum bpf_attach_type type, u32 flags)
-{
-	struct list_head *progs = &cgrp->bpf.progs[type];
-	struct bpf_prog *old_prog = NULL;
-	struct cgroup_subsys_state *css;
-	struct bpf_prog_list *pl;
-	bool pl_was_allocated;
-	u32 old_flags;
-	int err;
-
-	if ((flags & BPF_F_ALLOW_OVERRIDE) && (flags & BPF_F_ALLOW_MULTI))
-		/* invalid combination */
-		return -EINVAL;
-
-	if (!hierarchy_allows_attach(cgrp, type, flags))
-		return -EPERM;
-
-	if (!list_empty(progs) && cgrp->bpf.flags[type] != flags)
-		/* Disallow attaching non-overridable on top
-		 * of existing overridable in this cgroup.
-		 * Disallow attaching multi-prog if overridable or none
-		 */
-		return -EPERM;
-
-	if (prog_list_length(progs) >= BPF_CGROUP_MAX_PROGS)
-		return -E2BIG;
-
-	if (flags & BPF_F_ALLOW_MULTI) {
-		list_for_each_entry(pl, progs, node)
-			if (pl->prog == prog)
-				/* disallow attaching the same prog twice */
-				return -EINVAL;
-
-		pl = kmalloc(sizeof(*pl), GFP_KERNEL);
-		if (!pl)
-			return -ENOMEM;
-		pl_was_allocated = true;
-		pl->prog = prog;
-		list_add_tail(&pl->node, progs);
-	} else {
-		if (list_empty(progs)) {
-			pl = kmalloc(sizeof(*pl), GFP_KERNEL);
-			if (!pl)
-				return -ENOMEM;
-			pl_was_allocated = true;
-			list_add_tail(&pl->node, progs);
-		} else {
-			pl = list_first_entry(progs, typeof(*pl), node);
-			old_prog = pl->prog;
-			pl_was_allocated = false;
-		}
-		pl->prog = prog;
-	}
-
-	old_flags = cgrp->bpf.flags[type];
-	cgrp->bpf.flags[type] = flags;
-
-	/* allocate and recompute effective prog arrays */
-	css_for_each_descendant_pre(css, &cgrp->self) {
-		struct cgroup *desc = container_of(css, struct cgroup, self);
-
-		err = compute_effective_progs(desc, type, &desc->bpf.inactive);
-		if (err)
-			goto cleanup;
-	}
-
-	/* all allocations were successful. Activate all prog arrays */
-	css_for_each_descendant_pre(css, &cgrp->self) {
-		struct cgroup *desc = container_of(css, struct cgroup, self);
-
-		activate_effective_progs(desc, type, desc->bpf.inactive);
-		desc->bpf.inactive = NULL;
-	}
-
-	static_branch_inc(&cgroup_bpf_enabled_key);
-	if (old_prog) {
-		bpf_prog_put(old_prog);
-		static_branch_dec(&cgroup_bpf_enabled_key);
-	}
-	return 0;
-
-cleanup:
-	/* oom while computing effective. Free all computed effective arrays
-	 * since they were not activated
-	 */
-	css_for_each_descendant_pre(css, &cgrp->self) {
-		struct cgroup *desc = container_of(css, struct cgroup, self);
-
-		bpf_prog_array_free(desc->bpf.inactive);
-		desc->bpf.inactive = NULL;
-	}
-
-	/* and cleanup the prog list */
-	pl->prog = old_prog;
-	if (pl_was_allocated) {
-		list_del(&pl->node);
-		kfree(pl);
-	}
-	return err;
-}
-
-/**
- * __cgroup_bpf_detach() - Detach the program from a cgroup, and
- *                         propagate the change to descendants
- * @cgrp: The cgroup which descendants to traverse
- * @prog: A program to detach or NULL
- * @type: Type of detach operation
- *
- * Must be called with cgroup_mutex held.
- */
-int __cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
-			enum bpf_attach_type type, u32 unused_flags)
-{
-	struct list_head *progs = &cgrp->bpf.progs[type];
-	u32 flags = cgrp->bpf.flags[type];
-	struct bpf_prog *old_prog = NULL;
-	struct cgroup_subsys_state *css;
-	struct bpf_prog_list *pl;
-	int err;
-
-	if (flags & BPF_F_ALLOW_MULTI) {
-		if (!prog)
-			/* to detach MULTI prog the user has to specify valid FD
-			 * of the program to be detached
-			 */
-			return -EINVAL;
-	} else {
-		if (list_empty(progs))
-			/* report error when trying to detach and nothing is attached */
-			return -ENOENT;
-	}
-
-	if (flags & BPF_F_ALLOW_MULTI) {
-		/* find the prog and detach it */
-		list_for_each_entry(pl, progs, node) {
-			if (pl->prog != prog)
-				continue;
-			old_prog = prog;
-			/* mark it deleted, so it's ignored while
-			 * recomputing effective
-			 */
-			pl->prog = NULL;
-			break;
-		}
-		if (!old_prog)
-			return -ENOENT;
-	} else {
-		/* to maintain backward compatibility NONE and OVERRIDE cgroups
-		 * allow detaching with invalid FD (prog==NULL)
-		 */
-		pl = list_first_entry(progs, typeof(*pl), node);
-		old_prog = pl->prog;
-		pl->prog = NULL;
-	}
-
-	/* allocate and recompute effective prog arrays */
-	css_for_each_descendant_pre(css, &cgrp->self) {
-		struct cgroup *desc = container_of(css, struct cgroup, self);
-
-		err = compute_effective_progs(desc, type, &desc->bpf.inactive);
-		if (err)
-			goto cleanup;
-	}
-
-	/* all allocations were successful. Activate all prog arrays */
-	css_for_each_descendant_pre(css, &cgrp->self) {
-		struct cgroup *desc = container_of(css, struct cgroup, self);
-
-		activate_effective_progs(desc, type, desc->bpf.inactive);
-		desc->bpf.inactive = NULL;
-	}
-
-	/* now can actually delete it from this cgroup list */
-	list_del(&pl->node);
-	kfree(pl);
-	if (list_empty(progs))
-		/* last program was detached, reset flags to zero */
-		cgrp->bpf.flags[type] = 0;
-
-	bpf_prog_put(old_prog);
-	static_branch_dec(&cgroup_bpf_enabled_key);
-	return 0;
-
-cleanup:
-	/* oom while computing effective. Free all computed effective arrays
-	 * since they were not activated
-	 */
-	css_for_each_descendant_pre(css, &cgrp->self) {
-		struct cgroup *desc = container_of(css, struct cgroup, self);
-
-		bpf_prog_array_free(desc->bpf.inactive);
-		desc->bpf.inactive = NULL;
-	}
-
-	/* and restore back old_prog */
-	pl->prog = old_prog;
-	return err;
-}
-
-/**
- * __cgroup_bpf_run_filter() - Run a program for packet filtering
- * @sk: The socket sending or receiving traffic
- * @skb: The skb that is being sent or received
- * @type: The type of program to be exectuted
- *
- * If no socket is passed, or the socket is not of type INET or INET6,
- * this function does nothing and returns 0.
- *
- * The program type passed in via @type must be suitable for network
- * filtering. No further check is performed to assert that.
- *
- * This function will return %-EPERM if any if an attached program was found
- * and if it returned != 1 during execution. In all other cases, 0 is returned.
- */
-int __cgroup_bpf_run_filter(struct sock *sk,
-			    struct sk_buff *skb,
-			    enum bpf_attach_type type)
-{
-	unsigned int offset = skb->data - skb_network_header(skb);
-	struct sock *save_sk;
-	struct cgroup *cgrp;
-	int ret;
-
-	if (!sk || !sk_fullsock(sk))
-		return 0;
-
-	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
-		return 0;
-
-	cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
-	save_sk = skb->sk;
-	skb->sk = sk;
-	__skb_push(skb, offset);
-	ret = BPF_PROG_RUN_ARRAY(cgrp->bpf.effective[type], skb,
-				 bpf_prog_run_save_cb);
-	__skb_pull(skb, offset);
-	skb->sk = save_sk;
-	return ret == 1 ? 0 : -EPERM;
-}
-EXPORT_SYMBOL(__cgroup_bpf_run_filter);
diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
index 8def8ae931d9..eb52d11fdaa7 100644
--- a/kernel/bpf/core.c
+++ b/kernel/bpf/core.c
@@ -27,7 +27,6 @@
 #include <linux/random.h>
 #include <linux/moduleloader.h>
 #include <linux/bpf.h>
-#include <linux/frame.h>
 
 #include <asm/unaligned.h>
 
@@ -129,12 +128,14 @@ struct bpf_prog *bpf_prog_realloc(struct bpf_prog *fp_old, unsigned int size,
 
 	return fp;
 }
+EXPORT_SYMBOL_GPL(bpf_prog_realloc);
 
 void __bpf_prog_free(struct bpf_prog *fp)
 {
 	kfree(fp->aux);
 	vfree(fp);
 }
+EXPORT_SYMBOL_GPL(__bpf_prog_free);
 
 static bool bpf_is_jmp_and_has_target(const struct bpf_insn *insn)
 {
@@ -208,83 +209,30 @@ struct bpf_prog *bpf_patch_insn_single(struct bpf_prog *prog, u32 off,
 }
 
 #ifdef CONFIG_BPF_JIT
-/* All BPF JIT sysctl knobs here. */
-int bpf_jit_enable   __read_mostly = IS_BUILTIN(CONFIG_BPF_JIT_ALWAYS_ON);
-int bpf_jit_harden   __read_mostly;
-long bpf_jit_limit   __read_mostly;
-
-static atomic_long_t bpf_jit_current;
-
-/* Can be overridden by an arch's JIT compiler if it has a custom,
- * dedicated BPF backend memory area, or if neither of the two
- * below apply.
- */
-u64 __weak bpf_jit_alloc_exec_limit(void)
-{
-#if defined(MODULES_VADDR)
-	return MODULES_END - MODULES_VADDR;
-#else
-	return VMALLOC_END - VMALLOC_START;
-#endif
-}
-
-static int __init bpf_jit_charge_init(void)
-{
-	/* Only used as heuristic here to derive limit. */
-	bpf_jit_limit = min_t(u64, round_up(bpf_jit_alloc_exec_limit() >> 2,
-					    PAGE_SIZE), LONG_MAX);
-	return 0;
-}
-pure_initcall(bpf_jit_charge_init);
-
-static int bpf_jit_charge_modmem(u32 pages)
-{
-	if (atomic_long_add_return(pages, &bpf_jit_current) >
-	    (bpf_jit_limit >> PAGE_SHIFT)) {
-		if (!capable(CAP_SYS_ADMIN)) {
-			atomic_long_sub(pages, &bpf_jit_current);
-			return -EPERM;
-		}
-	}
-
-	return 0;
-}
-
-static void bpf_jit_uncharge_modmem(u32 pages)
-{
-	atomic_long_sub(pages, &bpf_jit_current);
-}
-
 struct bpf_binary_header *
 bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
 		     unsigned int alignment,
 		     bpf_jit_fill_hole_t bpf_fill_ill_insns)
 {
 	struct bpf_binary_header *hdr;
-	u32 size, hole, start, pages;
+	unsigned int size, hole, start;
 
 	/* Most of BPF filters are really small, but if some of them
 	 * fill a page, allow at least 128 extra bytes to insert a
 	 * random section of illegal instructions.
 	 */
 	size = round_up(proglen + sizeof(*hdr) + 128, PAGE_SIZE);
-	pages = size / PAGE_SIZE;
-
-	if (bpf_jit_charge_modmem(pages))
-		return NULL;
 	hdr = module_alloc(size);
-	if (!hdr) {
-		bpf_jit_uncharge_modmem(pages);
+	if (hdr == NULL)
 		return NULL;
-	}
 
 	/* Fill space with illegal/arch-dep instructions. */
 	bpf_fill_ill_insns(hdr, size);
 
-	hdr->pages = pages;
+	hdr->pages = size / PAGE_SIZE;
 	hole = min_t(unsigned int, size - (proglen + sizeof(*hdr)),
 		     PAGE_SIZE - sizeof(*hdr));
-	start = (get_random_int() % hole) & ~(alignment - 1);
+	start = (prandom_u32() % hole) & ~(alignment - 1);
 
 	/* Leave a random number of instructions before BPF code. */
 	*image_ptr = &hdr->image[start];
@@ -294,211 +242,7 @@ bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
 
 void bpf_jit_binary_free(struct bpf_binary_header *hdr)
 {
-	u32 pages = hdr->pages;
-
 	module_memfree(hdr);
-	bpf_jit_uncharge_modmem(pages);
-}
-
-static int bpf_jit_blind_insn(const struct bpf_insn *from,
-			      const struct bpf_insn *aux,
-			      struct bpf_insn *to_buff)
-{
-	struct bpf_insn *to = to_buff;
-	u32 imm_rnd = get_random_int();
-	s16 off;
-
-	BUILD_BUG_ON(BPF_REG_AX  + 1 != MAX_BPF_JIT_REG);
-	BUILD_BUG_ON(MAX_BPF_REG + 1 != MAX_BPF_JIT_REG);
-
-	if (from->imm == 0 &&
-	    (from->code == (BPF_ALU   | BPF_MOV | BPF_K) ||
-	     from->code == (BPF_ALU64 | BPF_MOV | BPF_K))) {
-		*to++ = BPF_ALU64_REG(BPF_XOR, from->dst_reg, from->dst_reg);
-		goto out;
-	}
-
-	switch (from->code) {
-	case BPF_ALU | BPF_ADD | BPF_K:
-	case BPF_ALU | BPF_SUB | BPF_K:
-	case BPF_ALU | BPF_AND | BPF_K:
-	case BPF_ALU | BPF_OR  | BPF_K:
-	case BPF_ALU | BPF_XOR | BPF_K:
-	case BPF_ALU | BPF_MUL | BPF_K:
-	case BPF_ALU | BPF_MOV | BPF_K:
-	case BPF_ALU | BPF_DIV | BPF_K:
-	case BPF_ALU | BPF_MOD | BPF_K:
-		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
-		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_ALU32_REG(from->code, from->dst_reg, BPF_REG_AX);
-		break;
-
-	case BPF_ALU64 | BPF_ADD | BPF_K:
-	case BPF_ALU64 | BPF_SUB | BPF_K:
-	case BPF_ALU64 | BPF_AND | BPF_K:
-	case BPF_ALU64 | BPF_OR  | BPF_K:
-	case BPF_ALU64 | BPF_XOR | BPF_K:
-	case BPF_ALU64 | BPF_MUL | BPF_K:
-	case BPF_ALU64 | BPF_MOV | BPF_K:
-	case BPF_ALU64 | BPF_DIV | BPF_K:
-	case BPF_ALU64 | BPF_MOD | BPF_K:
-		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
-		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_ALU64_REG(from->code, from->dst_reg, BPF_REG_AX);
-		break;
-
-	case BPF_JMP | BPF_JEQ  | BPF_K:
-	case BPF_JMP | BPF_JNE  | BPF_K:
-	case BPF_JMP | BPF_JGT  | BPF_K:
-	case BPF_JMP | BPF_JGE  | BPF_K:
-	case BPF_JMP | BPF_JSGT | BPF_K:
-	case BPF_JMP | BPF_JSGE | BPF_K:
-	case BPF_JMP | BPF_JSET | BPF_K:
-		/* Accommodate for extra offset in case of a backjump. */
-		off = from->off;
-		if (off < 0)
-			off -= 2;
-		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
-		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_JMP_REG(from->code, from->dst_reg, BPF_REG_AX, off);
-		break;
-
-	case BPF_LD | BPF_ABS | BPF_W:
-	case BPF_LD | BPF_ABS | BPF_H:
-	case BPF_LD | BPF_ABS | BPF_B:
-		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
-		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_LD_IND(from->code, BPF_REG_AX, 0);
-		break;
-
-	case BPF_LD | BPF_IND | BPF_W:
-	case BPF_LD | BPF_IND | BPF_H:
-	case BPF_LD | BPF_IND | BPF_B:
-		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
-		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_ALU32_REG(BPF_ADD, BPF_REG_AX, from->src_reg);
-		*to++ = BPF_LD_IND(from->code, BPF_REG_AX, 0);
-		break;
-
-	case BPF_LD | BPF_IMM | BPF_DW:
-		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ aux[1].imm);
-		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_ALU64_IMM(BPF_LSH, BPF_REG_AX, 32);
-		*to++ = BPF_ALU64_REG(BPF_MOV, aux[0].dst_reg, BPF_REG_AX);
-		break;
-	case 0: /* Part 2 of BPF_LD | BPF_IMM | BPF_DW. */
-		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ aux[0].imm);
-		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_ALU64_REG(BPF_OR,  aux[0].dst_reg, BPF_REG_AX);
-		break;
-
-	case BPF_ST | BPF_MEM | BPF_DW:
-	case BPF_ST | BPF_MEM | BPF_W:
-	case BPF_ST | BPF_MEM | BPF_H:
-	case BPF_ST | BPF_MEM | BPF_B:
-		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
-		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
-		*to++ = BPF_STX_MEM(from->code, from->dst_reg, BPF_REG_AX, from->off);
-		break;
-	}
-out:
-	return to - to_buff;
-}
-
-static struct bpf_prog *bpf_prog_clone_create(struct bpf_prog *fp_other,
-					      gfp_t gfp_extra_flags)
-{
-	gfp_t gfp_flags = GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO |
-			  gfp_extra_flags;
-	struct bpf_prog *fp;
-
-	fp = __vmalloc(fp_other->pages * PAGE_SIZE, gfp_flags, PAGE_KERNEL);
-	if (fp != NULL) {
-		kmemcheck_annotate_bitfield(fp, meta);
-
-		/* aux->prog still points to the fp_other one, so
-		 * when promoting the clone to the real program,
-		 * this still needs to be adapted.
-		 */
-		memcpy(fp, fp_other, fp_other->pages * PAGE_SIZE);
-	}
-
-	return fp;
-}
-
-static void bpf_prog_clone_free(struct bpf_prog *fp)
-{
-	/* aux was stolen by the other clone, so we cannot free
-	 * it from this path! It will be freed eventually by the
-	 * other program on release.
-	 *
-	 * At this point, we don't need a deferred release since
-	 * clone is guaranteed to not be locked.
-	 */
-	fp->aux = NULL;
-	__bpf_prog_free(fp);
-}
-
-void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other)
-{
-	/* We have to repoint aux->prog to self, as we don't
-	 * know whether fp here is the clone or the original.
-	 */
-	fp->aux->prog = fp;
-	bpf_prog_clone_free(fp_other);
-}
-
-struct bpf_prog *bpf_jit_blind_constants(struct bpf_prog *prog)
-{
-	struct bpf_insn insn_buff[16], aux[2];
-	struct bpf_prog *clone, *tmp;
-	int insn_delta, insn_cnt;
-	struct bpf_insn *insn;
-	int i, rewritten;
-
-	if (!bpf_jit_blinding_enabled())
-		return prog;
-
-	clone = bpf_prog_clone_create(prog, GFP_USER);
-	if (!clone)
-		return ERR_PTR(-ENOMEM);
-
-	insn_cnt = clone->len;
-	insn = clone->insnsi;
-
-	for (i = 0; i < insn_cnt; i++, insn++) {
-		/* We temporarily need to hold the original ld64 insn
-		 * so that we can still access the first part in the
-		 * second blinding run.
-		 */
-		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW) &&
-		    insn[1].code == 0)
-			memcpy(aux, insn, sizeof(aux));
-
-		rewritten = bpf_jit_blind_insn(insn, aux, insn_buff);
-		if (!rewritten)
-			continue;
-
-		tmp = bpf_patch_insn_single(clone, i, insn_buff, rewritten);
-		if (!tmp) {
-			/* Patching may have repointed aux->prog during
-			 * realloc from the original one, so we need to
-			 * fix it up here on error.
-			 */
-			bpf_jit_prog_release_other(prog, clone);
-			return ERR_PTR(-ENOMEM);
-		}
-
-		clone = tmp;
-		insn_delta = rewritten - 1;
-
-		/* Walk new program and skip insns we just inserted. */
-		insn = clone->insnsi + i + insn_delta;
-		insn_cnt += insn_delta;
-		i        += insn_delta;
-	}
-
-	return clone;
 }
 #endif /* CONFIG_BPF_JIT */
 
@@ -520,7 +264,7 @@ EXPORT_SYMBOL_GPL(__bpf_call_base);
  *
  * Decode and execute eBPF instructions.
  */
-static unsigned int __bpf_prog_run(const struct sk_buff *ctx, const struct bpf_insn *insn)
+static unsigned int __bpf_prog_run(void *ctx, const struct bpf_insn *insn)
 {
 	u64 stack[MAX_BPF_STACK / sizeof(u64)];
 	u64 regs[MAX_BPF_REG], tmp;
@@ -634,6 +378,10 @@ static unsigned int __bpf_prog_run(const struct sk_buff *ctx, const struct bpf_i
 	FP = (u64) (unsigned long) &stack[ARRAY_SIZE(stack)];
 	ARG1 = (u64) (unsigned long) ctx;
 
+	/* Registers used in classic BPF programs need to be reset first. */
+	regs[BPF_REG_A] = 0;
+	regs[BPF_REG_X] = 0;
+
 select_insn:
 	goto *jumptable[insn->code];
 
@@ -774,13 +522,14 @@ select_insn:
 
 		if (unlikely(index >= array->map.max_entries))
 			goto out;
+
 		if (unlikely(tail_call_cnt > MAX_TAIL_CALL_CNT))
 			goto out;
 
 		tail_call_cnt++;
 
 		prog = READ_ONCE(array->ptrs[index]);
-		if (!prog)
+		if (unlikely(!prog))
 			goto out;
 
 		/* ARG1 at this point is guaranteed to point to CTX from
@@ -976,16 +725,10 @@ load_byte:
 		WARN_RATELIMIT(1, "unknown opcode %02x\n", insn->code);
 		return 0;
 }
-STACK_FRAME_NON_STANDARD(__bpf_prog_run); /* jump table */
 
 #else
-static unsigned int __bpf_prog_ret0_warn(void *ctx,
-					 const struct bpf_insn *insn)
+static unsigned int __bpf_prog_ret0(void *ctx, const struct bpf_insn *insn)
 {
-	/* If this handler ever gets executed, then BPF_JIT_ALWAYS_ON
-	 * is not working properly, so warn about it!
-	 */
-	WARN_ON_ONCE(1);
 	return 0;
 }
 #endif
@@ -1030,17 +773,16 @@ static int bpf_check_tail_call(const struct bpf_prog *fp)
 /**
  *	bpf_prog_select_runtime - select exec runtime for BPF program
  *	@fp: bpf_prog populated with internal BPF program
- *	@err: pointer to error variable
  *
  * Try to JIT eBPF program, if JIT is not available, use interpreter.
  * The BPF program will be executed via BPF_PROG_RUN() macro.
  */
-struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err)
+int bpf_prog_select_runtime(struct bpf_prog *fp)
 {
 #ifndef CONFIG_BPF_JIT_ALWAYS_ON
 	fp->bpf_func = (void *) __bpf_prog_run;
 #else
-	fp->bpf_func = (void *) __bpf_prog_ret0_warn;
+	fp->bpf_func = (void *) __bpf_prog_ret0;
 #endif
 
 	/* eBPF JITs can rewrite the program in case constant
@@ -1049,12 +791,10 @@ struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err)
 	 * valid program, which in this case would simply not
 	 * be JITed, but falls back to the interpreter.
 	 */
-	fp = bpf_int_jit_compile(fp);
+	bpf_int_jit_compile(fp);
 #ifdef CONFIG_BPF_JIT_ALWAYS_ON
-	if (!fp->jited) {
-		*err = -ENOTSUPP;
-		return fp;
-	}
+	if (!fp->jited)
+		return -ENOTSUPP;
 #endif
 	bpf_prog_lock_ro(fp);
 
@@ -1063,124 +803,10 @@ struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err)
 	 * with JITed or non JITed program concatenations and not
 	 * all eBPF JITs might immediately support all features.
 	 */
-	*err = bpf_check_tail_call(fp);
-
-	return fp;
+	return bpf_check_tail_call(fp);
 }
 EXPORT_SYMBOL_GPL(bpf_prog_select_runtime);
 
-static unsigned int __bpf_prog_ret1(const struct sk_buff *ctx,
-				    const struct bpf_insn *insn)
-{
-	return 1;
-}
-
-static struct bpf_prog_dummy {
-	struct bpf_prog prog;
-} dummy_bpf_prog = {
-	.prog = {
-		.bpf_func = __bpf_prog_ret1,
-	},
-};
-
-/* to avoid allocating empty bpf_prog_array for cgroups that
- * don't have bpf program attached use one global 'empty_prog_array'
- * It will not be modified the caller of bpf_prog_array_alloc()
- * (since caller requested prog_cnt == 0)
- * that pointer should be 'freed' by bpf_prog_array_free()
- */
-static struct {
-	struct bpf_prog_array hdr;
-	struct bpf_prog *null_prog;
-} empty_prog_array = {
-	.null_prog = NULL,
-};
-
-struct bpf_prog_array __rcu *bpf_prog_array_alloc(u32 prog_cnt, gfp_t flags)
-{
-	if (prog_cnt)
-		return kzalloc(sizeof(struct bpf_prog_array) +
-			       sizeof(struct bpf_prog *) * (prog_cnt + 1),
-			       flags);
-
-	return &empty_prog_array.hdr;
-}
-
-void bpf_prog_array_free(struct bpf_prog_array __rcu *progs)
-{
-	if (!progs ||
-	    progs == (struct bpf_prog_array __rcu *)&empty_prog_array.hdr)
-		return;
-	kfree_rcu(progs, rcu);
-}
-
-void bpf_prog_array_delete_safe(struct bpf_prog_array __rcu *progs,
-				struct bpf_prog *old_prog)
-{
-	struct bpf_prog **prog = progs->progs;
-
-	for (; *prog; prog++)
-		if (*prog == old_prog) {
-			WRITE_ONCE(*prog, &dummy_bpf_prog.prog);
-			break;
-		}
-}
-
-int bpf_prog_array_copy(struct bpf_prog_array __rcu *old_array,
-			struct bpf_prog *exclude_prog,
-			struct bpf_prog *include_prog,
-			struct bpf_prog_array **new_array)
-{
-	int new_prog_cnt, carry_prog_cnt = 0;
-	struct bpf_prog **existing_prog;
-	struct bpf_prog_array *array;
-	int new_prog_idx = 0;
-
-	/* Figure out how many existing progs we need to carry over to
-	 * the new array.
-	 */
-	if (old_array) {
-		existing_prog = old_array->progs;
-		for (; *existing_prog; existing_prog++) {
-			if (*existing_prog != exclude_prog &&
-			    *existing_prog != &dummy_bpf_prog.prog)
-				carry_prog_cnt++;
-			if (*existing_prog == include_prog)
-				return -EEXIST;
-		}
-	}
-
-	/* How many progs (not NULL) will be in the new array? */
-	new_prog_cnt = carry_prog_cnt;
-	if (include_prog)
-		new_prog_cnt += 1;
-
-	/* Do we have any prog (not NULL) in the new array? */
-	if (!new_prog_cnt) {
-		*new_array = NULL;
-		return 0;
-	}
-
-	/* +1 as the end of prog_array is marked with NULL */
-	array = bpf_prog_array_alloc(new_prog_cnt + 1, GFP_KERNEL);
-	if (!array)
-		return -ENOMEM;
-
-	/* Fill in the new prog array */
-	if (carry_prog_cnt) {
-		existing_prog = old_array->progs;
-		for (; *existing_prog; existing_prog++)
-			if (*existing_prog != exclude_prog &&
-			    *existing_prog != &dummy_bpf_prog.prog)
-				array->progs[new_prog_idx++] = *existing_prog;
-	}
-	if (include_prog)
-		array->progs[new_prog_idx++] = include_prog;
-	array->progs[new_prog_idx] = NULL;
-	*new_array = array;
-	return 0;
-}
-
 static void bpf_prog_free_deferred(struct work_struct *work)
 {
 	struct bpf_prog_aux *aux;
@@ -1207,7 +833,7 @@ void bpf_user_rnd_init_once(void)
 	prandom_init_once(&bpf_user_rnd_state);
 }
 
-BPF_CALL_0(bpf_user_rnd_u32)
+u64 bpf_user_rnd_u32(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
 	/* Should someone ever have the rather unwise idea to use some
 	 * of the registers passed into this function, then note that
@@ -1220,7 +846,7 @@ BPF_CALL_0(bpf_user_rnd_u32)
 
 	state = &get_cpu_var(bpf_user_rnd_state);
 	res = prandom_u32_state(state);
-	put_cpu_var(bpf_user_rnd_state);
+	put_cpu_var(state);
 
 	return res;
 }
@@ -1233,23 +859,14 @@ const struct bpf_func_proto bpf_map_delete_elem_proto __weak;
 const struct bpf_func_proto bpf_get_prandom_u32_proto __weak;
 const struct bpf_func_proto bpf_get_smp_processor_id_proto __weak;
 const struct bpf_func_proto bpf_ktime_get_ns_proto __weak;
-
 const struct bpf_func_proto bpf_get_current_pid_tgid_proto __weak;
 const struct bpf_func_proto bpf_get_current_uid_gid_proto __weak;
 const struct bpf_func_proto bpf_get_current_comm_proto __weak;
-
 const struct bpf_func_proto * __weak bpf_get_trace_printk_proto(void)
 {
 	return NULL;
 }
 
-u64 __weak
-bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
-		 void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy)
-{
-	return -ENOTSUPP;
-}
-
 /* Always built-in helper functions. */
 const struct bpf_func_proto bpf_tail_call_proto = {
 	.func		= NULL,
@@ -1261,14 +878,8 @@ const struct bpf_func_proto bpf_tail_call_proto = {
 };
 
 /* For classic BPF JITs that don't implement bpf_int_jit_compile(). */
-struct bpf_prog * __weak bpf_int_jit_compile(struct bpf_prog *prog)
-{
-	return prog;
-}
-
-bool __weak bpf_helper_changes_skb_data(void *func)
+void __weak bpf_int_jit_compile(struct bpf_prog *prog)
 {
-	return false;
 }
 
 /* To execute LD_ABS/LD_IND instructions __bpf_prog_run() may call
diff --git a/kernel/bpf/hashtab.c b/kernel/bpf/hashtab.c
index b6e2bfd3491e..a35abe048239 100644
--- a/kernel/bpf/hashtab.c
+++ b/kernel/bpf/hashtab.c
@@ -1,5 +1,4 @@
 /* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
- * Copyright (c) 2016 Facebook
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -13,170 +12,39 @@
 #include <linux/bpf.h>
 #include <linux/jhash.h>
 #include <linux/filter.h>
-#include <linux/rculist_nulls.h>
-#include "percpu_freelist.h"
-#define HTAB_CREATE_FLAG_MASK						\
-	(BPF_F_NO_PREALLOC | BPF_F_RDONLY | BPF_F_WRONLY)
-
-struct bucket {
-	struct hlist_nulls_head head;
-	raw_spinlock_t lock;
-};
+#include <linux/vmalloc.h>
 
 struct bpf_htab {
 	struct bpf_map map;
-	struct bucket *buckets;
-	void *elems;
-	struct pcpu_freelist freelist;
-	void __percpu *extra_elems;
-	atomic_t count;	/* number of elements in this hashtable */
+	struct hlist_head *buckets;
+	raw_spinlock_t lock;
+	u32 count;	/* number of elements in this hashtable */
 	u32 n_buckets;	/* number of hash buckets */
 	u32 elem_size;	/* size of each element in bytes */
 };
 
-enum extra_elem_state {
-	HTAB_NOT_AN_EXTRA_ELEM = 0,
-	HTAB_EXTRA_ELEM_FREE,
-	HTAB_EXTRA_ELEM_USED
-};
-
 /* each htab element is struct htab_elem + key + value */
 struct htab_elem {
-	union {
-		struct hlist_nulls_node hash_node;
-		struct {
-			void *padding;
-			union {
-				struct bpf_htab *htab;
-				struct pcpu_freelist_node fnode;
-			};
-		};
-	};
-	union {
-		struct rcu_head rcu;
-		enum extra_elem_state state;
-	};
+	struct hlist_node hash_node;
+	struct rcu_head rcu;
 	u32 hash;
 	char key[0] __aligned(8);
 };
 
-static inline void htab_elem_set_ptr(struct htab_elem *l, u32 key_size,
-				     void __percpu *pptr)
-{
-	*(void __percpu **)(l->key + key_size) = pptr;
-}
-
-static inline void __percpu *htab_elem_get_ptr(struct htab_elem *l, u32 key_size)
-{
-	return *(void __percpu **)(l->key + key_size);
-}
-
-static struct htab_elem *get_htab_elem(struct bpf_htab *htab, int i)
-{
-	return (struct htab_elem *) (htab->elems + i * htab->elem_size);
-}
-
-static void htab_free_elems(struct bpf_htab *htab)
-{
-	int i;
-
-	if (htab->map.map_type != BPF_MAP_TYPE_PERCPU_HASH)
-		goto free_elems;
-
-	for (i = 0; i < htab->map.max_entries; i++) {
-		void __percpu *pptr;
-
-		pptr = htab_elem_get_ptr(get_htab_elem(htab, i),
-					 htab->map.key_size);
-		free_percpu(pptr);
-	}
-free_elems:
-	bpf_map_area_free(htab->elems);
-}
-
-static int prealloc_elems_and_freelist(struct bpf_htab *htab)
-{
-	int err = -ENOMEM, i;
-
-	htab->elems = bpf_map_area_alloc(htab->elem_size *
-					 htab->map.max_entries);
-	if (!htab->elems)
-		return -ENOMEM;
-
-	if (htab->map.map_type != BPF_MAP_TYPE_PERCPU_HASH)
-		goto skip_percpu_elems;
-
-	for (i = 0; i < htab->map.max_entries; i++) {
-		u32 size = round_up(htab->map.value_size, 8);
-		void __percpu *pptr;
-
-		pptr = __alloc_percpu_gfp(size, 8, GFP_USER | __GFP_NOWARN);
-		if (!pptr)
-			goto free_elems;
-		htab_elem_set_ptr(get_htab_elem(htab, i), htab->map.key_size,
-				  pptr);
-	}
-
-skip_percpu_elems:
-	err = pcpu_freelist_init(&htab->freelist);
-	if (err)
-		goto free_elems;
-
-	pcpu_freelist_populate(&htab->freelist,
-			       htab->elems + offsetof(struct htab_elem, fnode),
-			       htab->elem_size, htab->map.max_entries);
-
-	return 0;
-
-free_elems:
-	htab_free_elems(htab);
-	return err;
-}
-
-static int alloc_extra_elems(struct bpf_htab *htab)
-{
-	void __percpu *pptr;
-	int cpu;
-
-	pptr = __alloc_percpu_gfp(htab->elem_size, 8, GFP_USER | __GFP_NOWARN);
-	if (!pptr)
-		return -ENOMEM;
-
-	for_each_possible_cpu(cpu) {
-		((struct htab_elem *)per_cpu_ptr(pptr, cpu))->state =
-			HTAB_EXTRA_ELEM_FREE;
-	}
-	htab->extra_elems = pptr;
-	return 0;
-}
-
 /* Called from syscall */
 static struct bpf_map *htab_map_alloc(union bpf_attr *attr)
 {
-	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_HASH;
 	struct bpf_htab *htab;
 	int err, i;
-	u64 cost;
-
-	BUILD_BUG_ON(offsetof(struct htab_elem, htab) !=
-		     offsetof(struct htab_elem, hash_node.pprev));
-	BUILD_BUG_ON(offsetof(struct htab_elem, fnode.next) !=
-		     offsetof(struct htab_elem, hash_node.pprev));
-
-	if (attr->map_flags & ~HTAB_CREATE_FLAG_MASK)
-		/* reserved bits should not be used */
-		return ERR_PTR(-EINVAL);
 
 	htab = kzalloc(sizeof(*htab), GFP_USER);
 	if (!htab)
 		return ERR_PTR(-ENOMEM);
 
 	/* mandatory map attributes */
-	htab->map.map_type = attr->map_type;
 	htab->map.key_size = attr->key_size;
 	htab->map.value_size = attr->value_size;
 	htab->map.max_entries = attr->max_entries;
-	htab->map.map_flags = attr->map_flags;
 
 	/* check sanity of attributes.
 	 * value_size == 0 may be allowed in the future to use map as a set
@@ -205,71 +73,43 @@ static struct bpf_map *htab_map_alloc(union bpf_attr *attr)
 		 */
 		goto free_htab;
 
-	if (percpu && round_up(htab->map.value_size, 8) > PCPU_MIN_UNIT_SIZE)
-		/* make sure the size for pcpu_alloc() is reasonable */
-		goto free_htab;
-
 	htab->elem_size = sizeof(struct htab_elem) +
-			  round_up(htab->map.key_size, 8);
-	if (percpu)
-		htab->elem_size += sizeof(void *);
-	else
-		htab->elem_size += round_up(htab->map.value_size, 8);
+			  round_up(htab->map.key_size, 8) +
+			  htab->map.value_size;
 
 	/* prevent zero size kmalloc and check for u32 overflow */
 	if (htab->n_buckets == 0 ||
-	    htab->n_buckets > U32_MAX / sizeof(struct bucket))
+	    htab->n_buckets > U32_MAX / sizeof(struct hlist_head))
 		goto free_htab;
 
-	cost = (u64) htab->n_buckets * sizeof(struct bucket) +
-	       (u64) htab->elem_size * htab->map.max_entries;
-
-	if (percpu)
-		cost += (u64) round_up(htab->map.value_size, 8) *
-			num_possible_cpus() * htab->map.max_entries;
-	else
-	       cost += (u64) htab->elem_size * num_possible_cpus();
-
-	if (cost >= U32_MAX - PAGE_SIZE)
+	if ((u64) htab->n_buckets * sizeof(struct hlist_head) +
+	    (u64) htab->elem_size * htab->map.max_entries >=
+	    U32_MAX - PAGE_SIZE)
 		/* make sure page count doesn't overflow */
 		goto free_htab;
 
-	htab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
-
-	/* if map size is larger than memlock limit, reject it early */
-	err = bpf_map_precharge_memlock(htab->map.pages);
-	if (err)
-		goto free_htab;
+	htab->map.pages = round_up(htab->n_buckets * sizeof(struct hlist_head) +
+				   htab->elem_size * htab->map.max_entries,
+				   PAGE_SIZE) >> PAGE_SHIFT;
 
 	err = -ENOMEM;
-	htab->buckets = bpf_map_area_alloc(htab->n_buckets *
-					   sizeof(struct bucket));
-	if (!htab->buckets)
-		goto free_htab;
+	htab->buckets = kmalloc_array(htab->n_buckets, sizeof(struct hlist_head),
+				      GFP_USER | __GFP_NOWARN);
 
-	for (i = 0; i < htab->n_buckets; i++) {
-		INIT_HLIST_NULLS_HEAD(&htab->buckets[i].head, i);
-		raw_spin_lock_init(&htab->buckets[i].lock);
+	if (!htab->buckets) {
+		htab->buckets = vmalloc(htab->n_buckets * sizeof(struct hlist_head));
+		if (!htab->buckets)
+			goto free_htab;
 	}
 
-	if (!percpu) {
-		err = alloc_extra_elems(htab);
-		if (err)
-			goto free_buckets;
-	}
+	for (i = 0; i < htab->n_buckets; i++)
+		INIT_HLIST_HEAD(&htab->buckets[i]);
 
-	if (!(attr->map_flags & BPF_F_NO_PREALLOC)) {
-		err = prealloc_elems_and_freelist(htab);
-		if (err)
-			goto free_extra_elems;
-	}
+	raw_spin_lock_init(&htab->lock);
+	htab->count = 0;
 
 	return &htab->map;
 
-free_extra_elems:
-	free_percpu(htab->extra_elems);
-free_buckets:
-	bpf_map_area_free(htab->buckets);
 free_htab:
 	kfree(htab);
 	return ERR_PTR(err);
@@ -280,57 +120,28 @@ static inline u32 htab_map_hash(const void *key, u32 key_len)
 	return jhash(key, key_len, 0);
 }
 
-static inline struct bucket *__select_bucket(struct bpf_htab *htab, u32 hash)
+static inline struct hlist_head *select_bucket(struct bpf_htab *htab, u32 hash)
 {
 	return &htab->buckets[hash & (htab->n_buckets - 1)];
 }
 
-static inline struct hlist_nulls_head *select_bucket(struct bpf_htab *htab, u32 hash)
-{
-	return &__select_bucket(htab, hash)->head;
-}
-
-/* this lookup function can only be called with bucket lock taken */
-static struct htab_elem *lookup_elem_raw(struct hlist_nulls_head *head, u32 hash,
+static struct htab_elem *lookup_elem_raw(struct hlist_head *head, u32 hash,
 					 void *key, u32 key_size)
 {
-	struct hlist_nulls_node *n;
 	struct htab_elem *l;
 
-	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
+	hlist_for_each_entry_rcu(l, head, hash_node)
 		if (l->hash == hash && !memcmp(&l->key, key, key_size))
 			return l;
 
 	return NULL;
 }
 
-/* can be called without bucket lock. it will repeat the loop in
- * the unlikely event when elements moved from one bucket into another
- * while link list is being walked
- */
-static struct htab_elem *lookup_nulls_elem_raw(struct hlist_nulls_head *head,
-					       u32 hash, void *key,
-					       u32 key_size, u32 n_buckets)
-{
-	struct hlist_nulls_node *n;
-	struct htab_elem *l;
-
-again:
-	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
-		if (l->hash == hash && !memcmp(&l->key, key, key_size))
-			return l;
-
-	if (unlikely(get_nulls_value(n) != (hash & (n_buckets - 1))))
-		goto again;
-
-	return NULL;
-}
-
 /* Called from syscall or from eBPF program */
-static void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
+static void *htab_map_lookup_elem(struct bpf_map *map, void *key)
 {
 	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
-	struct hlist_nulls_head *head;
+	struct hlist_head *head;
 	struct htab_elem *l;
 	u32 hash, key_size;
 
@@ -343,14 +154,7 @@ static void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
 
 	head = select_bucket(htab, hash);
 
-	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);
-
-	return l;
-}
-
-static void *htab_map_lookup_elem(struct bpf_map *map, void *key)
-{
-	struct htab_elem *l = __htab_map_lookup_elem(map, key);
+	l = lookup_elem_raw(head, hash, key, key_size);
 
 	if (l)
 		return l->key + round_up(map->key_size, 8);
@@ -362,7 +166,7 @@ static void *htab_map_lookup_elem(struct bpf_map *map, void *key)
 static int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
 {
 	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
-	struct hlist_nulls_head *head;
+	struct hlist_head *head;
 	struct htab_elem *l, *next_l;
 	u32 hash, key_size;
 	int i = 0;
@@ -379,13 +183,13 @@ static int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
 	head = select_bucket(htab, hash);
 
 	/* lookup the key */
-	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);
+	l = lookup_elem_raw(head, hash, key, key_size);
 
 	if (!l)
 		goto find_first_elem;
 
 	/* key was found, get next key in the same bucket */
-	next_l = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_next_rcu(&l->hash_node)),
+	next_l = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&l->hash_node)),
 				  struct htab_elem, hash_node);
 
 	if (next_l) {
@@ -404,7 +208,7 @@ find_first_elem:
 		head = select_bucket(htab, i);
 
 		/* pick first element in the bucket */
-		next_l = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_first_rcu(head)),
+		next_l = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
 					  struct htab_elem, hash_node);
 		if (next_l) {
 			/* if it's not empty, just return it */
@@ -413,282 +217,90 @@ find_first_elem:
 		}
 	}
 
-	/* iterated over all buckets and all elements */
+	/* itereated over all buckets and all elements */
 	return -ENOENT;
 }
 
-static void htab_elem_free(struct bpf_htab *htab, struct htab_elem *l)
-{
-	if (htab->map.map_type == BPF_MAP_TYPE_PERCPU_HASH)
-		free_percpu(htab_elem_get_ptr(l, htab->map.key_size));
-	kfree(l);
-}
-
-static void htab_elem_free_rcu(struct rcu_head *head)
-{
-	struct htab_elem *l = container_of(head, struct htab_elem, rcu);
-	struct bpf_htab *htab = l->htab;
-
-	/* must increment bpf_prog_active to avoid kprobe+bpf triggering while
-	 * we're calling kfree, otherwise deadlock is possible if kprobes
-	 * are placed somewhere inside of slub
-	 */
-	preempt_disable();
-	__this_cpu_inc(bpf_prog_active);
-	htab_elem_free(htab, l);
-	__this_cpu_dec(bpf_prog_active);
-	preempt_enable();
-}
-
-static void free_htab_elem(struct bpf_htab *htab, struct htab_elem *l)
-{
-	if (l->state == HTAB_EXTRA_ELEM_USED) {
-		l->state = HTAB_EXTRA_ELEM_FREE;
-		return;
-	}
-
-	if (!(htab->map.map_flags & BPF_F_NO_PREALLOC)) {
-		pcpu_freelist_push(&htab->freelist, &l->fnode);
-	} else {
-		atomic_dec(&htab->count);
-		l->htab = htab;
-		call_rcu(&l->rcu, htab_elem_free_rcu);
-	}
-}
-
-static struct htab_elem *alloc_htab_elem(struct bpf_htab *htab, void *key,
-					 void *value, u32 key_size, u32 hash,
-					 bool percpu, bool onallcpus,
-					 bool old_elem_exists)
-{
-	u32 size = htab->map.value_size;
-	bool prealloc = !(htab->map.map_flags & BPF_F_NO_PREALLOC);
-	struct htab_elem *l_new;
-	void __percpu *pptr;
-	int err = 0;
-
-	if (prealloc) {
-		struct pcpu_freelist_node *l;
-
-		l = pcpu_freelist_pop(&htab->freelist);
-		if (!l)
-			err = -E2BIG;
-		else
-			l_new = container_of(l, struct htab_elem, fnode);
-	} else {
-		if (atomic_inc_return(&htab->count) > htab->map.max_entries) {
-			atomic_dec(&htab->count);
-			err = -E2BIG;
-		} else {
-			l_new = kmalloc(htab->elem_size,
-					GFP_ATOMIC | __GFP_NOWARN);
-			if (!l_new)
-				return ERR_PTR(-ENOMEM);
-		}
-	}
-
-	if (err) {
-		if (!old_elem_exists)
-			return ERR_PTR(err);
-
-		/* if we're updating the existing element and the hash table
-		 * is full, use per-cpu extra elems
-		 */
-		l_new = this_cpu_ptr(htab->extra_elems);
-		if (l_new->state != HTAB_EXTRA_ELEM_FREE)
-			return ERR_PTR(-E2BIG);
-		l_new->state = HTAB_EXTRA_ELEM_USED;
-	} else {
-		l_new->state = HTAB_NOT_AN_EXTRA_ELEM;
-	}
-
-	memcpy(l_new->key, key, key_size);
-	if (percpu) {
-		/* round up value_size to 8 bytes */
-		size = round_up(size, 8);
-
-		if (prealloc) {
-			pptr = htab_elem_get_ptr(l_new, key_size);
-		} else {
-			/* alloc_percpu zero-fills */
-			pptr = __alloc_percpu_gfp(size, 8,
-						  GFP_ATOMIC | __GFP_NOWARN);
-			if (!pptr) {
-				kfree(l_new);
-				return ERR_PTR(-ENOMEM);
-			}
-		}
-
-		if (!onallcpus) {
-			/* copy true value_size bytes */
-			memcpy(this_cpu_ptr(pptr), value, htab->map.value_size);
-		} else {
-			int off = 0, cpu;
-
-			for_each_possible_cpu(cpu) {
-				bpf_long_memcpy(per_cpu_ptr(pptr, cpu),
-						value + off, size);
-				off += size;
-			}
-		}
-		if (!prealloc)
-			htab_elem_set_ptr(l_new, key_size, pptr);
-	} else {
-		memcpy(l_new->key + round_up(key_size, 8), value, size);
-	}
-
-	l_new->hash = hash;
-	return l_new;
-}
-
-static int check_flags(struct bpf_htab *htab, struct htab_elem *l_old,
-		       u64 map_flags)
-{
-	if (l_old && map_flags == BPF_NOEXIST)
-		/* elem already exists */
-		return -EEXIST;
-
-	if (!l_old && map_flags == BPF_EXIST)
-		/* elem doesn't exist, cannot update it */
-		return -ENOENT;
-
-	return 0;
-}
-
 /* Called from syscall or from eBPF program */
 static int htab_map_update_elem(struct bpf_map *map, void *key, void *value,
 				u64 map_flags)
 {
 	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
-	struct htab_elem *l_new = NULL, *l_old;
-	struct hlist_nulls_head *head;
+	struct htab_elem *l_new, *l_old;
+	struct hlist_head *head;
 	unsigned long flags;
-	struct bucket *b;
-	u32 key_size, hash;
+	u32 key_size;
 	int ret;
 
-	if (unlikely(map_flags > BPF_EXIST))
+	if (map_flags > BPF_EXIST)
 		/* unknown flags */
 		return -EINVAL;
 
 	WARN_ON_ONCE(!rcu_read_lock_held());
 
+	/* allocate new element outside of lock */
+	l_new = kmalloc(htab->elem_size, GFP_ATOMIC | __GFP_NOWARN);
+	if (!l_new)
+		return -ENOMEM;
+
 	key_size = map->key_size;
 
-	hash = htab_map_hash(key, key_size);
+	memcpy(l_new->key, key, key_size);
+	memcpy(l_new->key + round_up(key_size, 8), value, map->value_size);
 
-	b = __select_bucket(htab, hash);
-	head = &b->head;
+	l_new->hash = htab_map_hash(l_new->key, key_size);
 
 	/* bpf_map_update_elem() can be called in_irq() */
-	raw_spin_lock_irqsave(&b->lock, flags);
+	raw_spin_lock_irqsave(&htab->lock, flags);
 
-	l_old = lookup_elem_raw(head, hash, key, key_size);
+	head = select_bucket(htab, l_new->hash);
 
-	ret = check_flags(htab, l_old, map_flags);
-	if (ret)
-		goto err;
+	l_old = lookup_elem_raw(head, l_new->hash, key, key_size);
 
-	l_new = alloc_htab_elem(htab, key, value, key_size, hash, false, false,
-				!!l_old);
-	if (IS_ERR(l_new)) {
-		/* all pre-allocated elements are in use or memory exhausted */
-		ret = PTR_ERR(l_new);
+	if (!l_old && unlikely(htab->count >= map->max_entries)) {
+		/* if elem with this 'key' doesn't exist and we've reached
+		 * max_entries limit, fail insertion of new elem
+		 */
+		ret = -E2BIG;
 		goto err;
 	}
 
-	/* add new element to the head of the list, so that
-	 * concurrent search will find it before old elem
-	 */
-	hlist_nulls_add_head_rcu(&l_new->hash_node, head);
-	if (l_old) {
-		hlist_nulls_del_rcu(&l_old->hash_node);
-		free_htab_elem(htab, l_old);
+	if (l_old && map_flags == BPF_NOEXIST) {
+		/* elem already exists */
+		ret = -EEXIST;
+		goto err;
 	}
-	ret = 0;
-err:
-	raw_spin_unlock_irqrestore(&b->lock, flags);
-	return ret;
-}
-
-static int __htab_percpu_map_update_elem(struct bpf_map *map, void *key,
-					 void *value, u64 map_flags,
-					 bool onallcpus)
-{
-	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
-	struct htab_elem *l_new = NULL, *l_old;
-	struct hlist_nulls_head *head;
-	unsigned long flags;
-	struct bucket *b;
-	u32 key_size, hash;
-	int ret;
-
-	if (unlikely(map_flags > BPF_EXIST))
-		/* unknown flags */
-		return -EINVAL;
-
-	WARN_ON_ONCE(!rcu_read_lock_held());
-
-	key_size = map->key_size;
-
-	hash = htab_map_hash(key, key_size);
 
-	b = __select_bucket(htab, hash);
-	head = &b->head;
-
-	/* bpf_map_update_elem() can be called in_irq() */
-	raw_spin_lock_irqsave(&b->lock, flags);
-
-	l_old = lookup_elem_raw(head, hash, key, key_size);
-
-	ret = check_flags(htab, l_old, map_flags);
-	if (ret)
+	if (!l_old && map_flags == BPF_EXIST) {
+		/* elem doesn't exist, cannot update it */
+		ret = -ENOENT;
 		goto err;
+	}
 
+	/* add new element to the head of the list, so that concurrent
+	 * search will find it before old elem
+	 */
+	hlist_add_head_rcu(&l_new->hash_node, head);
 	if (l_old) {
-		void __percpu *pptr = htab_elem_get_ptr(l_old, key_size);
-		u32 size = htab->map.value_size;
-
-		/* per-cpu hash map can update value in-place */
-		if (!onallcpus) {
-			memcpy(this_cpu_ptr(pptr), value, size);
-		} else {
-			int off = 0, cpu;
-
-			size = round_up(size, 8);
-			for_each_possible_cpu(cpu) {
-				bpf_long_memcpy(per_cpu_ptr(pptr, cpu),
-						value + off, size);
-				off += size;
-			}
-		}
+		hlist_del_rcu(&l_old->hash_node);
+		kfree_rcu(l_old, rcu);
 	} else {
-		l_new = alloc_htab_elem(htab, key, value, key_size,
-					hash, true, onallcpus, false);
-		if (IS_ERR(l_new)) {
-			ret = PTR_ERR(l_new);
-			goto err;
-		}
-		hlist_nulls_add_head_rcu(&l_new->hash_node, head);
+		htab->count++;
 	}
-	ret = 0;
+	raw_spin_unlock_irqrestore(&htab->lock, flags);
+
+	return 0;
 err:
-	raw_spin_unlock_irqrestore(&b->lock, flags);
+	raw_spin_unlock_irqrestore(&htab->lock, flags);
+	kfree(l_new);
 	return ret;
 }
 
-static int htab_percpu_map_update_elem(struct bpf_map *map, void *key,
-				       void *value, u64 map_flags)
-{
-	return __htab_percpu_map_update_elem(map, key, value, map_flags, false);
-}
-
 /* Called from syscall or from eBPF program */
 static int htab_map_delete_elem(struct bpf_map *map, void *key)
 {
 	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
-	struct hlist_nulls_head *head;
-	struct bucket *b;
+	struct hlist_head *head;
 	struct htab_elem *l;
 	unsigned long flags;
 	u32 hash, key_size;
@@ -699,20 +311,21 @@ static int htab_map_delete_elem(struct bpf_map *map, void *key)
 	key_size = map->key_size;
 
 	hash = htab_map_hash(key, key_size);
-	b = __select_bucket(htab, hash);
-	head = &b->head;
 
-	raw_spin_lock_irqsave(&b->lock, flags);
+	raw_spin_lock_irqsave(&htab->lock, flags);
+
+	head = select_bucket(htab, hash);
 
 	l = lookup_elem_raw(head, hash, key, key_size);
 
 	if (l) {
-		hlist_nulls_del_rcu(&l->hash_node);
-		free_htab_elem(htab, l);
+		hlist_del_rcu(&l->hash_node);
+		htab->count--;
+		kfree_rcu(l, rcu);
 		ret = 0;
 	}
 
-	raw_spin_unlock_irqrestore(&b->lock, flags);
+	raw_spin_unlock_irqrestore(&htab->lock, flags);
 	return ret;
 }
 
@@ -721,17 +334,18 @@ static void delete_all_elements(struct bpf_htab *htab)
 	int i;
 
 	for (i = 0; i < htab->n_buckets; i++) {
-		struct hlist_nulls_head *head = select_bucket(htab, i);
-		struct hlist_nulls_node *n;
+		struct hlist_head *head = select_bucket(htab, i);
+		struct hlist_node *n;
 		struct htab_elem *l;
 
-		hlist_nulls_for_each_entry_safe(l, n, head, hash_node) {
-			hlist_nulls_del_rcu(&l->hash_node);
-			if (l->state != HTAB_EXTRA_ELEM_USED)
-				htab_elem_free(htab, l);
+		hlist_for_each_entry_safe(l, n, head, hash_node) {
+			hlist_del_rcu(&l->hash_node);
+			htab->count--;
+			kfree(l);
 		}
 	}
 }
+
 /* Called when map->refcnt goes to zero, either from workqueue or from syscall */
 static void htab_map_free(struct bpf_map *map)
 {
@@ -744,18 +358,11 @@ static void htab_map_free(struct bpf_map *map)
 	 */
 	synchronize_rcu();
 
-	/* some of free_htab_elem() callbacks for elements of this map may
-	 * not have executed. Wait for them.
+	/* some of kfree_rcu() callbacks for elements of this map may not have
+	 * executed. It's ok. Proceed to free residual elements and map itself
 	 */
-	rcu_barrier();
-	if (htab->map.map_flags & BPF_F_NO_PREALLOC) {
-		delete_all_elements(htab);
-	} else {
-		htab_free_elems(htab);
-		pcpu_freelist_destroy(&htab->freelist);
-	}
-	free_percpu(htab->extra_elems);
-	bpf_map_area_free(htab->buckets);
+	delete_all_elements(htab);
+	kvfree(htab->buckets);
 	kfree(htab);
 }
 
@@ -773,76 +380,9 @@ static struct bpf_map_type_list htab_type __read_mostly = {
 	.type = BPF_MAP_TYPE_HASH,
 };
 
-/* Called from eBPF program */
-static void *htab_percpu_map_lookup_elem(struct bpf_map *map, void *key)
-{
-	struct htab_elem *l = __htab_map_lookup_elem(map, key);
-
-	if (l)
-		return this_cpu_ptr(htab_elem_get_ptr(l, map->key_size));
-	else
-		return NULL;
-}
-
-int bpf_percpu_hash_copy(struct bpf_map *map, void *key, void *value)
-{
-	struct htab_elem *l;
-	void __percpu *pptr;
-	int ret = -ENOENT;
-	int cpu, off = 0;
-	u32 size;
-
-	/* per_cpu areas are zero-filled and bpf programs can only
-	 * access 'value_size' of them, so copying rounded areas
-	 * will not leak any kernel data
-	 */
-	size = round_up(map->value_size, 8);
-	rcu_read_lock();
-	l = __htab_map_lookup_elem(map, key);
-	if (!l)
-		goto out;
-	pptr = htab_elem_get_ptr(l, map->key_size);
-	for_each_possible_cpu(cpu) {
-		bpf_long_memcpy(value + off,
-				per_cpu_ptr(pptr, cpu), size);
-		off += size;
-	}
-	ret = 0;
-out:
-	rcu_read_unlock();
-	return ret;
-}
-
-int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
-			   u64 map_flags)
-{
-	int ret;
-
-	rcu_read_lock();
-	ret = __htab_percpu_map_update_elem(map, key, value, map_flags, true);
-	rcu_read_unlock();
-
-	return ret;
-}
-
-static const struct bpf_map_ops htab_percpu_ops = {
-	.map_alloc = htab_map_alloc,
-	.map_free = htab_map_free,
-	.map_get_next_key = htab_map_get_next_key,
-	.map_lookup_elem = htab_percpu_map_lookup_elem,
-	.map_update_elem = htab_percpu_map_update_elem,
-	.map_delete_elem = htab_map_delete_elem,
-};
-
-static struct bpf_map_type_list htab_percpu_type __read_mostly = {
-	.ops = &htab_percpu_ops,
-	.type = BPF_MAP_TYPE_PERCPU_HASH,
-};
-
 static int __init register_htab_map(void)
 {
 	bpf_register_map_type(&htab_type);
-	bpf_register_map_type(&htab_percpu_type);
 	return 0;
 }
 late_initcall(register_htab_map);
diff --git a/kernel/bpf/helpers.c b/kernel/bpf/helpers.c
index 39918402e6e9..50da680c479f 100644
--- a/kernel/bpf/helpers.c
+++ b/kernel/bpf/helpers.c
@@ -16,7 +16,6 @@
 #include <linux/ktime.h>
 #include <linux/sched.h>
 #include <linux/uidgid.h>
-#include <linux/filter.h>
 
 /* If kernel subsystem is allowing eBPF programs to call this function,
  * inside its own verifier_ops->get_func_proto() callback it should return
@@ -27,32 +26,48 @@
  * if program is allowed to access maps, so check rcu_read_lock_held in
  * all three functions.
  */
-BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
+static u64 bpf_map_lookup_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
+	/* verifier checked that R1 contains a valid pointer to bpf_map
+	 * and R2 points to a program stack and map->key_size bytes were
+	 * initialized
+	 */
+	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
+	void *key = (void *) (unsigned long) r2;
+	void *value;
+
 	WARN_ON_ONCE(!rcu_read_lock_held());
-	return (unsigned long) map->ops->map_lookup_elem(map, key);
+
+	value = map->ops->map_lookup_elem(map, key);
+
+	/* lookup() returns either pointer to element value or NULL
+	 * which is the meaning of PTR_TO_MAP_VALUE_OR_NULL type
+	 */
+	return (unsigned long) value;
 }
 
 const struct bpf_func_proto bpf_map_lookup_elem_proto = {
 	.func		= bpf_map_lookup_elem,
 	.gpl_only	= false,
-	.pkt_access	= true,
 	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
 	.arg1_type	= ARG_CONST_MAP_PTR,
 	.arg2_type	= ARG_PTR_TO_MAP_KEY,
 };
 
-BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
-	   void *, value, u64, flags)
+static u64 bpf_map_update_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
+	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
+	void *key = (void *) (unsigned long) r2;
+	void *value = (void *) (unsigned long) r3;
+
 	WARN_ON_ONCE(!rcu_read_lock_held());
-	return map->ops->map_update_elem(map, key, value, flags);
+
+	return map->ops->map_update_elem(map, key, value, r4);
 }
 
 const struct bpf_func_proto bpf_map_update_elem_proto = {
 	.func		= bpf_map_update_elem,
 	.gpl_only	= false,
-	.pkt_access	= true,
 	.ret_type	= RET_INTEGER,
 	.arg1_type	= ARG_CONST_MAP_PTR,
 	.arg2_type	= ARG_PTR_TO_MAP_KEY,
@@ -60,16 +75,19 @@ const struct bpf_func_proto bpf_map_update_elem_proto = {
 	.arg4_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_2(bpf_map_delete_elem, struct bpf_map *, map, void *, key)
+static u64 bpf_map_delete_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
+	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
+	void *key = (void *) (unsigned long) r2;
+
 	WARN_ON_ONCE(!rcu_read_lock_held());
+
 	return map->ops->map_delete_elem(map, key);
 }
 
 const struct bpf_func_proto bpf_map_delete_elem_proto = {
 	.func		= bpf_map_delete_elem,
 	.gpl_only	= false,
-	.pkt_access	= true,
 	.ret_type	= RET_INTEGER,
 	.arg1_type	= ARG_CONST_MAP_PTR,
 	.arg2_type	= ARG_PTR_TO_MAP_KEY,
@@ -81,9 +99,9 @@ const struct bpf_func_proto bpf_get_prandom_u32_proto = {
 	.ret_type	= RET_INTEGER,
 };
 
-BPF_CALL_0(bpf_get_smp_processor_id)
+static u64 bpf_get_smp_processor_id(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
-	return smp_processor_id();
+	return raw_smp_processor_id();
 }
 
 const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
@@ -92,7 +110,7 @@ const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
 	.ret_type	= RET_INTEGER,
 };
 
-BPF_CALL_0(bpf_ktime_get_ns)
+static u64 bpf_ktime_get_ns(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
 	/* NMI safe access to clock monotonic */
 	return ktime_get_mono_fast_ns();
@@ -104,11 +122,11 @@ const struct bpf_func_proto bpf_ktime_get_ns_proto = {
 	.ret_type	= RET_INTEGER,
 };
 
-BPF_CALL_0(bpf_get_current_pid_tgid)
+static u64 bpf_get_current_pid_tgid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
 	struct task_struct *task = current;
 
-	if (unlikely(!task))
+	if (!task)
 		return -EINVAL;
 
 	return (u64) task->tgid << 32 | task->pid;
@@ -120,18 +138,18 @@ const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
 	.ret_type	= RET_INTEGER,
 };
 
-BPF_CALL_0(bpf_get_current_uid_gid)
+static u64 bpf_get_current_uid_gid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
 	struct task_struct *task = current;
 	kuid_t uid;
 	kgid_t gid;
 
-	if (unlikely(!task))
+	if (!task)
 		return -EINVAL;
 
 	current_uid_gid(&uid, &gid);
 	return (u64) from_kgid(&init_user_ns, gid) << 32 |
-		     from_kuid(&init_user_ns, uid);
+		from_kuid(&init_user_ns, uid);
 }
 
 const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
@@ -140,30 +158,22 @@ const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
 	.ret_type	= RET_INTEGER,
 };
 
-BPF_CALL_2(bpf_get_current_comm, char *, buf, u32, size)
+static u64 bpf_get_current_comm(u64 r1, u64 size, u64 r3, u64 r4, u64 r5)
 {
 	struct task_struct *task = current;
+	char *buf = (char *) (long) r1;
 
-	if (unlikely(!task))
-		goto err_clear;
-
-	strncpy(buf, task->comm, size);
+	if (!task)
+		return -EINVAL;
 
-	/* Verifier guarantees that size > 0. For task->comm exceeding
-	 * size, guarantee that buf is %NUL-terminated. Unconditionally
-	 * done here to save the size test.
-	 */
-	buf[size - 1] = 0;
+	strlcpy(buf, task->comm, min_t(size_t, size, sizeof(task->comm)));
 	return 0;
-err_clear:
-	memset(buf, 0, size);
-	return -EINVAL;
 }
 
 const struct bpf_func_proto bpf_get_current_comm_proto = {
 	.func		= bpf_get_current_comm,
 	.gpl_only	= false,
 	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_RAW_STACK,
+	.arg1_type	= ARG_PTR_TO_STACK,
 	.arg2_type	= ARG_CONST_STACK_SIZE,
 };
diff --git a/kernel/bpf/inode.c b/kernel/bpf/inode.c
index 5a52c25ba18a..cb85d228b1ac 100644
--- a/kernel/bpf/inode.c
+++ b/kernel/bpf/inode.c
@@ -11,7 +11,7 @@
  * version 2 as published by the Free Software Foundation.
  */
 
-#include <linux/init.h>
+#include <linux/module.h>
 #include <linux/magic.h>
 #include <linux/major.h>
 #include <linux/mount.h>
@@ -119,10 +119,18 @@ static int bpf_inode_type(const struct inode *inode, enum bpf_type *type)
 	return 0;
 }
 
+static bool bpf_dname_reserved(const struct dentry *dentry)
+{
+	return strchr(dentry->d_name.name, '.');
+}
+
 static int bpf_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
 {
 	struct inode *inode;
 
+	if (bpf_dname_reserved(dentry))
+		return -EPERM;
+
 	inode = bpf_get_inode(dir->i_sb, dir, mode | S_IFDIR);
 	if (IS_ERR(inode))
 		return PTR_ERR(inode);
@@ -144,6 +152,9 @@ static int bpf_mkobj_ops(struct inode *dir, struct dentry *dentry,
 {
 	struct inode *inode;
 
+	if (bpf_dname_reserved(dentry))
+		return -EPERM;
+
 	inode = bpf_get_inode(dir->i_sb, dir, mode | S_IFREG);
 	if (IS_ERR(inode))
 		return PTR_ERR(inode);
@@ -176,21 +187,11 @@ static int bpf_mkobj(struct inode *dir, struct dentry *dentry, umode_t mode,
 	}
 }
 
-static struct dentry *
-bpf_lookup(struct inode *dir, struct dentry *dentry, unsigned flags)
-{
-	if (strchr(dentry->d_name.name, '.'))
-		return ERR_PTR(-EPERM);
-	return simple_lookup(dir, dentry, flags);
-}
-
 static const struct inode_operations bpf_dir_iops = {
-	.lookup		= bpf_lookup,
+	.lookup		= simple_lookup,
 	.mknod		= bpf_mkobj,
 	.mkdir		= bpf_mkdir,
 	.rmdir		= simple_rmdir,
-	.rename		= simple_rename,
-	.link		= simple_link,
 	.unlink		= simple_unlink,
 };
 
@@ -255,7 +256,7 @@ out:
 }
 
 static void *bpf_obj_do_get(const struct filename *pathname,
-			    enum bpf_type *type, int flags)
+			    enum bpf_type *type)
 {
 	struct inode *inode;
 	struct path path;
@@ -267,7 +268,7 @@ static void *bpf_obj_do_get(const struct filename *pathname,
 		return ERR_PTR(ret);
 
 	inode = d_backing_inode(path.dentry);
-	ret = inode_permission(inode, ACC_MODE(flags));
+	ret = inode_permission(inode, MAY_WRITE);
 	if (ret)
 		goto out;
 
@@ -286,23 +287,18 @@ out:
 	return ERR_PTR(ret);
 }
 
-int bpf_obj_get_user(const char __user *pathname, int flags)
+int bpf_obj_get_user(const char __user *pathname)
 {
 	enum bpf_type type = BPF_TYPE_UNSPEC;
 	struct filename *pname;
 	int ret = -ENOENT;
-	int f_flags;
 	void *raw;
 
-	f_flags = bpf_get_file_flag(flags);
-	if (f_flags < 0)
-		return f_flags;
-
 	pname = getname(pathname);
 	if (IS_ERR(pname))
 		return PTR_ERR(pname);
 
-	raw = bpf_obj_do_get(pname, &type, f_flags);
+	raw = bpf_obj_do_get(pname, &type);
 	if (IS_ERR(raw)) {
 		ret = PTR_ERR(raw);
 		goto out;
@@ -311,7 +307,7 @@ int bpf_obj_get_user(const char __user *pathname, int flags)
 	if (type == BPF_TYPE_PROG)
 		ret = bpf_prog_new_fd(raw);
 	else if (type == BPF_TYPE_MAP)
-		ret = bpf_map_new_fd(raw, f_flags);
+		ret = bpf_map_new_fd(raw);
 	else
 		goto out;
 
@@ -322,42 +318,6 @@ out:
 	return ret;
 }
 
-static struct bpf_prog *__get_prog_inode(struct inode *inode, enum bpf_prog_type type)
-{
-	struct bpf_prog *prog;
-	int ret = inode_permission(inode, MAY_READ);
-	if (ret)
-		return ERR_PTR(ret);
-
-	if (inode->i_op == &bpf_map_iops)
-		return ERR_PTR(-EINVAL);
-	if (inode->i_op != &bpf_prog_iops)
-		return ERR_PTR(-EACCES);
-
-	prog = inode->i_private;
-
-	ret = security_bpf_prog(prog);
-	if (ret < 0)
-		return ERR_PTR(ret);
-
-	return bpf_prog_inc(prog);
-}
-
-struct bpf_prog *bpf_prog_get_type_path(const char *name, enum bpf_prog_type type)
-{
-	struct bpf_prog *prog;
-	struct path path;
-	int ret = kern_path(name, LOOKUP_FOLLOW, &path);
-	if (ret)
-		return ERR_PTR(ret);
-	prog = __get_prog_inode(d_backing_inode(path.dentry), type);
-	if (!IS_ERR(prog))
-		touch_atime(&path);
-	path_put(&path);
-	return prog;
-}
-EXPORT_SYMBOL(bpf_prog_get_type_path);
-
 static void bpf_evict_inode(struct inode *inode)
 {
 	enum bpf_type type;
@@ -408,6 +368,8 @@ static struct file_system_type bpf_fs_type = {
 	.kill_sb	= kill_litter_super,
 };
 
+MODULE_ALIAS_FS("bpf");
+
 static int __init bpf_init(void)
 {
 	int ret;
diff --git a/kernel/bpf/percpu_freelist.c b/kernel/bpf/percpu_freelist.c
deleted file mode 100644
index 673fa6fe2d73..000000000000
--- a/kernel/bpf/percpu_freelist.c
+++ /dev/null
@@ -1,104 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include "percpu_freelist.h"
-
-int pcpu_freelist_init(struct pcpu_freelist *s)
-{
-	int cpu;
-
-	s->freelist = alloc_percpu(struct pcpu_freelist_head);
-	if (!s->freelist)
-		return -ENOMEM;
-
-	for_each_possible_cpu(cpu) {
-		struct pcpu_freelist_head *head = per_cpu_ptr(s->freelist, cpu);
-
-		raw_spin_lock_init(&head->lock);
-		head->first = NULL;
-	}
-	return 0;
-}
-
-void pcpu_freelist_destroy(struct pcpu_freelist *s)
-{
-	free_percpu(s->freelist);
-}
-
-static inline void __pcpu_freelist_push(struct pcpu_freelist_head *head,
-					struct pcpu_freelist_node *node)
-{
-	raw_spin_lock(&head->lock);
-	node->next = head->first;
-	head->first = node;
-	raw_spin_unlock(&head->lock);
-}
-
-void pcpu_freelist_push(struct pcpu_freelist *s,
-			struct pcpu_freelist_node *node)
-{
-	struct pcpu_freelist_head *head = this_cpu_ptr(s->freelist);
-
-	__pcpu_freelist_push(head, node);
-}
-
-void pcpu_freelist_populate(struct pcpu_freelist *s, void *buf, u32 elem_size,
-			    u32 nr_elems)
-{
-	struct pcpu_freelist_head *head;
-	unsigned long flags;
-	int i, cpu, pcpu_entries;
-
-	pcpu_entries = nr_elems / num_possible_cpus() + 1;
-	i = 0;
-
-	/* disable irq to workaround lockdep false positive
-	 * in bpf usage pcpu_freelist_populate() will never race
-	 * with pcpu_freelist_push()
-	 */
-	local_irq_save(flags);
-	for_each_possible_cpu(cpu) {
-again:
-		head = per_cpu_ptr(s->freelist, cpu);
-		__pcpu_freelist_push(head, buf);
-		i++;
-		buf += elem_size;
-		if (i == nr_elems)
-			break;
-		if (i % pcpu_entries)
-			goto again;
-	}
-	local_irq_restore(flags);
-}
-
-struct pcpu_freelist_node *pcpu_freelist_pop(struct pcpu_freelist *s)
-{
-	struct pcpu_freelist_head *head;
-	struct pcpu_freelist_node *node;
-	unsigned long flags;
-	int orig_cpu, cpu;
-
-	local_irq_save(flags);
-	orig_cpu = cpu = raw_smp_processor_id();
-	while (1) {
-		head = per_cpu_ptr(s->freelist, cpu);
-		raw_spin_lock(&head->lock);
-		node = head->first;
-		if (node) {
-			head->first = node->next;
-			raw_spin_unlock_irqrestore(&head->lock, flags);
-			return node;
-		}
-		raw_spin_unlock(&head->lock);
-		cpu = cpumask_next(cpu, cpu_possible_mask);
-		if (cpu >= nr_cpu_ids)
-			cpu = 0;
-		if (cpu == orig_cpu) {
-			local_irq_restore(flags);
-			return NULL;
-		}
-	}
-}
diff --git a/kernel/bpf/percpu_freelist.h b/kernel/bpf/percpu_freelist.h
deleted file mode 100644
index 3049aae8ea1e..000000000000
--- a/kernel/bpf/percpu_freelist.h
+++ /dev/null
@@ -1,31 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#ifndef __PERCPU_FREELIST_H__
-#define __PERCPU_FREELIST_H__
-#include <linux/spinlock.h>
-#include <linux/percpu.h>
-
-struct pcpu_freelist_head {
-	struct pcpu_freelist_node *first;
-	raw_spinlock_t lock;
-};
-
-struct pcpu_freelist {
-	struct pcpu_freelist_head __percpu *freelist;
-};
-
-struct pcpu_freelist_node {
-	struct pcpu_freelist_node *next;
-};
-
-void pcpu_freelist_push(struct pcpu_freelist *, struct pcpu_freelist_node *);
-struct pcpu_freelist_node *pcpu_freelist_pop(struct pcpu_freelist *);
-void pcpu_freelist_populate(struct pcpu_freelist *s, void *buf, u32 elem_size,
-			    u32 nr_elems);
-int pcpu_freelist_init(struct pcpu_freelist *);
-void pcpu_freelist_destroy(struct pcpu_freelist *s);
-#endif
diff --git a/kernel/bpf/stackmap.c b/kernel/bpf/stackmap.c
deleted file mode 100644
index 6039db3dcf02..000000000000
--- a/kernel/bpf/stackmap.c
+++ /dev/null
@@ -1,290 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/bpf.h>
-#include <linux/jhash.h>
-#include <linux/filter.h>
-#include <linux/stacktrace.h>
-#include <linux/perf_event.h>
-#include "percpu_freelist.h"
-
-#define STACK_CREATE_FLAG_MASK \
-	(BPF_F_RDONLY | BPF_F_WRONLY)
-
-struct stack_map_bucket {
-	struct pcpu_freelist_node fnode;
-	u32 hash;
-	u32 nr;
-	u64 ip[];
-};
-
-struct bpf_stack_map {
-	struct bpf_map map;
-	void *elems;
-	struct pcpu_freelist freelist;
-	u32 n_buckets;
-	struct stack_map_bucket *buckets[];
-};
-
-static int prealloc_elems_and_freelist(struct bpf_stack_map *smap)
-{
-	u32 elem_size = sizeof(struct stack_map_bucket) + smap->map.value_size;
-	int err;
-
-	smap->elems = bpf_map_area_alloc(elem_size * smap->map.max_entries);
-	if (!smap->elems)
-		return -ENOMEM;
-
-	err = pcpu_freelist_init(&smap->freelist);
-	if (err)
-		goto free_elems;
-
-	pcpu_freelist_populate(&smap->freelist, smap->elems, elem_size,
-			       smap->map.max_entries);
-	return 0;
-
-free_elems:
-	bpf_map_area_free(smap->elems);
-	return err;
-}
-
-/* Called from syscall */
-static struct bpf_map *stack_map_alloc(union bpf_attr *attr)
-{
-	u32 value_size = attr->value_size;
-	struct bpf_stack_map *smap;
-	u64 cost, n_buckets;
-	int err;
-
-	if (!capable(CAP_SYS_ADMIN))
-		return ERR_PTR(-EPERM);
-
-	if (attr->map_flags & ~STACK_CREATE_FLAG_MASK)
-		return ERR_PTR(-EINVAL);
-
-	/* check sanity of attributes */
-	if (attr->max_entries == 0 || attr->key_size != 4 ||
-	    value_size < 8 || value_size % 8 ||
-	    value_size / 8 > sysctl_perf_event_max_stack)
-		return ERR_PTR(-EINVAL);
-
-	/* hash table size must be power of 2 */
-	n_buckets = roundup_pow_of_two(attr->max_entries);
-
-	cost = n_buckets * sizeof(struct stack_map_bucket *) + sizeof(*smap);
-	if (cost >= U32_MAX - PAGE_SIZE)
-		return ERR_PTR(-E2BIG);
-
-	smap = bpf_map_area_alloc(cost);
-	if (!smap)
-		return ERR_PTR(-ENOMEM);
-
-	err = -E2BIG;
-	cost += n_buckets * (value_size + sizeof(struct stack_map_bucket));
-	if (cost >= U32_MAX - PAGE_SIZE)
-		goto free_smap;
-
-	smap->map.map_type = attr->map_type;
-	smap->map.key_size = attr->key_size;
-	smap->map.value_size = value_size;
-	smap->map.max_entries = attr->max_entries;
-	smap->map.map_flags = attr->map_flags;
-	smap->n_buckets = n_buckets;
-	smap->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
-
-	err = bpf_map_precharge_memlock(smap->map.pages);
-	if (err)
-		goto free_smap;
-
-	err = get_callchain_buffers(sysctl_perf_event_max_stack);
-	if (err)
-		goto free_smap;
-
-	err = prealloc_elems_and_freelist(smap);
-	if (err)
-		goto put_buffers;
-
-	return &smap->map;
-
-put_buffers:
-	put_callchain_buffers();
-free_smap:
-	bpf_map_area_free(smap);
-	return ERR_PTR(err);
-}
-
-BPF_CALL_3(bpf_get_stackid, struct pt_regs *, regs, struct bpf_map *, map,
-	   u64, flags)
-{
-	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
-	struct perf_callchain_entry *trace;
-	struct stack_map_bucket *bucket, *new_bucket, *old_bucket;
-	u32 max_depth = map->value_size / 8;
-	/* stack_map_alloc() checks that max_depth <= sysctl_perf_event_max_stack */
-	u32 init_nr = sysctl_perf_event_max_stack - max_depth;
-	u32 skip = flags & BPF_F_SKIP_FIELD_MASK;
-	u32 hash, id, trace_nr, trace_len;
-	bool user = flags & BPF_F_USER_STACK;
-	bool kernel = !user;
-	u64 *ips;
-
-	if (unlikely(flags & ~(BPF_F_SKIP_FIELD_MASK | BPF_F_USER_STACK |
-			       BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID)))
-		return -EINVAL;
-
-	trace = get_perf_callchain(regs, init_nr, kernel, user,
-				   sysctl_perf_event_max_stack, false, false);
-
-	if (unlikely(!trace))
-		/* couldn't fetch the stack trace */
-		return -EFAULT;
-
-	/* get_perf_callchain() guarantees that trace->nr >= init_nr
-	 * and trace-nr <= sysctl_perf_event_max_stack, so trace_nr <= max_depth
-	 */
-	trace_nr = trace->nr - init_nr;
-
-	if (trace_nr <= skip)
-		/* skipping more than usable stack trace */
-		return -EFAULT;
-
-	trace_nr -= skip;
-	trace_len = trace_nr * sizeof(u64);
-	ips = trace->ip + skip + init_nr;
-	hash = jhash2((u32 *)ips, trace_len / sizeof(u32), 0);
-	id = hash & (smap->n_buckets - 1);
-	bucket = READ_ONCE(smap->buckets[id]);
-
-	if (bucket && bucket->hash == hash) {
-		if (flags & BPF_F_FAST_STACK_CMP)
-			return id;
-		if (bucket->nr == trace_nr &&
-		    memcmp(bucket->ip, ips, trace_len) == 0)
-			return id;
-	}
-
-	/* this call stack is not in the map, try to add it */
-	if (bucket && !(flags & BPF_F_REUSE_STACKID))
-		return -EEXIST;
-
-	new_bucket = (struct stack_map_bucket *)
-		pcpu_freelist_pop(&smap->freelist);
-	if (unlikely(!new_bucket))
-		return -ENOMEM;
-
-	memcpy(new_bucket->ip, ips, trace_len);
-	new_bucket->hash = hash;
-	new_bucket->nr = trace_nr;
-
-	old_bucket = xchg(&smap->buckets[id], new_bucket);
-	if (old_bucket)
-		pcpu_freelist_push(&smap->freelist, &old_bucket->fnode);
-	return id;
-}
-
-const struct bpf_func_proto bpf_get_stackid_proto = {
-	.func		= bpf_get_stackid,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_CONST_MAP_PTR,
-	.arg3_type	= ARG_ANYTHING,
-};
-
-/* Called from eBPF program */
-static void *stack_map_lookup_elem(struct bpf_map *map, void *key)
-{
-	return NULL;
-}
-
-/* Called from syscall */
-int bpf_stackmap_copy(struct bpf_map *map, void *key, void *value)
-{
-	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
-	struct stack_map_bucket *bucket, *old_bucket;
-	u32 id = *(u32 *)key, trace_len;
-
-	if (unlikely(id >= smap->n_buckets))
-		return -ENOENT;
-
-	bucket = xchg(&smap->buckets[id], NULL);
-	if (!bucket)
-		return -ENOENT;
-
-	trace_len = bucket->nr * sizeof(u64);
-	memcpy(value, bucket->ip, trace_len);
-	memset(value + trace_len, 0, map->value_size - trace_len);
-
-	old_bucket = xchg(&smap->buckets[id], bucket);
-	if (old_bucket)
-		pcpu_freelist_push(&smap->freelist, &old_bucket->fnode);
-	return 0;
-}
-
-static int stack_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
-{
-	return -EINVAL;
-}
-
-static int stack_map_update_elem(struct bpf_map *map, void *key, void *value,
-				 u64 map_flags)
-{
-	return -EINVAL;
-}
-
-/* Called from syscall or from eBPF program */
-static int stack_map_delete_elem(struct bpf_map *map, void *key)
-{
-	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
-	struct stack_map_bucket *old_bucket;
-	u32 id = *(u32 *)key;
-
-	if (unlikely(id >= smap->n_buckets))
-		return -E2BIG;
-
-	old_bucket = xchg(&smap->buckets[id], NULL);
-	if (old_bucket) {
-		pcpu_freelist_push(&smap->freelist, &old_bucket->fnode);
-		return 0;
-	} else {
-		return -ENOENT;
-	}
-}
-
-/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
-static void stack_map_free(struct bpf_map *map)
-{
-	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
-
-	/* wait for bpf programs to complete before freeing stack map */
-	synchronize_rcu();
-
-	bpf_map_area_free(smap->elems);
-	pcpu_freelist_destroy(&smap->freelist);
-	bpf_map_area_free(smap);
-	put_callchain_buffers();
-}
-
-static const struct bpf_map_ops stack_map_ops = {
-	.map_alloc = stack_map_alloc,
-	.map_free = stack_map_free,
-	.map_get_next_key = stack_map_get_next_key,
-	.map_lookup_elem = stack_map_lookup_elem,
-	.map_update_elem = stack_map_update_elem,
-	.map_delete_elem = stack_map_delete_elem,
-};
-
-static struct bpf_map_type_list stack_map_type __read_mostly = {
-	.ops = &stack_map_ops,
-	.type = BPF_MAP_TYPE_STACK_TRACE,
-};
-
-static int __init register_stack_map(void)
-{
-	bpf_register_map_type(&stack_map_type);
-	return 0;
-}
-late_initcall(register_stack_map);
diff --git a/kernel/bpf/syscall.c b/kernel/bpf/syscall.c
index e6e243a2c13f..01431ef8cf07 100644
--- a/kernel/bpf/syscall.c
+++ b/kernel/bpf/syscall.c
@@ -12,18 +12,12 @@
 #include <linux/bpf.h>
 #include <linux/syscalls.h>
 #include <linux/slab.h>
-#include <linux/vmalloc.h>
-#include <linux/mmzone.h>
 #include <linux/anon_inodes.h>
 #include <linux/file.h>
 #include <linux/license.h>
 #include <linux/filter.h>
 #include <linux/version.h>
 
-#define BPF_OBJ_FLAG_MASK   (BPF_F_RDONLY | BPF_F_WRONLY)
-
-DEFINE_PER_CPU(int, bpf_prog_active);
-
 int sysctl_unprivileged_bpf_disabled __read_mostly;
 
 static LIST_HEAD(bpf_map_types);
@@ -52,43 +46,6 @@ void bpf_register_map_type(struct bpf_map_type_list *tl)
 	list_add(&tl->list_node, &bpf_map_types);
 }
 
-void *bpf_map_area_alloc(size_t size)
-{
-	/* We definitely need __GFP_NORETRY, so OOM killer doesn't
-	 * trigger under memory pressure as we really just want to
-	 * fail instead.
-	 */
-	const gfp_t flags = __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO;
-	void *area;
-
-	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
-		area = kmalloc(size, GFP_USER | flags);
-		if (area != NULL)
-			return area;
-	}
-
-	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | flags,
-			 PAGE_KERNEL);
-}
-
-void bpf_map_area_free(void *area)
-{
-	kvfree(area);
-}
-
-int bpf_map_precharge_memlock(u32 pages)
-{
-	struct user_struct *user = get_current_user();
-	unsigned long memlock_limit, cur;
-
-	memlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
-	cur = atomic_long_read(&user->locked_vm);
-	free_uid(user);
-	if (cur + pages > memlock_limit)
-		return -EPERM;
-	return 0;
-}
-
 static int bpf_map_charge_memlock(struct bpf_map *map)
 {
 	struct user_struct *user = get_current_user();
@@ -121,7 +78,6 @@ static void bpf_map_free_deferred(struct work_struct *work)
 	struct bpf_map *map = container_of(work, struct bpf_map, work);
 
 	bpf_map_uncharge_memlock(map);
-	security_bpf_map_free(map);
 	/* implementation dependent freeing */
 	map->ops->map_free(map);
 }
@@ -153,82 +109,18 @@ void bpf_map_put_with_uref(struct bpf_map *map)
 
 static int bpf_map_release(struct inode *inode, struct file *filp)
 {
-	struct bpf_map *map = filp->private_data;
-
-	if (map->ops->map_release)
-		map->ops->map_release(map, filp);
-
-	bpf_map_put_with_uref(map);
+	bpf_map_put_with_uref(filp->private_data);
 	return 0;
 }
 
-#ifdef CONFIG_PROC_FS
-static void bpf_map_show_fdinfo(struct seq_file *m, struct file *filp)
-{
-        const struct bpf_map *map = filp->private_data;
-
-        seq_printf(m,
-                   "map_type:\t%u\n"
-                   "key_size:\t%u\n"
-                   "value_size:\t%u\n"
-                   "max_entries:\t%u\n"
-                   "map_flags:\t%#x\n",
-                   map->map_type,
-                   map->key_size,
-                   map->value_size,
-                   map->max_entries,
-                   map->map_flags);
-}
-#endif
-
-static ssize_t bpf_dummy_read(struct file *filp, char __user *buf, size_t siz,
-			      loff_t *ppos)
-{
-	/* We need this handler such that alloc_file() enables
-	 * f_mode with FMODE_CAN_READ.
-	 */
-	return -EINVAL;
-}
-
-static ssize_t bpf_dummy_write(struct file *filp, const char __user *buf,
-			       size_t siz, loff_t *ppos)
-{
-	/* We need this handler such that alloc_file() enables
-	 * f_mode with FMODE_CAN_WRITE.
-	 */
-	return -EINVAL;
-}
-
-const struct file_operations bpf_map_fops = {
-#ifdef CONFIG_PROC_FS
-	.show_fdinfo	= bpf_map_show_fdinfo,
-#endif
-	.release	= bpf_map_release,
-	.read		= bpf_dummy_read,
-	.write		= bpf_dummy_write,
+static const struct file_operations bpf_map_fops = {
+	.release = bpf_map_release,
 };
 
-int bpf_map_new_fd(struct bpf_map *map, int flags)
+int bpf_map_new_fd(struct bpf_map *map)
 {
-	int ret;
-
-	ret = security_bpf_map(map, OPEN_FMODE(flags));
-	if (ret < 0)
-		return ret;
-
 	return anon_inode_getfd("bpf-map", &bpf_map_fops, map,
-				flags | O_CLOEXEC);
-}
-
-int bpf_get_file_flag(int flags)
-{
-	if ((flags & BPF_F_RDONLY) && (flags & BPF_F_WRONLY))
-		return -EINVAL;
-	if (flags & BPF_F_RDONLY)
-		return O_RDONLY;
-	if (flags & BPF_F_WRONLY)
-		return O_WRONLY;
-	return O_RDWR;
+				O_RDWR | O_CLOEXEC);
 }
 
 /* helper macro to check that unused fields 'union bpf_attr' are zero */
@@ -239,22 +131,17 @@ int bpf_get_file_flag(int flags)
 		   offsetof(union bpf_attr, CMD##_LAST_FIELD) - \
 		   sizeof(attr->CMD##_LAST_FIELD)) != NULL
 
-#define BPF_MAP_CREATE_LAST_FIELD map_flags
+#define BPF_MAP_CREATE_LAST_FIELD max_entries
 /* called via syscall */
 static int map_create(union bpf_attr *attr)
 {
 	struct bpf_map *map;
-	int f_flags;
 	int err;
 
 	err = CHECK_ATTR(BPF_MAP_CREATE);
 	if (err)
 		return -EINVAL;
 
-	f_flags = bpf_get_file_flag(attr->map_flags);
-	if (f_flags < 0)
-		return f_flags;
-
 	/* find map type and init map: hashtable vs rbtree vs bloom vs ... */
 	map = find_and_alloc_map(attr);
 	if (IS_ERR(map))
@@ -263,15 +150,11 @@ static int map_create(union bpf_attr *attr)
 	atomic_set(&map->refcnt, 1);
 	atomic_set(&map->usercnt, 1);
 
-	err = security_bpf_map_alloc(map);
-	if (err)
-		goto free_map_nouncharge;
-
 	err = bpf_map_charge_memlock(map);
 	if (err)
-		goto free_map_sec;
+		goto free_map_nouncharge;
 
-	err = bpf_map_new_fd(map, f_flags);
+	err = bpf_map_new_fd(map);
 	if (err < 0)
 		/* failed to allocate fd */
 		goto free_map;
@@ -280,8 +163,6 @@ static int map_create(union bpf_attr *attr)
 
 free_map:
 	bpf_map_uncharge_memlock(map);
-free_map_sec:
-	security_bpf_map_free(map);
 free_map_nouncharge:
 	map->ops->map_free(map);
 	return err;
@@ -337,11 +218,6 @@ static void __user *u64_to_ptr(__u64 val)
 	return (void __user *) (unsigned long) val;
 }
 
-int __weak bpf_stackmap_copy(struct bpf_map *map, void *key, void *value)
-{
-	return -ENOTSUPP;
-}
-
 /* last field in 'union bpf_attr' used by this command */
 #define BPF_MAP_LOOKUP_ELEM_LAST_FIELD value
 
@@ -352,7 +228,6 @@ static int map_lookup_elem(union bpf_attr *attr)
 	int ufd = attr->map_fd;
 	struct bpf_map *map;
 	void *key, *value, *ptr;
-	u32 value_size;
 	struct fd f;
 	int err;
 
@@ -364,11 +239,6 @@ static int map_lookup_elem(union bpf_attr *attr)
 	if (IS_ERR(map))
 		return PTR_ERR(map);
 
-	if (!(f.file->f_mode & FMODE_CAN_READ)) {
-		err = -EPERM;
-		goto err_put;
-	}
-
 	err = -ENOMEM;
 	key = kmalloc(map->key_size, GFP_USER);
 	if (!key)
@@ -378,37 +248,23 @@ static int map_lookup_elem(union bpf_attr *attr)
 	if (copy_from_user(key, ukey, map->key_size) != 0)
 		goto free_key;
 
-	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
-	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
-		value_size = round_up(map->value_size, 8) * num_possible_cpus();
-	else
-		value_size = map->value_size;
-
 	err = -ENOMEM;
-	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
+	value = kmalloc(map->value_size, GFP_USER | __GFP_NOWARN);
 	if (!value)
 		goto free_key;
 
-	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH) {
-		err = bpf_percpu_hash_copy(map, key, value);
-	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
-		err = bpf_percpu_array_copy(map, key, value);
-	} else if (map->map_type == BPF_MAP_TYPE_STACK_TRACE) {
-		err = bpf_stackmap_copy(map, key, value);
-	} else {
-		rcu_read_lock();
-		ptr = map->ops->map_lookup_elem(map, key);
-		if (ptr)
-			memcpy(value, ptr, value_size);
-		rcu_read_unlock();
-		err = ptr ? 0 : -ENOENT;
-	}
+	rcu_read_lock();
+	ptr = map->ops->map_lookup_elem(map, key);
+	if (ptr)
+		memcpy(value, ptr, map->value_size);
+	rcu_read_unlock();
 
-	if (err)
+	err = -ENOENT;
+	if (!ptr)
 		goto free_value;
 
 	err = -EFAULT;
-	if (copy_to_user(uvalue, value, value_size) != 0)
+	if (copy_to_user(uvalue, value, map->value_size) != 0)
 		goto free_value;
 
 	err = 0;
@@ -431,7 +287,6 @@ static int map_update_elem(union bpf_attr *attr)
 	int ufd = attr->map_fd;
 	struct bpf_map *map;
 	void *key, *value;
-	u32 value_size;
 	struct fd f;
 	int err;
 
@@ -443,11 +298,6 @@ static int map_update_elem(union bpf_attr *attr)
 	if (IS_ERR(map))
 		return PTR_ERR(map);
 
-	if (!(f.file->f_mode & FMODE_CAN_WRITE)) {
-		err = -EPERM;
-		goto err_put;
-	}
-
 	err = -ENOMEM;
 	key = kmalloc(map->key_size, GFP_USER);
 	if (!key)
@@ -457,44 +307,21 @@ static int map_update_elem(union bpf_attr *attr)
 	if (copy_from_user(key, ukey, map->key_size) != 0)
 		goto free_key;
 
-	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
-	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
-		value_size = round_up(map->value_size, 8) * num_possible_cpus();
-	else
-		value_size = map->value_size;
-
 	err = -ENOMEM;
-	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
+	value = kmalloc(map->value_size, GFP_USER | __GFP_NOWARN);
 	if (!value)
 		goto free_key;
 
 	err = -EFAULT;
-	if (copy_from_user(value, uvalue, value_size) != 0)
+	if (copy_from_user(value, uvalue, map->value_size) != 0)
 		goto free_value;
 
-	/* must increment bpf_prog_active to avoid kprobe+bpf triggering from
-	 * inside bpf map update or delete otherwise deadlocks are possible
+	/* eBPF program that use maps are running under rcu_read_lock(),
+	 * therefore all map accessors rely on this fact, so do the same here
 	 */
-	preempt_disable();
-	__this_cpu_inc(bpf_prog_active);
-	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH) {
-		err = bpf_percpu_hash_update(map, key, value, attr->flags);
-	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
-		err = bpf_percpu_array_update(map, key, value, attr->flags);
-	} else if (map->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
-		   map->map_type == BPF_MAP_TYPE_PROG_ARRAY ||
-		   map->map_type == BPF_MAP_TYPE_CGROUP_ARRAY) {
-		rcu_read_lock();
-		err = bpf_fd_array_map_update_elem(map, f.file, key, value,
-						   attr->flags);
-		rcu_read_unlock();
-	} else {
-		rcu_read_lock();
-		err = map->ops->map_update_elem(map, key, value, attr->flags);
-		rcu_read_unlock();
-	}
-	__this_cpu_dec(bpf_prog_active);
-	preempt_enable();
+	rcu_read_lock();
+	err = map->ops->map_update_elem(map, key, value, attr->flags);
+	rcu_read_unlock();
 
 free_value:
 	kfree(value);
@@ -524,11 +351,6 @@ static int map_delete_elem(union bpf_attr *attr)
 	if (IS_ERR(map))
 		return PTR_ERR(map);
 
-	if (!(f.file->f_mode & FMODE_CAN_WRITE)) {
-		err = -EPERM;
-		goto err_put;
-	}
-
 	err = -ENOMEM;
 	key = kmalloc(map->key_size, GFP_USER);
 	if (!key)
@@ -538,13 +360,9 @@ static int map_delete_elem(union bpf_attr *attr)
 	if (copy_from_user(key, ukey, map->key_size) != 0)
 		goto free_key;
 
-	preempt_disable();
-	__this_cpu_inc(bpf_prog_active);
 	rcu_read_lock();
 	err = map->ops->map_delete_elem(map, key);
 	rcu_read_unlock();
-	__this_cpu_dec(bpf_prog_active);
-	preempt_enable();
 
 free_key:
 	kfree(key);
@@ -574,11 +392,6 @@ static int map_get_next_key(union bpf_attr *attr)
 	if (IS_ERR(map))
 		return PTR_ERR(map);
 
-	if (!(f.file->f_mode & FMODE_CAN_READ)) {
-		err = -EPERM;
-		goto err_put;
-	}
-
 	if (ukey) {
 		err = -ENOMEM;
 		key = kmalloc(map->key_size, GFP_USER);
@@ -682,7 +495,6 @@ static void __bpf_prog_put_rcu(struct rcu_head *rcu)
 
 	free_used_maps(aux);
 	bpf_prog_uncharge_memlock(aux->prog);
-	security_bpf_prog_free(aux);
 	bpf_prog_free(aux->prog);
 }
 
@@ -701,25 +513,17 @@ static int bpf_prog_release(struct inode *inode, struct file *filp)
 	return 0;
 }
 
-const struct file_operations bpf_prog_fops = {
+static const struct file_operations bpf_prog_fops = {
         .release = bpf_prog_release,
-	.read		= bpf_dummy_read,
-	.write		= bpf_dummy_write,
 };
 
 int bpf_prog_new_fd(struct bpf_prog *prog)
 {
-	int ret;
-
-	ret = security_bpf_prog(prog);
-	if (ret < 0)
-		return ret;
-
 	return anon_inode_getfd("bpf-prog", &bpf_prog_fops, prog,
 				O_RDWR | O_CLOEXEC);
 }
 
-static struct bpf_prog *____bpf_prog_get(struct fd f)
+static struct bpf_prog *__bpf_prog_get(struct fd f)
 {
 	if (!f.file)
 		return ERR_PTR(-EBADF);
@@ -731,50 +535,33 @@ static struct bpf_prog *____bpf_prog_get(struct fd f)
 	return f.file->private_data;
 }
 
-struct bpf_prog *bpf_prog_add(struct bpf_prog *prog, int i)
+struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog)
 {
-	if (atomic_add_return(i, &prog->aux->refcnt) > BPF_MAX_REFCNT) {
-		atomic_sub(i, &prog->aux->refcnt);
+	if (atomic_inc_return(&prog->aux->refcnt) > BPF_MAX_REFCNT) {
+		atomic_dec(&prog->aux->refcnt);
 		return ERR_PTR(-EBUSY);
 	}
 	return prog;
 }
-EXPORT_SYMBOL_GPL(bpf_prog_add);
-
-struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog)
-{
-	return bpf_prog_add(prog, 1);
-}
 
-static struct bpf_prog *__bpf_prog_get(u32 ufd, enum bpf_prog_type *type)
+/* called by sockets/tracing/seccomp before attaching program to an event
+ * pairs with bpf_prog_put()
+ */
+struct bpf_prog *bpf_prog_get(u32 ufd)
 {
 	struct fd f = fdget(ufd);
 	struct bpf_prog *prog;
 
-	prog = ____bpf_prog_get(f);
+	prog = __bpf_prog_get(f);
 	if (IS_ERR(prog))
 		return prog;
-	if (type && prog->type != *type) {
-		prog = ERR_PTR(-EINVAL);
-		goto out;
-	}
 
 	prog = bpf_prog_inc(prog);
-out:
 	fdput(f);
-	return prog;
-}
-
-struct bpf_prog *bpf_prog_get(u32 ufd)
-{
-	return __bpf_prog_get(ufd, NULL);
-}
 
-struct bpf_prog *bpf_prog_get_type(u32 ufd, enum bpf_prog_type type)
-{
-	return __bpf_prog_get(ufd, &type);
+	return prog;
 }
-EXPORT_SYMBOL_GPL(bpf_prog_get_type);
+EXPORT_SYMBOL_GPL(bpf_prog_get);
 
 /* last field in 'union bpf_attr' used by this command */
 #define	BPF_PROG_LOAD_LAST_FIELD kern_version
@@ -806,9 +593,7 @@ static int bpf_prog_load(union bpf_attr *attr)
 	    attr->kern_version != LINUX_VERSION_CODE)
 		return -EINVAL;
 
-	if (type != BPF_PROG_TYPE_SOCKET_FILTER &&
-	    type != BPF_PROG_TYPE_CGROUP_SKB &&
-	    !capable(CAP_SYS_ADMIN))
+	if (type != BPF_PROG_TYPE_SOCKET_FILTER && !capable(CAP_SYS_ADMIN))
 		return -EPERM;
 
 	/* plain bpf_prog allocation */
@@ -816,13 +601,9 @@ static int bpf_prog_load(union bpf_attr *attr)
 	if (!prog)
 		return -ENOMEM;
 
-	err = security_bpf_prog_alloc(prog->aux);
-	if (err)
-		goto free_prog_nouncharge;
-
 	err = bpf_prog_charge_memlock(prog);
 	if (err)
-		goto free_prog_sec;
+		goto free_prog_nouncharge;
 
 	prog->len = attr->insn_cnt;
 
@@ -848,7 +629,7 @@ static int bpf_prog_load(union bpf_attr *attr)
 		goto free_used_maps;
 
 	/* eBPF program is ready to be JITed */
-	prog = bpf_prog_select_runtime(prog, &err);
+	err = bpf_prog_select_runtime(prog);
 	if (err < 0)
 		goto free_used_maps;
 
@@ -863,18 +644,16 @@ free_used_maps:
 	free_used_maps(prog->aux);
 free_prog:
 	bpf_prog_uncharge_memlock(prog);
-free_prog_sec:
-	security_bpf_prog_free(prog->aux);
 free_prog_nouncharge:
 	bpf_prog_free(prog);
 	return err;
 }
 
-#define BPF_OBJ_LAST_FIELD file_flags
+#define BPF_OBJ_LAST_FIELD bpf_fd
 
 static int bpf_obj_pin(const union bpf_attr *attr)
 {
-	if (CHECK_ATTR(BPF_OBJ) || attr->file_flags != 0)
+	if (CHECK_ATTR(BPF_OBJ))
 		return -EINVAL;
 
 	return bpf_obj_pin_user(attr->bpf_fd, u64_to_ptr(attr->pathname));
@@ -882,105 +661,12 @@ static int bpf_obj_pin(const union bpf_attr *attr)
 
 static int bpf_obj_get(const union bpf_attr *attr)
 {
-	if (CHECK_ATTR(BPF_OBJ) || attr->bpf_fd != 0 ||
-	    attr->file_flags & ~BPF_OBJ_FLAG_MASK)
+	if (CHECK_ATTR(BPF_OBJ) || attr->bpf_fd != 0)
 		return -EINVAL;
 
-	return bpf_obj_get_user(u64_to_ptr(attr->pathname),
-				attr->file_flags);
+	return bpf_obj_get_user(u64_to_ptr(attr->pathname));
 }
 
-#ifdef CONFIG_CGROUP_BPF
-
-#define BPF_PROG_ATTACH_LAST_FIELD attach_flags
-
-#define BPF_F_ATTACH_MASK \
-	(BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI)
-
-static int bpf_prog_attach(const union bpf_attr *attr)
-{
-	struct bpf_prog *prog;
-	struct cgroup *cgrp;
-	int ret;
-
-	if (!capable(CAP_NET_ADMIN))
-		return -EPERM;
-
-	if (CHECK_ATTR(BPF_PROG_ATTACH))
-		return -EINVAL;
-
-	if (attr->attach_flags & ~BPF_F_ATTACH_MASK)
-		return -EINVAL;
-
-	switch (attr->attach_type) {
-	case BPF_CGROUP_INET_INGRESS:
-	case BPF_CGROUP_INET_EGRESS:
-		prog = bpf_prog_get_type(attr->attach_bpf_fd,
-					 BPF_PROG_TYPE_CGROUP_SKB);
-		if (IS_ERR(prog))
-			return PTR_ERR(prog);
-
-		cgrp = cgroup_get_from_fd(attr->target_fd);
-		if (IS_ERR(cgrp)) {
-			bpf_prog_put(prog);
-			return PTR_ERR(cgrp);
-		}
-
-		ret = cgroup_bpf_attach(cgrp, prog, attr->attach_type,
-					attr->attach_flags);
-		if (ret)
-			bpf_prog_put(prog);
-		cgroup_put(cgrp);
-		break;
-
-	default:
-		return -EINVAL;
-	}
-
-	return ret;
-}
-
-#define BPF_PROG_DETACH_LAST_FIELD attach_type
-
-static int bpf_prog_detach(const union bpf_attr *attr)
-{
-	enum bpf_prog_type ptype;
-	struct bpf_prog *prog;
-	struct cgroup *cgrp;
-	int ret;
-
-	if (!capable(CAP_NET_ADMIN))
-		return -EPERM;
-
-	if (CHECK_ATTR(BPF_PROG_DETACH))
-		return -EINVAL;
-
-	switch (attr->attach_type) {
-	case BPF_CGROUP_INET_INGRESS:
-	case BPF_CGROUP_INET_EGRESS:
-		ptype = BPF_PROG_TYPE_CGROUP_SKB;
-		break;
-
-	default:
-		return -EINVAL;
-	}
-
-	cgrp = cgroup_get_from_fd(attr->target_fd);
-	if (IS_ERR(cgrp))
-		return PTR_ERR(cgrp);
-
-	prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
-	if (IS_ERR(prog))
-		prog = NULL;
-
-	ret = cgroup_bpf_detach(cgrp, prog, attr->attach_type, 0);
-	if (prog)
-		bpf_prog_put(prog);
-	cgroup_put(cgrp);
-	return ret;
-}
-#endif /* CONFIG_CGROUP_BPF */
-
 SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 {
 	union bpf_attr attr;
@@ -1023,10 +709,6 @@ SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, siz
 	if (copy_from_user(&attr, uattr, size) != 0)
 		return -EFAULT;
 
-	err = security_bpf(cmd, &attr, size);
-	if (err < 0)
-		return err;
-
 	switch (cmd) {
 	case BPF_MAP_CREATE:
 		err = map_create(&attr);
@@ -1052,16 +734,6 @@ SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, siz
 	case BPF_OBJ_GET:
 		err = bpf_obj_get(&attr);
 		break;
-
-#ifdef CONFIG_CGROUP_BPF
-	case BPF_PROG_ATTACH:
-		err = bpf_prog_attach(&attr);
-		break;
-	case BPF_PROG_DETACH:
-		err = bpf_prog_detach(&attr);
-		break;
-#endif
-
 	default:
 		err = -EINVAL;
 		break;
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 78bdfbefd996..c43ca9857479 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1,5 +1,4 @@
 /* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
- * Copyright (c) 2016 Facebook
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -14,7 +13,6 @@
 #include <linux/types.h>
 #include <linux/slab.h>
 #include <linux/bpf.h>
-#include <linux/bpf_verifier.h>
 #include <linux/filter.h>
 #include <net/netlink.h>
 #include <linux/file.h>
@@ -127,27 +125,91 @@
  * are set to NOT_INIT to indicate that they are no longer readable.
  */
 
+/* types of values stored in eBPF registers */
+enum bpf_reg_type {
+	NOT_INIT = 0,		 /* nothing was written into register */
+	UNKNOWN_VALUE,		 /* reg doesn't contain a valid pointer */
+	PTR_TO_CTX,		 /* reg points to bpf_context */
+	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
+	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
+	PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
+	FRAME_PTR,		 /* reg == frame_pointer */
+	PTR_TO_STACK,		 /* reg == frame_pointer + imm */
+	CONST_IMM,		 /* constant integer value */
+};
+
+struct reg_state {
+	enum bpf_reg_type type;
+	union {
+		/* valid when type == CONST_IMM | PTR_TO_STACK */
+		int imm;
+
+		/* valid when type == CONST_PTR_TO_MAP | PTR_TO_MAP_VALUE |
+		 *   PTR_TO_MAP_VALUE_OR_NULL
+		 */
+		struct bpf_map *map_ptr;
+	};
+};
+
+enum bpf_stack_slot_type {
+	STACK_INVALID,    /* nothing was stored in this stack slot */
+	STACK_SPILL,      /* register spilled into stack */
+	STACK_MISC	  /* BPF program wrote some data into this slot */
+};
+
+#define BPF_REG_SIZE 8	/* size of eBPF register in bytes */
+
+/* state of the program:
+ * type of all registers and stack info
+ */
+struct verifier_state {
+	struct reg_state regs[MAX_BPF_REG];
+	u8 stack_slot_type[MAX_BPF_STACK];
+	struct reg_state spilled_regs[MAX_BPF_STACK / BPF_REG_SIZE];
+};
+
+/* linked list of verifier states used to prune search */
+struct verifier_state_list {
+	struct verifier_state state;
+	struct verifier_state_list *next;
+};
+
 /* verifier_state + insn_idx are pushed to stack when branch is encountered */
-struct bpf_verifier_stack_elem {
+struct verifier_stack_elem {
 	/* verifer state is 'st'
 	 * before processing instruction 'insn_idx'
 	 * and after processing instruction 'prev_insn_idx'
 	 */
-	struct bpf_verifier_state st;
+	struct verifier_state st;
 	int insn_idx;
 	int prev_insn_idx;
-	struct bpf_verifier_stack_elem *next;
+	struct verifier_stack_elem *next;
 };
 
-#define BPF_COMPLEXITY_LIMIT_INSNS	98304
-#define BPF_COMPLEXITY_LIMIT_STACK	1024
+struct bpf_insn_aux_data {
+	union {
+		enum bpf_reg_type ptr_type;	/* pointer type for load/store insns */
+		struct bpf_map *map_ptr;	/* pointer for call insn into lookup_elem */
+	};
+	int sanitize_stack_off; /* stack slot to be cleared */
+	bool seen; /* this insn was processed by the verifier */
+};
 
-struct bpf_call_arg_meta {
-	struct bpf_map *map_ptr;
-	bool raw_mode;
-	bool pkt_access;
-	int regno;
-	int access_size;
+#define MAX_USED_MAPS 64 /* max number of maps accessed by one eBPF program */
+
+/* single container for all structs
+ * one verifier_env per bpf_check() call
+ */
+struct verifier_env {
+	struct bpf_prog *prog;		/* eBPF program being verified */
+	struct verifier_stack_elem *head; /* stack of verifier states to be processed */
+	int stack_size;			/* number of states to be processed */
+	struct verifier_state cur_state; /* current verifier state */
+	struct verifier_state_list **explored_states; /* search pruning optimization */
+	struct bpf_map *used_maps[MAX_USED_MAPS]; /* array of map's used by eBPF program */
+	u32 used_map_cnt;		/* number of used maps */
+	bool allow_ptr_leaks;
+	struct bpf_insn_aux_data *insn_aux_data; /* array of per-insn state */
 };
 
 /* verbose verifier prints what it's seeing
@@ -182,51 +244,33 @@ static const char * const reg_type_str[] = {
 	[CONST_PTR_TO_MAP]	= "map_ptr",
 	[PTR_TO_MAP_VALUE]	= "map_value",
 	[PTR_TO_MAP_VALUE_OR_NULL] = "map_value_or_null",
-	[PTR_TO_MAP_VALUE_ADJ]	= "map_value_adj",
 	[FRAME_PTR]		= "fp",
 	[PTR_TO_STACK]		= "fp",
 	[CONST_IMM]		= "imm",
-	[PTR_TO_PACKET]		= "pkt",
-	[PTR_TO_PACKET_END]	= "pkt_end",
 };
 
-static void print_verifier_state(struct bpf_verifier_state *state)
+static void print_verifier_state(struct verifier_env *env)
 {
-	struct bpf_reg_state *reg;
 	enum bpf_reg_type t;
 	int i;
 
 	for (i = 0; i < MAX_BPF_REG; i++) {
-		reg = &state->regs[i];
-		t = reg->type;
+		t = env->cur_state.regs[i].type;
 		if (t == NOT_INIT)
 			continue;
 		verbose(" R%d=%s", i, reg_type_str[t]);
 		if (t == CONST_IMM || t == PTR_TO_STACK)
-			verbose("%lld", reg->imm);
-		else if (t == PTR_TO_PACKET)
-			verbose("(id=%d,off=%d,r=%d)",
-				reg->id, reg->off, reg->range);
-		else if (t == UNKNOWN_VALUE && reg->imm)
-			verbose("%lld", reg->imm);
+			verbose("%d", env->cur_state.regs[i].imm);
 		else if (t == CONST_PTR_TO_MAP || t == PTR_TO_MAP_VALUE ||
-			 t == PTR_TO_MAP_VALUE_OR_NULL ||
-			 t == PTR_TO_MAP_VALUE_ADJ)
-			verbose("(ks=%d,vs=%d,id=%u)",
-				reg->map_ptr->key_size,
-				reg->map_ptr->value_size,
-				reg->id);
-		if (reg->min_value != BPF_REGISTER_MIN_RANGE)
-			verbose(",min_value=%lld",
-				(long long)reg->min_value);
-		if (reg->max_value != BPF_REGISTER_MAX_RANGE)
-			verbose(",max_value=%llu",
-				(unsigned long long)reg->max_value);
+			 t == PTR_TO_MAP_VALUE_OR_NULL)
+			verbose("(ks=%d,vs=%d)",
+				env->cur_state.regs[i].map_ptr->key_size,
+				env->cur_state.regs[i].map_ptr->value_size);
 	}
 	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
-		if (state->stack_slot_type[i] == STACK_SPILL)
+		if (env->cur_state.stack_slot_type[i] == STACK_SPILL)
 			verbose(" fp%d=%s", -MAX_BPF_STACK + i,
-				reg_type_str[state->spilled_regs[i / BPF_REG_SIZE].type]);
+				reg_type_str[env->cur_state.spilled_regs[i / BPF_REG_SIZE].type]);
 	}
 	verbose("\n");
 }
@@ -279,7 +323,7 @@ static const char *const bpf_jmp_string[16] = {
 	[BPF_EXIT >> 4] = "exit",
 };
 
-static void print_bpf_insn(const struct bpf_verifier_env *env,
+static void print_bpf_insn(const struct verifier_env *env,
 			   const struct bpf_insn *insn)
 {
 	u8 class = BPF_CLASS(insn->code);
@@ -387,9 +431,9 @@ static void print_bpf_insn(const struct bpf_verifier_env *env,
 	}
 }
 
-static int pop_stack(struct bpf_verifier_env *env, int *prev_insn_idx)
+static int pop_stack(struct verifier_env *env, int *prev_insn_idx)
 {
-	struct bpf_verifier_stack_elem *elem;
+	struct verifier_stack_elem *elem;
 	int insn_idx;
 
 	if (env->head == NULL)
@@ -406,12 +450,12 @@ static int pop_stack(struct bpf_verifier_env *env, int *prev_insn_idx)
 	return insn_idx;
 }
 
-static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
-					     int insn_idx, int prev_insn_idx)
+static struct verifier_state *push_stack(struct verifier_env *env, int insn_idx,
+					 int prev_insn_idx)
 {
-	struct bpf_verifier_stack_elem *elem;
+	struct verifier_stack_elem *elem;
 
-	elem = kmalloc(sizeof(struct bpf_verifier_stack_elem), GFP_KERNEL);
+	elem = kmalloc(sizeof(struct verifier_stack_elem), GFP_KERNEL);
 	if (!elem)
 		goto err;
 
@@ -421,7 +465,7 @@ static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
 	elem->next = env->head;
 	env->head = elem;
 	env->stack_size++;
-	if (env->stack_size > BPF_COMPLEXITY_LIMIT_STACK) {
+	if (env->stack_size > 1024) {
 		verbose("BPF program is too complex\n");
 		goto err;
 	}
@@ -437,15 +481,14 @@ static const int caller_saved[CALLER_SAVED_REGS] = {
 	BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5
 };
 
-static void init_reg_state(struct bpf_reg_state *regs)
+static void init_reg_state(struct reg_state *regs)
 {
 	int i;
 
 	for (i = 0; i < MAX_BPF_REG; i++) {
 		regs[i].type = NOT_INIT;
 		regs[i].imm = 0;
-		regs[i].min_value = BPF_REGISTER_MIN_RANGE;
-		regs[i].max_value = BPF_REGISTER_MAX_RANGE;
+		regs[i].map_ptr = NULL;
 	}
 
 	/* frame pointer */
@@ -455,23 +498,12 @@ static void init_reg_state(struct bpf_reg_state *regs)
 	regs[BPF_REG_1].type = PTR_TO_CTX;
 }
 
-static void __mark_reg_unknown_value(struct bpf_reg_state *regs, u32 regno)
+static void mark_reg_unknown_value(struct reg_state *regs, u32 regno)
 {
+	BUG_ON(regno >= MAX_BPF_REG);
 	regs[regno].type = UNKNOWN_VALUE;
-	regs[regno].id = 0;
 	regs[regno].imm = 0;
-}
-
-static void mark_reg_unknown_value(struct bpf_reg_state *regs, u32 regno)
-{
-	BUG_ON(regno >= MAX_BPF_REG);
-	__mark_reg_unknown_value(regs, regno);
-}
-
-static void reset_reg_range_values(struct bpf_reg_state *regs, u32 regno)
-{
-	regs[regno].min_value = BPF_REGISTER_MIN_RANGE;
-	regs[regno].max_value = BPF_REGISTER_MAX_RANGE;
+	regs[regno].map_ptr = NULL;
 }
 
 enum reg_arg_type {
@@ -480,7 +512,7 @@ enum reg_arg_type {
 	DST_OP_NO_MARK	/* same as above, check only, don't mark */
 };
 
-static int check_reg_arg(struct bpf_reg_state *regs, u32 regno,
+static int check_reg_arg(struct reg_state *regs, u32 regno,
 			 enum reg_arg_type t)
 {
 	if (regno >= MAX_BPF_REG) {
@@ -527,8 +559,6 @@ static bool is_spillable_regtype(enum bpf_reg_type type)
 	case PTR_TO_MAP_VALUE_OR_NULL:
 	case PTR_TO_STACK:
 	case PTR_TO_CTX:
-	case PTR_TO_PACKET:
-	case PTR_TO_PACKET_END:
 	case FRAME_PTR:
 	case CONST_PTR_TO_MAP:
 		return true;
@@ -540,8 +570,8 @@ static bool is_spillable_regtype(enum bpf_reg_type type)
 /* check_stack_read/write functions track spill/fill of registers,
  * stack boundary and alignment are checked in check_mem_access()
  */
-static int check_stack_write(struct bpf_verifier_env *env,
-			     struct bpf_verifier_state *state, int off,
+static int check_stack_write(struct verifier_env *env,
+			     struct verifier_state *state, int off,
 			     int size, int value_regno, int insn_idx)
 {
 	int i, spi = (MAX_BPF_STACK + off) / BPF_REG_SIZE;
@@ -589,7 +619,7 @@ static int check_stack_write(struct bpf_verifier_env *env,
 		}
 	} else {
 		/* regular write of data into stack */
-		state->spilled_regs[spi] = (struct bpf_reg_state) {};
+		state->spilled_regs[spi] = (struct reg_state) {};
 
 		for (i = 0; i < size; i++)
 			state->stack_slot_type[MAX_BPF_STACK + off + i] = STACK_MISC;
@@ -597,7 +627,7 @@ static int check_stack_write(struct bpf_verifier_env *env,
 	return 0;
 }
 
-static int check_stack_read(struct bpf_verifier_state *state, int off, int size,
+static int check_stack_read(struct verifier_state *state, int off, int size,
 			    int value_regno)
 {
 	u8 *slot_type;
@@ -638,7 +668,7 @@ static int check_stack_read(struct bpf_verifier_state *state, int off, int size,
 }
 
 /* check read/write into map element returned by bpf_map_lookup_elem() */
-static int check_map_access(struct bpf_verifier_env *env, u32 regno, int off,
+static int check_map_access(struct verifier_env *env, u32 regno, int off,
 			    int size)
 {
 	struct bpf_map *map = env->cur_state.regs[regno].map_ptr;
@@ -651,67 +681,24 @@ static int check_map_access(struct bpf_verifier_env *env, u32 regno, int off,
 	return 0;
 }
 
-#define MAX_PACKET_OFF 0xffff
-
-static bool may_access_direct_pkt_data(struct bpf_verifier_env *env,
-				       const struct bpf_call_arg_meta *meta)
-{
-	switch (env->prog->type) {
-	case BPF_PROG_TYPE_SCHED_CLS:
-	case BPF_PROG_TYPE_SCHED_ACT:
-	case BPF_PROG_TYPE_XDP:
-		if (meta)
-			return meta->pkt_access;
-
-		env->seen_direct_write = true;
-		return true;
-	default:
-		return false;
-	}
-}
-
-static int check_packet_access(struct bpf_verifier_env *env, u32 regno, int off,
-			       int size)
-{
-	struct bpf_reg_state *regs = env->cur_state.regs;
-	struct bpf_reg_state *reg = &regs[regno];
-
-	off += reg->off;
-	if (off < 0 || size <= 0 || off + size > reg->range) {
-		verbose("invalid access to packet, off=%d size=%d, R%d(id=%d,off=%d,r=%d)\n",
-			off, size, regno, reg->id, reg->off, reg->range);
-		return -EACCES;
-	}
-	return 0;
-}
-
 /* check access to 'struct bpf_context' fields */
-static int check_ctx_access(struct bpf_verifier_env *env, int off, int size,
-			    enum bpf_access_type t, enum bpf_reg_type *reg_type)
+static int check_ctx_access(struct verifier_env *env, int off, int size,
+			    enum bpf_access_type t)
 {
-	/* for analyzer ctx accesses are already validated and converted */
-	if (env->analyzer_ops)
-		return 0;
-
 	if (env->prog->aux->ops->is_valid_access &&
-	    env->prog->aux->ops->is_valid_access(off, size, t, reg_type)) {
-		/* remember the offset of last byte accessed in ctx */
-		if (env->prog->aux->max_ctx_offset < off + size)
-			env->prog->aux->max_ctx_offset = off + size;
+	    env->prog->aux->ops->is_valid_access(off, size, t))
 		return 0;
-	}
 
 	verbose("invalid bpf_context access off=%d size=%d\n", off, size);
 	return -EACCES;
 }
 
-static bool __is_pointer_value(bool allow_ptr_leaks,
-			       const struct bpf_reg_state *reg)
+static bool is_pointer_value(struct verifier_env *env, int regno)
 {
-	if (allow_ptr_leaks)
+	if (env->allow_ptr_leaks)
 		return false;
 
-	switch (reg->type) {
+	switch (env->cur_state.regs[regno].type) {
 	case UNKNOWN_VALUE:
 	case CONST_IMM:
 		return false;
@@ -720,141 +707,60 @@ static bool __is_pointer_value(bool allow_ptr_leaks,
 	}
 }
 
-static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
-{
-	return __is_pointer_value(env->allow_ptr_leaks, &env->cur_state.regs[regno]);
-}
-
-static bool is_ctx_reg(struct bpf_verifier_env *env, int regno)
+static bool is_ctx_reg(struct verifier_env *env, int regno)
 {
-	const struct bpf_reg_state *reg = &env->cur_state.regs[regno];
+	const struct reg_state *reg = &env->cur_state.regs[regno];
 
 	return reg->type == PTR_TO_CTX;
 }
 
-static int check_ptr_alignment(struct bpf_verifier_env *env,
-			       struct bpf_reg_state *reg, int off, int size)
-{
-	if (reg->type != PTR_TO_PACKET && reg->type != PTR_TO_MAP_VALUE_ADJ) {
-		if (off % size != 0) {
-			verbose("misaligned access off %d size %d\n",
-				off, size);
-			return -EACCES;
-		} else {
-			return 0;
-		}
-	}
-
-	if (IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
-		/* misaligned access to packet is ok on x86,arm,arm64 */
-		return 0;
-
-	if (reg->id && size != 1) {
-		verbose("Unknown packet alignment. Only byte-sized access allowed\n");
-		return -EACCES;
-	}
-
-	/* skb->data is NET_IP_ALIGN-ed */
-	if (reg->type == PTR_TO_PACKET &&
-	    (NET_IP_ALIGN + reg->off + off) % size != 0) {
-		verbose("misaligned packet access off %d+%d+%d size %d\n",
-			NET_IP_ALIGN, reg->off, off, size);
-		return -EACCES;
-	}
-	return 0;
-}
-
 /* check whether memory at (regno + off) is accessible for t = (read | write)
  * if t==write, value_regno is a register which value is stored into memory
  * if t==read, value_regno is a register which will receive the value from memory
  * if t==write && value_regno==-1, some unknown value is stored into memory
  * if t==read && value_regno==-1, don't care what we read from memory
  */
-static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno, int off,
+static int check_mem_access(struct verifier_env *env, int insn_idx, u32 regno, int off,
 			    int bpf_size, enum bpf_access_type t,
 			    int value_regno)
 {
-	struct bpf_verifier_state *state = &env->cur_state;
-	struct bpf_reg_state *reg = &state->regs[regno];
+	struct verifier_state *state = &env->cur_state;
 	int size, err = 0;
 
-	if (reg->type == PTR_TO_STACK)
-		off += reg->imm;
+	if (state->regs[regno].type == PTR_TO_STACK)
+		off += state->regs[regno].imm;
 
 	size = bpf_size_to_bytes(bpf_size);
 	if (size < 0)
 		return size;
 
-	err = check_ptr_alignment(env, reg, off, size);
-	if (err)
-		return err;
+	if (off % size != 0) {
+		verbose("misaligned access off %d size %d\n", off, size);
+		return -EACCES;
+	}
 
-	if (reg->type == PTR_TO_MAP_VALUE ||
-	    reg->type == PTR_TO_MAP_VALUE_ADJ) {
+	if (state->regs[regno].type == PTR_TO_MAP_VALUE) {
 		if (t == BPF_WRITE && value_regno >= 0 &&
 		    is_pointer_value(env, value_regno)) {
 			verbose("R%d leaks addr into map\n", value_regno);
 			return -EACCES;
 		}
-
-		/* If we adjusted the register to this map value at all then we
-		 * need to change off and size to min_value and max_value
-		 * respectively to make sure our theoretical access will be
-		 * safe.
-		 */
-		if (reg->type == PTR_TO_MAP_VALUE_ADJ) {
-			if (log_level)
-				print_verifier_state(state);
-			env->varlen_map_value_access = true;
-			/* The minimum value is only important with signed
-			 * comparisons where we can't assume the floor of a
-			 * value is 0.  If we are using signed variables for our
-			 * index'es we need to make sure that whatever we use
-			 * will have a set floor within our range.
-			 */
-			if (reg->min_value < 0) {
-				verbose("R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n",
-					regno);
-				return -EACCES;
-			}
-			err = check_map_access(env, regno, reg->min_value + off,
-					       size);
-			if (err) {
-				verbose("R%d min value is outside of the array range\n",
-					regno);
-				return err;
-			}
-
-			/* If we haven't set a max value then we need to bail
-			 * since we can't be sure we won't do bad things.
-			 */
-			if (reg->max_value == BPF_REGISTER_MAX_RANGE) {
-				verbose("R%d unbounded memory access, make sure to bounds check any array access into a map\n",
-					regno);
-				return -EACCES;
-			}
-			off += reg->max_value;
-		}
 		err = check_map_access(env, regno, off, size);
 		if (!err && t == BPF_READ && value_regno >= 0)
 			mark_reg_unknown_value(state->regs, value_regno);
 
-	} else if (reg->type == PTR_TO_CTX) {
-		enum bpf_reg_type reg_type = UNKNOWN_VALUE;
-
+	} else if (state->regs[regno].type == PTR_TO_CTX) {
 		if (t == BPF_WRITE && value_regno >= 0 &&
 		    is_pointer_value(env, value_regno)) {
 			verbose("R%d leaks addr into ctx\n", value_regno);
 			return -EACCES;
 		}
-		err = check_ctx_access(env, off, size, t, &reg_type);
-		if (!err && t == BPF_READ && value_regno >= 0) {
+		err = check_ctx_access(env, off, size, t);
+		if (!err && t == BPF_READ && value_regno >= 0)
 			mark_reg_unknown_value(state->regs, value_regno);
-			/* note that reg.[id|off|range] == 0 */
-			state->regs[value_regno].type = reg_type;
-		}
 
-	} else if (reg->type == FRAME_PTR || reg->type == PTR_TO_STACK) {
+	} else if (state->regs[regno].type == FRAME_PTR ||
+		   state->regs[regno].type == PTR_TO_STACK) {
 		if (off >= 0 || off < -MAX_BPF_STACK) {
 			verbose("invalid stack off=%d size=%d\n", off, size);
 			return -EACCES;
@@ -871,39 +777,17 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regn
 		} else {
 			err = check_stack_read(state, off, size, value_regno);
 		}
-	} else if (state->regs[regno].type == PTR_TO_PACKET) {
-		if (t == BPF_WRITE && !may_access_direct_pkt_data(env, NULL)) {
-			verbose("cannot write into packet\n");
-			return -EACCES;
-		}
-		if (t == BPF_WRITE && value_regno >= 0 &&
-		    is_pointer_value(env, value_regno)) {
-			verbose("R%d leaks addr into packet\n", value_regno);
-			return -EACCES;
-		}
-		err = check_packet_access(env, regno, off, size);
-		if (!err && t == BPF_READ && value_regno >= 0)
-			mark_reg_unknown_value(state->regs, value_regno);
 	} else {
 		verbose("R%d invalid mem access '%s'\n",
-			regno, reg_type_str[reg->type]);
+			regno, reg_type_str[state->regs[regno].type]);
 		return -EACCES;
 	}
-
-	if (!err && size <= 2 && value_regno >= 0 && env->allow_ptr_leaks &&
-	    state->regs[value_regno].type == UNKNOWN_VALUE) {
-		/* 1 or 2 byte load zero-extends, determine the number of
-		 * zero upper bits. Not doing it fo 4 byte load, since
-		 * such values cannot be added to ptr_to_packet anyway.
-		 */
-		state->regs[value_regno].imm = 64 - size * 8;
-	}
 	return err;
 }
 
-static int check_xadd(struct bpf_verifier_env *env, int insn_idx, struct bpf_insn *insn)
+static int check_xadd(struct verifier_env *env, int insn_idx, struct bpf_insn *insn)
 {
-	struct bpf_reg_state *regs = env->cur_state.regs;
+	struct reg_state *regs = env->cur_state.regs;
 	int err;
 
 	if ((BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) ||
@@ -948,25 +832,15 @@ static int check_xadd(struct bpf_verifier_env *env, int insn_idx, struct bpf_ins
  * bytes from that pointer, make sure that it's within stack boundary
  * and all elements of stack are initialized
  */
-static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
-				int access_size, bool zero_size_allowed,
-				struct bpf_call_arg_meta *meta)
+static int check_stack_boundary(struct verifier_env *env,
+				int regno, int access_size)
 {
-	struct bpf_verifier_state *state = &env->cur_state;
-	struct bpf_reg_state *regs = state->regs;
+	struct verifier_state *state = &env->cur_state;
+	struct reg_state *regs = state->regs;
 	int off, i;
 
-	if (regs[regno].type != PTR_TO_STACK) {
-		if (zero_size_allowed && access_size == 0 &&
-		    regs[regno].type == CONST_IMM &&
-		    regs[regno].imm  == 0)
-			return 0;
-
-		verbose("R%d type=%s expected=%s\n", regno,
-			reg_type_str[regs[regno].type],
-			reg_type_str[PTR_TO_STACK]);
+	if (regs[regno].type != PTR_TO_STACK)
 		return -EACCES;
-	}
 
 	off = regs[regno].imm;
 	if (off >= 0 || off < -MAX_BPF_STACK || off + access_size > 0 ||
@@ -976,12 +850,6 @@ static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
 		return -EACCES;
 	}
 
-	if (meta && meta->raw_mode) {
-		meta->access_size = access_size;
-		meta->regno = regno;
-		return 0;
-	}
-
 	for (i = 0; i < access_size; i++) {
 		if (state->stack_slot_type[MAX_BPF_STACK + off + i] != STACK_MISC) {
 			verbose("invalid indirect read from stack off %d+%d size %d\n",
@@ -992,18 +860,17 @@ static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
 	return 0;
 }
 
-static int check_func_arg(struct bpf_verifier_env *env, u32 regno,
-			  enum bpf_arg_type arg_type,
-			  struct bpf_call_arg_meta *meta)
+static int check_func_arg(struct verifier_env *env, u32 regno,
+			  enum bpf_arg_type arg_type, struct bpf_map **mapp)
 {
-	struct bpf_reg_state *regs = env->cur_state.regs, *reg = &regs[regno];
-	enum bpf_reg_type expected_type, type = reg->type;
+	struct reg_state *reg = env->cur_state.regs + regno;
+	enum bpf_reg_type expected_type;
 	int err = 0;
 
 	if (arg_type == ARG_DONTCARE)
 		return 0;
 
-	if (type == NOT_INIT) {
+	if (reg->type == NOT_INIT) {
 		verbose("R%d !read_ok\n", regno);
 		return -EACCES;
 	}
@@ -1016,55 +883,36 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 regno,
 		return 0;
 	}
 
-	if (type == PTR_TO_PACKET && !may_access_direct_pkt_data(env, meta)) {
-		verbose("helper access to the packet is not allowed\n");
-		return -EACCES;
-	}
-
-	if (arg_type == ARG_PTR_TO_MAP_KEY ||
+	if (arg_type == ARG_PTR_TO_STACK || arg_type == ARG_PTR_TO_MAP_KEY ||
 	    arg_type == ARG_PTR_TO_MAP_VALUE) {
 		expected_type = PTR_TO_STACK;
-		if (type != PTR_TO_PACKET && type != expected_type)
-			goto err_type;
-	} else if (arg_type == ARG_CONST_STACK_SIZE ||
-		   arg_type == ARG_CONST_STACK_SIZE_OR_ZERO) {
+	} else if (arg_type == ARG_CONST_STACK_SIZE) {
 		expected_type = CONST_IMM;
-		if (type != expected_type)
-			goto err_type;
 	} else if (arg_type == ARG_CONST_MAP_PTR) {
 		expected_type = CONST_PTR_TO_MAP;
-		if (type != expected_type)
-			goto err_type;
 	} else if (arg_type == ARG_PTR_TO_CTX) {
 		expected_type = PTR_TO_CTX;
-		if (type != expected_type)
-			goto err_type;
-	} else if (arg_type == ARG_PTR_TO_STACK ||
-		   arg_type == ARG_PTR_TO_RAW_STACK) {
-		expected_type = PTR_TO_STACK;
-		/* One exception here. In case function allows for NULL to be
-		 * passed in as argument, it's a CONST_IMM type. Final test
-		 * happens during stack boundary checking.
-		 */
-		if (type == CONST_IMM && reg->imm == 0)
-			/* final test in check_stack_boundary() */;
-		else if (type != PTR_TO_PACKET && type != expected_type)
-			goto err_type;
-		meta->raw_mode = arg_type == ARG_PTR_TO_RAW_STACK;
 	} else {
 		verbose("unsupported arg_type %d\n", arg_type);
 		return -EFAULT;
 	}
 
+	if (reg->type != expected_type) {
+		verbose("R%d type=%s expected=%s\n", regno,
+			reg_type_str[reg->type], reg_type_str[expected_type]);
+		return -EACCES;
+	}
+
 	if (arg_type == ARG_CONST_MAP_PTR) {
 		/* bpf_map_xxx(map_ptr) call: remember that map_ptr */
-		meta->map_ptr = reg->map_ptr;
+		*mapp = reg->map_ptr;
+
 	} else if (arg_type == ARG_PTR_TO_MAP_KEY) {
 		/* bpf_map_xxx(..., map_ptr, ..., key) call:
 		 * check that [key, key + map->key_size) are within
 		 * stack limits and initialized
 		 */
-		if (!meta->map_ptr) {
+		if (!*mapp) {
 			/* in function declaration map_ptr must come before
 			 * map_key, so that it's verified and known before
 			 * we have to check map_key here. Otherwise it means
@@ -1073,33 +921,20 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 regno,
 			verbose("invalid map_ptr to access map->key\n");
 			return -EACCES;
 		}
-		if (type == PTR_TO_PACKET)
-			err = check_packet_access(env, regno, 0,
-						  meta->map_ptr->key_size);
-		else
-			err = check_stack_boundary(env, regno,
-						   meta->map_ptr->key_size,
-						   false, NULL);
+		err = check_stack_boundary(env, regno, (*mapp)->key_size);
+
 	} else if (arg_type == ARG_PTR_TO_MAP_VALUE) {
 		/* bpf_map_xxx(..., map_ptr, ..., value) call:
 		 * check [value, value + map->value_size) validity
 		 */
-		if (!meta->map_ptr) {
+		if (!*mapp) {
 			/* kernel subsystem misconfigured verifier */
 			verbose("invalid map_ptr to access map->value\n");
 			return -EACCES;
 		}
-		if (type == PTR_TO_PACKET)
-			err = check_packet_access(env, regno, 0,
-						  meta->map_ptr->value_size);
-		else
-			err = check_stack_boundary(env, regno,
-						   meta->map_ptr->value_size,
-						   false, NULL);
-	} else if (arg_type == ARG_CONST_STACK_SIZE ||
-		   arg_type == ARG_CONST_STACK_SIZE_OR_ZERO) {
-		bool zero_size_allowed = (arg_type == ARG_CONST_STACK_SIZE_OR_ZERO);
+		err = check_stack_boundary(env, regno, (*mapp)->value_size);
 
+	} else if (arg_type == ARG_CONST_STACK_SIZE) {
 		/* bpf_xxx(..., buf, len) call will access 'len' bytes
 		 * from stack pointer 'buf'. Check it
 		 * note: regno == len, regno - 1 == buf
@@ -1109,18 +944,10 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 regno,
 			verbose("ARG_CONST_STACK_SIZE cannot be first argument\n");
 			return -EACCES;
 		}
-		if (regs[regno - 1].type == PTR_TO_PACKET)
-			err = check_packet_access(env, regno - 1, 0, reg->imm);
-		else
-			err = check_stack_boundary(env, regno - 1, reg->imm,
-						   zero_size_allowed, meta);
+		err = check_stack_boundary(env, regno - 1, reg->imm);
 	}
 
 	return err;
-err_type:
-	verbose("R%d type=%s expected=%s\n", regno,
-		reg_type_str[type], reg_type_str[expected_type]);
-	return -EACCES;
 }
 
 static int check_map_func_compatibility(struct bpf_map *map, int func_id)
@@ -1139,15 +966,6 @@ static int check_map_func_compatibility(struct bpf_map *map, int func_id)
 		    func_id != BPF_FUNC_perf_event_output)
 			goto error;
 		break;
-	case BPF_MAP_TYPE_STACK_TRACE:
-		if (func_id != BPF_FUNC_get_stackid)
-			goto error;
-		break;
-	case BPF_MAP_TYPE_CGROUP_ARRAY:
-		if (func_id != BPF_FUNC_skb_under_cgroup &&
-		    func_id != BPF_FUNC_current_task_under_cgroup)
-			goto error;
-		break;
 	default:
 		break;
 	}
@@ -1163,15 +981,6 @@ static int check_map_func_compatibility(struct bpf_map *map, int func_id)
 		if (map->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
 			goto error;
 		break;
-	case BPF_FUNC_get_stackid:
-		if (map->map_type != BPF_MAP_TYPE_STACK_TRACE)
-			goto error;
-		break;
-	case BPF_FUNC_current_task_under_cgroup:
-	case BPF_FUNC_skb_under_cgroup:
-		if (map->map_type != BPF_MAP_TYPE_CGROUP_ARRAY)
-			goto error;
-		break;
 	default:
 		break;
 	}
@@ -1183,55 +992,13 @@ error:
 	return -EINVAL;
 }
 
-static int check_raw_mode(const struct bpf_func_proto *fn)
-{
-	int count = 0;
-
-	if (fn->arg1_type == ARG_PTR_TO_RAW_STACK)
-		count++;
-	if (fn->arg2_type == ARG_PTR_TO_RAW_STACK)
-		count++;
-	if (fn->arg3_type == ARG_PTR_TO_RAW_STACK)
-		count++;
-	if (fn->arg4_type == ARG_PTR_TO_RAW_STACK)
-		count++;
-	if (fn->arg5_type == ARG_PTR_TO_RAW_STACK)
-		count++;
-
-	return count > 1 ? -EINVAL : 0;
-}
-
-static void clear_all_pkt_pointers(struct bpf_verifier_env *env)
+static int check_call(struct verifier_env *env, int func_id, int insn_idx)
 {
-	struct bpf_verifier_state *state = &env->cur_state;
-	struct bpf_reg_state *regs = state->regs, *reg;
-	int i;
-
-	for (i = 0; i < MAX_BPF_REG; i++)
-		if (regs[i].type == PTR_TO_PACKET ||
-		    regs[i].type == PTR_TO_PACKET_END)
-			mark_reg_unknown_value(regs, i);
-
-	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
-		if (state->stack_slot_type[i] != STACK_SPILL)
-			continue;
-		reg = &state->spilled_regs[i / BPF_REG_SIZE];
-		if (reg->type != PTR_TO_PACKET &&
-		    reg->type != PTR_TO_PACKET_END)
-			continue;
-		reg->type = UNKNOWN_VALUE;
-		reg->imm = 0;
-	}
-}
-
-static int check_call(struct bpf_verifier_env *env, int func_id, int insn_idx)
-{
-	struct bpf_verifier_state *state = &env->cur_state;
+	struct verifier_state *state = &env->cur_state;
 	const struct bpf_func_proto *fn = NULL;
-	struct bpf_reg_state *regs = state->regs;
-	struct bpf_reg_state *reg;
-	struct bpf_call_arg_meta meta;
-	bool changes_data;
+	struct reg_state *regs = state->regs;
+	struct bpf_map *map = NULL;
+	struct reg_state *reg;
 	int i, err;
 
 	/* find function prototype */
@@ -1254,53 +1021,30 @@ static int check_call(struct bpf_verifier_env *env, int func_id, int insn_idx)
 		return -EINVAL;
 	}
 
-	changes_data = bpf_helper_changes_skb_data(fn->func);
-
-	memset(&meta, 0, sizeof(meta));
-	meta.pkt_access = fn->pkt_access;
-
-	/* We only support one arg being in raw mode at the moment, which
-	 * is sufficient for the helper functions we have right now.
-	 */
-	err = check_raw_mode(fn);
-	if (err) {
-		verbose("kernel subsystem misconfigured func %d\n", func_id);
-		return err;
-	}
-
 	/* check args */
-	err = check_func_arg(env, BPF_REG_1, fn->arg1_type, &meta);
+	err = check_func_arg(env, BPF_REG_1, fn->arg1_type, &map);
 	if (err)
 		return err;
-	err = check_func_arg(env, BPF_REG_2, fn->arg2_type, &meta);
+	err = check_func_arg(env, BPF_REG_2, fn->arg2_type, &map);
 	if (err)
 		return err;
 	if (func_id == BPF_FUNC_tail_call) {
-		if (meta.map_ptr == NULL) {
+		if (map == NULL) {
 			verbose("verifier bug\n");
 			return -EINVAL;
 		}
-		env->insn_aux_data[insn_idx].map_ptr = meta.map_ptr;
+		env->insn_aux_data[insn_idx].map_ptr = map;
 	}
-	err = check_func_arg(env, BPF_REG_3, fn->arg3_type, &meta);
+	err = check_func_arg(env, BPF_REG_3, fn->arg3_type, &map);
 	if (err)
 		return err;
-	err = check_func_arg(env, BPF_REG_4, fn->arg4_type, &meta);
+	err = check_func_arg(env, BPF_REG_4, fn->arg4_type, &map);
 	if (err)
 		return err;
-	err = check_func_arg(env, BPF_REG_5, fn->arg5_type, &meta);
+	err = check_func_arg(env, BPF_REG_5, fn->arg5_type, &map);
 	if (err)
 		return err;
 
-	/* Mark slots with STACK_MISC in case of raw mode, stack offset
-	 * is inferred from register state.
-	 */
-	for (i = 0; i < meta.access_size; i++) {
-		err = check_mem_access(env, insn_idx, meta.regno, i, BPF_B, BPF_WRITE, -1);
-		if (err)
-			return err;
-	}
-
 	/* reset caller saved regs */
 	for (i = 0; i < CALLER_SAVED_REGS; i++) {
 		reg = regs + caller_saved[i];
@@ -1315,441 +1059,32 @@ static int check_call(struct bpf_verifier_env *env, int func_id, int insn_idx)
 		regs[BPF_REG_0].type = NOT_INIT;
 	} else if (fn->ret_type == RET_PTR_TO_MAP_VALUE_OR_NULL) {
 		regs[BPF_REG_0].type = PTR_TO_MAP_VALUE_OR_NULL;
-		regs[BPF_REG_0].max_value = regs[BPF_REG_0].min_value = 0;
 		/* remember map_ptr, so that check_map_access()
 		 * can check 'value_size' boundary of memory access
 		 * to map element returned from bpf_map_lookup_elem()
 		 */
-		if (meta.map_ptr == NULL) {
+		if (map == NULL) {
 			verbose("kernel subsystem misconfigured verifier\n");
 			return -EINVAL;
 		}
-		regs[BPF_REG_0].map_ptr = meta.map_ptr;
-		regs[BPF_REG_0].id = ++env->id_gen;
+		regs[BPF_REG_0].map_ptr = map;
 	} else {
 		verbose("unknown return type %d of func %d\n",
 			fn->ret_type, func_id);
 		return -EINVAL;
 	}
 
-	err = check_map_func_compatibility(meta.map_ptr, func_id);
+	err = check_map_func_compatibility(map, func_id);
 	if (err)
 		return err;
 
-	if (changes_data)
-		clear_all_pkt_pointers(env);
 	return 0;
 }
 
-static int check_packet_ptr_add(struct bpf_verifier_env *env,
-				struct bpf_insn *insn)
-{
-	struct bpf_reg_state *regs = env->cur_state.regs;
-	struct bpf_reg_state *dst_reg = &regs[insn->dst_reg];
-	struct bpf_reg_state *src_reg = &regs[insn->src_reg];
-	struct bpf_reg_state tmp_reg;
-	s32 imm;
-
-	if (BPF_SRC(insn->code) == BPF_K) {
-		/* pkt_ptr += imm */
-		imm = insn->imm;
-
-add_imm:
-		if (imm <= 0) {
-			verbose("addition of negative constant to packet pointer is not allowed\n");
-			return -EACCES;
-		}
-		if (imm >= MAX_PACKET_OFF ||
-		    imm + dst_reg->off >= MAX_PACKET_OFF) {
-			verbose("constant %d is too large to add to packet pointer\n",
-				imm);
-			return -EACCES;
-		}
-		/* a constant was added to pkt_ptr.
-		 * Remember it while keeping the same 'id'
-		 */
-		dst_reg->off += imm;
-	} else {
-		if (src_reg->type == PTR_TO_PACKET) {
-			/* R6=pkt(id=0,off=0,r=62) R7=imm22; r7 += r6 */
-			tmp_reg = *dst_reg;  /* save r7 state */
-			*dst_reg = *src_reg; /* copy pkt_ptr state r6 into r7 */
-			src_reg = &tmp_reg;  /* pretend it's src_reg state */
-			/* if the checks below reject it, the copy won't matter,
-			 * since we're rejecting the whole program. If all ok,
-			 * then imm22 state will be added to r7
-			 * and r7 will be pkt(id=0,off=22,r=62) while
-			 * r6 will stay as pkt(id=0,off=0,r=62)
-			 */
-		}
-
-		if (src_reg->type == CONST_IMM) {
-			/* pkt_ptr += reg where reg is known constant */
-			imm = src_reg->imm;
-			goto add_imm;
-		}
-		/* disallow pkt_ptr += reg
-		 * if reg is not uknown_value with guaranteed zero upper bits
-		 * otherwise pkt_ptr may overflow and addition will become
-		 * subtraction which is not allowed
-		 */
-		if (src_reg->type != UNKNOWN_VALUE) {
-			verbose("cannot add '%s' to ptr_to_packet\n",
-				reg_type_str[src_reg->type]);
-			return -EACCES;
-		}
-		if (src_reg->imm < 48) {
-			verbose("cannot add integer value with %lld upper zero bits to ptr_to_packet\n",
-				src_reg->imm);
-			return -EACCES;
-		}
-		/* dst_reg stays as pkt_ptr type and since some positive
-		 * integer value was added to the pointer, increment its 'id'
-		 */
-		dst_reg->id = ++env->id_gen;
-
-		/* something was added to pkt_ptr, set range and off to zero */
-		dst_reg->off = 0;
-		dst_reg->range = 0;
-	}
-	return 0;
-}
-
-static int evaluate_reg_alu(struct bpf_verifier_env *env, struct bpf_insn *insn)
-{
-	struct bpf_reg_state *regs = env->cur_state.regs;
-	struct bpf_reg_state *dst_reg = &regs[insn->dst_reg];
-	u8 opcode = BPF_OP(insn->code);
-	s64 imm_log2;
-
-	/* for type == UNKNOWN_VALUE:
-	 * imm > 0 -> number of zero upper bits
-	 * imm == 0 -> don't track which is the same as all bits can be non-zero
-	 */
-
-	if (BPF_SRC(insn->code) == BPF_X) {
-		struct bpf_reg_state *src_reg = &regs[insn->src_reg];
-
-		if (src_reg->type == UNKNOWN_VALUE && src_reg->imm > 0 &&
-		    dst_reg->imm && opcode == BPF_ADD) {
-			/* dreg += sreg
-			 * where both have zero upper bits. Adding them
-			 * can only result making one more bit non-zero
-			 * in the larger value.
-			 * Ex. 0xffff (imm=48) + 1 (imm=63) = 0x10000 (imm=47)
-			 *     0xffff (imm=48) + 0xffff = 0x1fffe (imm=47)
-			 */
-			dst_reg->imm = min(dst_reg->imm, src_reg->imm);
-			dst_reg->imm--;
-			return 0;
-		}
-		if (src_reg->type == CONST_IMM && src_reg->imm > 0 &&
-		    dst_reg->imm && opcode == BPF_ADD) {
-			/* dreg += sreg
-			 * where dreg has zero upper bits and sreg is const.
-			 * Adding them can only result making one more bit
-			 * non-zero in the larger value.
-			 */
-			imm_log2 = __ilog2_u64((long long)src_reg->imm);
-			dst_reg->imm = min(dst_reg->imm, 63 - imm_log2);
-			dst_reg->imm--;
-			return 0;
-		}
-		/* all other cases non supported yet, just mark dst_reg */
-		dst_reg->imm = 0;
-		return 0;
-	}
-
-	/* sign extend 32-bit imm into 64-bit to make sure that
-	 * negative values occupy bit 63. Note ilog2() would have
-	 * been incorrect, since sizeof(insn->imm) == 4
-	 */
-	imm_log2 = __ilog2_u64((long long)insn->imm);
-
-	if (dst_reg->imm && opcode == BPF_LSH) {
-		/* reg <<= imm
-		 * if reg was a result of 2 byte load, then its imm == 48
-		 * which means that upper 48 bits are zero and shifting this reg
-		 * left by 4 would mean that upper 44 bits are still zero
-		 */
-		dst_reg->imm -= insn->imm;
-	} else if (dst_reg->imm && opcode == BPF_MUL) {
-		/* reg *= imm
-		 * if multiplying by 14 subtract 4
-		 * This is conservative calculation of upper zero bits.
-		 * It's not trying to special case insn->imm == 1 or 0 cases
-		 */
-		dst_reg->imm -= imm_log2 + 1;
-	} else if (opcode == BPF_AND) {
-		/* reg &= imm */
-		dst_reg->imm = 63 - imm_log2;
-	} else if (dst_reg->imm && opcode == BPF_ADD) {
-		/* reg += imm */
-		dst_reg->imm = min(dst_reg->imm, 63 - imm_log2);
-		dst_reg->imm--;
-	} else if (opcode == BPF_RSH) {
-		/* reg >>= imm
-		 * which means that after right shift, upper bits will be zero
-		 * note that verifier already checked that
-		 * 0 <= imm < 64 for shift insn
-		 */
-		dst_reg->imm += insn->imm;
-		if (unlikely(dst_reg->imm > 64))
-			/* some dumb code did:
-			 * r2 = *(u32 *)mem;
-			 * r2 >>= 32;
-			 * and all bits are zero now */
-			dst_reg->imm = 64;
-	} else {
-		/* all other alu ops, means that we don't know what will
-		 * happen to the value, mark it with unknown number of zero bits
-		 */
-		dst_reg->imm = 0;
-	}
-
-	if (dst_reg->imm < 0) {
-		/* all 64 bits of the register can contain non-zero bits
-		 * and such value cannot be added to ptr_to_packet, since it
-		 * may overflow, mark it as unknown to avoid further eval
-		 */
-		dst_reg->imm = 0;
-	}
-	return 0;
-}
-
-static int evaluate_reg_imm_alu_unknown(struct bpf_verifier_env *env,
-					struct bpf_insn *insn)
-{
-	struct bpf_reg_state *regs = env->cur_state.regs;
-	struct bpf_reg_state *dst_reg = &regs[insn->dst_reg];
-	struct bpf_reg_state *src_reg = &regs[insn->src_reg];
-	u8 opcode = BPF_OP(insn->code);
-	s64 imm_log2 = __ilog2_u64((long long)dst_reg->imm);
-
-	/* BPF_X code with src_reg->type UNKNOWN_VALUE here. */
-	if (src_reg->imm > 0 && dst_reg->imm) {
-		switch (opcode) {
-		case BPF_ADD:
-			/* dreg += sreg
-			 * where both have zero upper bits. Adding them
-			 * can only result making one more bit non-zero
-			 * in the larger value.
-			 * Ex. 0xffff (imm=48) + 1 (imm=63) = 0x10000 (imm=47)
-			 *     0xffff (imm=48) + 0xffff = 0x1fffe (imm=47)
-			 */
-			dst_reg->imm = min(src_reg->imm, 63 - imm_log2);
-			dst_reg->imm--;
-			break;
-		case BPF_AND:
-			/* dreg &= sreg
-			 * AND can not extend zero bits only shrink
-			 * Ex.  0x00..00ffffff
-			 *    & 0x0f..ffffffff
-			 *     ----------------
-			 *      0x00..00ffffff
-			 */
-			dst_reg->imm = max(src_reg->imm, 63 - imm_log2);
-			break;
-		case BPF_OR:
-			/* dreg |= sreg
-			 * OR can only extend zero bits
-			 * Ex.  0x00..00ffffff
-			 *    | 0x0f..ffffffff
-			 *     ----------------
-			 *      0x0f..00ffffff
-			 */
-			dst_reg->imm = min(src_reg->imm, 63 - imm_log2);
-			break;
-		case BPF_SUB:
-		case BPF_MUL:
-		case BPF_RSH:
-		case BPF_LSH:
-			/* These may be flushed out later */
-		default:
-			mark_reg_unknown_value(regs, insn->dst_reg);
-		}
-	} else {
-		mark_reg_unknown_value(regs, insn->dst_reg);
-	}
-
-	dst_reg->type = UNKNOWN_VALUE;
-	return 0;
-}
-
-static int evaluate_reg_imm_alu(struct bpf_verifier_env *env,
-				struct bpf_insn *insn)
-{
-	struct bpf_reg_state *regs = env->cur_state.regs;
-	struct bpf_reg_state *dst_reg = &regs[insn->dst_reg];
-	struct bpf_reg_state *src_reg = &regs[insn->src_reg];
-	u8 opcode = BPF_OP(insn->code);
-
-	if (BPF_SRC(insn->code) == BPF_X && src_reg->type == UNKNOWN_VALUE)
-		return evaluate_reg_imm_alu_unknown(env, insn);
-
-	/* dst_reg->type == CONST_IMM here, simulate execution of 'add' insn.
-	 * Don't care about overflow or negative values, just add them
-	 */
-	if (opcode == BPF_ADD && BPF_SRC(insn->code) == BPF_K)
-		dst_reg->imm += insn->imm;
-	else if (opcode == BPF_ADD && BPF_SRC(insn->code) == BPF_X &&
-		 src_reg->type == CONST_IMM)
-		dst_reg->imm += src_reg->imm;
-	else
-		mark_reg_unknown_value(regs, insn->dst_reg);
-	return 0;
-}
-
-static void check_reg_overflow(struct bpf_reg_state *reg)
-{
-	if (reg->max_value > BPF_REGISTER_MAX_RANGE)
-		reg->max_value = BPF_REGISTER_MAX_RANGE;
-	if (reg->min_value < BPF_REGISTER_MIN_RANGE ||
-	    reg->min_value > BPF_REGISTER_MAX_RANGE)
-		reg->min_value = BPF_REGISTER_MIN_RANGE;
-}
-
-static void adjust_reg_min_max_vals(struct bpf_verifier_env *env,
-				    struct bpf_insn *insn)
-{
-	struct bpf_reg_state *regs = env->cur_state.regs, *dst_reg;
-	s64 min_val = BPF_REGISTER_MIN_RANGE;
-	u64 max_val = BPF_REGISTER_MAX_RANGE;
-	bool min_set = false, max_set = false;
-	u8 opcode = BPF_OP(insn->code);
-
-	dst_reg = &regs[insn->dst_reg];
-	if (BPF_SRC(insn->code) == BPF_X) {
-		check_reg_overflow(&regs[insn->src_reg]);
-		min_val = regs[insn->src_reg].min_value;
-		max_val = regs[insn->src_reg].max_value;
-
-		/* If the source register is a random pointer then the
-		 * min_value/max_value values represent the range of the known
-		 * accesses into that value, not the actual min/max value of the
-		 * register itself.  In this case we have to reset the reg range
-		 * values so we know it is not safe to look at.
-		 */
-		if (regs[insn->src_reg].type != CONST_IMM &&
-		    regs[insn->src_reg].type != UNKNOWN_VALUE) {
-			min_val = BPF_REGISTER_MIN_RANGE;
-			max_val = BPF_REGISTER_MAX_RANGE;
-		}
-	} else if (insn->imm < BPF_REGISTER_MAX_RANGE &&
-		   (s64)insn->imm > BPF_REGISTER_MIN_RANGE) {
-		min_val = max_val = insn->imm;
-		min_set = max_set = true;
-	}
-
-	/* We don't know anything about what was done to this register, mark it
-	 * as unknown. Also, if both derived bounds came from signed/unsigned
-	 * mixed compares and one side is unbounded, we cannot really do anything
-	 * with them as boundaries cannot be trusted. Thus, arithmetic of two
-	 * regs of such kind will get invalidated bounds on the dst side.
-	 */
-	if ((min_val == BPF_REGISTER_MIN_RANGE &&
-	     max_val == BPF_REGISTER_MAX_RANGE) ||
-	    (BPF_SRC(insn->code) == BPF_X &&
-	     ((min_val != BPF_REGISTER_MIN_RANGE &&
-	       max_val == BPF_REGISTER_MAX_RANGE) ||
-	      (min_val == BPF_REGISTER_MIN_RANGE &&
-	       max_val != BPF_REGISTER_MAX_RANGE) ||
-	      (dst_reg->min_value != BPF_REGISTER_MIN_RANGE &&
-	       dst_reg->max_value == BPF_REGISTER_MAX_RANGE) ||
-	      (dst_reg->min_value == BPF_REGISTER_MIN_RANGE &&
-	       dst_reg->max_value != BPF_REGISTER_MAX_RANGE)) &&
-	     regs[insn->dst_reg].value_from_signed !=
-	     regs[insn->src_reg].value_from_signed)) {
-		reset_reg_range_values(regs, insn->dst_reg);
-		return;
-	}
-
-	/* If one of our values was at the end of our ranges then we can't just
-	 * do our normal operations to the register, we need to set the values
-	 * to the min/max since they are undefined.
-	 */
-	if (opcode != BPF_SUB) {
-		if (min_val == BPF_REGISTER_MIN_RANGE)
-			dst_reg->min_value = BPF_REGISTER_MIN_RANGE;
-		if (max_val == BPF_REGISTER_MAX_RANGE)
-			dst_reg->max_value = BPF_REGISTER_MAX_RANGE;
-	}
-
-	switch (opcode) {
-	case BPF_ADD:
-		if (dst_reg->min_value != BPF_REGISTER_MIN_RANGE)
-			dst_reg->min_value += min_val;
-		if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
-			dst_reg->max_value += max_val;
-		break;
-	case BPF_SUB:
-		/* If one of our values was at the end of our ranges, then the
-		 * _opposite_ value in the dst_reg goes to the end of our range.
-		 */
-		if (min_val == BPF_REGISTER_MIN_RANGE)
-			dst_reg->max_value = BPF_REGISTER_MAX_RANGE;
-		if (max_val == BPF_REGISTER_MAX_RANGE)
-			dst_reg->min_value = BPF_REGISTER_MIN_RANGE;
-		if (dst_reg->min_value != BPF_REGISTER_MIN_RANGE)
-			dst_reg->min_value -= max_val;
-		if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
-			dst_reg->max_value -= min_val;
-		break;
-	case BPF_MUL:
-		if (dst_reg->min_value != BPF_REGISTER_MIN_RANGE)
-			dst_reg->min_value *= min_val;
-		if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
-			dst_reg->max_value *= max_val;
-		break;
-	case BPF_AND:
-		/* Disallow AND'ing of negative numbers, ain't nobody got time
-		 * for that.  Otherwise the minimum is 0 and the max is the max
-		 * value we could AND against.
-		 */
-		if (min_val < 0)
-			dst_reg->min_value = BPF_REGISTER_MIN_RANGE;
-		else
-			dst_reg->min_value = 0;
-		dst_reg->max_value = max_val;
-		break;
-	case BPF_LSH:
-		/* Gotta have special overflow logic here, if we're shifting
-		 * more than MAX_RANGE then just assume we have an invalid
-		 * range.
-		 */
-		if (min_val > ilog2(BPF_REGISTER_MAX_RANGE))
-			dst_reg->min_value = BPF_REGISTER_MIN_RANGE;
-		else if (dst_reg->min_value != BPF_REGISTER_MIN_RANGE)
-			dst_reg->min_value <<= min_val;
-
-		if (max_val > ilog2(BPF_REGISTER_MAX_RANGE))
-			dst_reg->max_value = BPF_REGISTER_MAX_RANGE;
-		else if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
-			dst_reg->max_value <<= max_val;
-		break;
-	case BPF_RSH:
-		/* RSH by a negative number is undefined, and the BPF_RSH is an
-		 * unsigned shift, so make the appropriate casts.
-		 */
-		if (min_val < 0 || dst_reg->min_value < 0)
-			reset_reg_range_values(regs, insn->dst_reg);
-		else
-			dst_reg->min_value = (u64)(dst_reg->min_value) >> max_val;
-		if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
-			dst_reg->max_value >>= min_val;
-		break;
-	default:
-		reset_reg_range_values(regs, insn->dst_reg);
-		break;
-	}
-
-	check_reg_overflow(dst_reg);
-}
-
 /* check validity of 32-bit and 64-bit arithmetic operations */
-static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
+static int check_alu_op(struct verifier_env *env, struct bpf_insn *insn)
 {
-	struct bpf_reg_state *regs = env->cur_state.regs, *dst_reg;
+	struct reg_state *regs = env->cur_state.regs;
 	u8 opcode = BPF_OP(insn->code);
 	int err;
 
@@ -1810,11 +1145,6 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 		if (err)
 			return err;
 
-		/* we are setting our register to something new, we need to
-		 * reset its range values.
-		 */
-		reset_reg_range_values(regs, insn->dst_reg);
-
 		if (BPF_SRC(insn->code) == BPF_X) {
 			if (BPF_CLASS(insn->code) == BPF_ALU64) {
 				/* case: R1 = R2
@@ -1827,23 +1157,16 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 						insn->src_reg);
 					return -EACCES;
 				}
-				mark_reg_unknown_value(regs, insn->dst_reg);
+				regs[insn->dst_reg].type = UNKNOWN_VALUE;
+				regs[insn->dst_reg].map_ptr = NULL;
 			}
-		} else {
+		} else if (BPF_CLASS(insn->code) == BPF_ALU64 ||
+			   insn->imm >= 0) {
 			/* case: R = imm
 			 * remember the value we stored into this reg
 			 */
-			u64 imm;
-
-			if (BPF_CLASS(insn->code) == BPF_ALU64)
-				imm = insn->imm;
-			else
-				imm = (u32)insn->imm;
-
 			regs[insn->dst_reg].type = CONST_IMM;
-			regs[insn->dst_reg].imm = imm;
-			regs[insn->dst_reg].max_value = imm;
-			regs[insn->dst_reg].min_value = imm;
+			regs[insn->dst_reg].imm = insn->imm;
 		}
 
 	} else if (opcode > BPF_END) {
@@ -1852,6 +1175,8 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 
 	} else {	/* all other ALU ops: and, sub, xor, add, ... */
 
+		bool stack_relative = false;
+
 		if (BPF_SRC(insn->code) == BPF_X) {
 			if (insn->imm != 0 || insn->off != 0) {
 				verbose("BPF_ALU uses reserved fields\n");
@@ -1894,68 +1219,11 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 			}
 		}
 
-		/* check dest operand */
-		err = check_reg_arg(regs, insn->dst_reg, DST_OP_NO_MARK);
-		if (err)
-			return err;
-
-		dst_reg = &regs[insn->dst_reg];
-
-		/* first we want to adjust our ranges. */
-		adjust_reg_min_max_vals(env, insn);
-
 		/* pattern match 'bpf_add Rx, imm' instruction */
 		if (opcode == BPF_ADD && BPF_CLASS(insn->code) == BPF_ALU64 &&
-		    dst_reg->type == FRAME_PTR && BPF_SRC(insn->code) == BPF_K) {
-			dst_reg->type = PTR_TO_STACK;
-			dst_reg->imm = insn->imm;
-			return 0;
-		} else if (opcode == BPF_ADD &&
-			   BPF_CLASS(insn->code) == BPF_ALU64 &&
-			   dst_reg->type == PTR_TO_STACK &&
-			   ((BPF_SRC(insn->code) == BPF_X &&
-			     regs[insn->src_reg].type == CONST_IMM) ||
-			    BPF_SRC(insn->code) == BPF_K)) {
-			if (BPF_SRC(insn->code) == BPF_X) {
-				/* check in case the register contains a big
-				 * 64-bit value
-				 */
-				if (regs[insn->src_reg].imm < -MAX_BPF_STACK ||
-				    regs[insn->src_reg].imm > MAX_BPF_STACK) {
-					verbose("R%d value too big in R%d pointer arithmetic\n",
-						insn->src_reg, insn->dst_reg);
-					return -EACCES;
-				}
-				dst_reg->imm += regs[insn->src_reg].imm;
-			} else {
-				/* safe against overflow: addition of 32-bit
-				 * numbers in 64-bit representation
-				 */
-				dst_reg->imm += insn->imm;
-			}
-			if (dst_reg->imm > 0 || dst_reg->imm < -MAX_BPF_STACK) {
-				verbose("R%d out-of-bounds pointer arithmetic\n",
-					insn->dst_reg);
-				return -EACCES;
-			}
-			return 0;
-		} else if (opcode == BPF_ADD &&
-			   BPF_CLASS(insn->code) == BPF_ALU64 &&
-			   (dst_reg->type == PTR_TO_PACKET ||
-			    (BPF_SRC(insn->code) == BPF_X &&
-			     regs[insn->src_reg].type == PTR_TO_PACKET))) {
-			/* ptr_to_packet += K|X */
-			return check_packet_ptr_add(env, insn);
-		} else if (BPF_CLASS(insn->code) == BPF_ALU64 &&
-			   dst_reg->type == UNKNOWN_VALUE &&
-			   env->allow_ptr_leaks) {
-			/* unknown += K|X */
-			return evaluate_reg_alu(env, insn);
-		} else if (BPF_CLASS(insn->code) == BPF_ALU64 &&
-			   dst_reg->type == CONST_IMM &&
-			   env->allow_ptr_leaks) {
-			/* reg_imm += K|X */
-			return evaluate_reg_imm_alu(env, insn);
+		    regs[insn->dst_reg].type == FRAME_PTR &&
+		    BPF_SRC(insn->code) == BPF_K) {
+			stack_relative = true;
 		} else if (is_pointer_value(env, insn->dst_reg)) {
 			verbose("R%d pointer arithmetic prohibited\n",
 				insn->dst_reg);
@@ -1967,275 +1235,25 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 			return -EACCES;
 		}
 
-		/* If we did pointer math on a map value then just set it to our
-		 * PTR_TO_MAP_VALUE_ADJ type so we can deal with any stores or
-		 * loads to this register appropriately, otherwise just mark the
-		 * register as unknown.
-		 */
-		if (env->allow_ptr_leaks &&
-		    BPF_CLASS(insn->code) == BPF_ALU64 && opcode == BPF_ADD &&
-		    (dst_reg->type == PTR_TO_MAP_VALUE ||
-		     dst_reg->type == PTR_TO_MAP_VALUE_ADJ))
-			dst_reg->type = PTR_TO_MAP_VALUE_ADJ;
-		else
-			mark_reg_unknown_value(regs, insn->dst_reg);
-	}
-
-	return 0;
-}
-
-static void find_good_pkt_pointers(struct bpf_verifier_state *state,
-				   struct bpf_reg_state *dst_reg)
-{
-	struct bpf_reg_state *regs = state->regs, *reg;
-	int i;
-
-	/* LLVM can generate two kind of checks:
-	 *
-	 * Type 1:
-	 *
-	 *   r2 = r3;
-	 *   r2 += 8;
-	 *   if (r2 > pkt_end) goto <handle exception>
-	 *   <access okay>
-	 *
-	 *   Where:
-	 *     r2 == dst_reg, pkt_end == src_reg
-	 *     r2=pkt(id=n,off=8,r=0)
-	 *     r3=pkt(id=n,off=0,r=0)
-	 *
-	 * Type 2:
-	 *
-	 *   r2 = r3;
-	 *   r2 += 8;
-	 *   if (pkt_end >= r2) goto <access okay>
-	 *   <handle exception>
-	 *
-	 *   Where:
-	 *     pkt_end == dst_reg, r2 == src_reg
-	 *     r2=pkt(id=n,off=8,r=0)
-	 *     r3=pkt(id=n,off=0,r=0)
-	 *
-	 * Find register r3 and mark its range as r3=pkt(id=n,off=0,r=8)
-	 * so that range of bytes [r3, r3 + 8) is safe to access.
-	 */
-
-	for (i = 0; i < MAX_BPF_REG; i++)
-		if (regs[i].type == PTR_TO_PACKET && regs[i].id == dst_reg->id)
-			/* keep the maximum range already checked */
-			regs[i].range = max(regs[i].range, dst_reg->off);
-
-	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
-		if (state->stack_slot_type[i] != STACK_SPILL)
-			continue;
-		reg = &state->spilled_regs[i / BPF_REG_SIZE];
-		if (reg->type == PTR_TO_PACKET && reg->id == dst_reg->id)
-			reg->range = max(reg->range, dst_reg->off);
-	}
-}
-
-/* Adjusts the register min/max values in the case that the dst_reg is the
- * variable register that we are working on, and src_reg is a constant or we're
- * simply doing a BPF_K check.
- */
-static void reg_set_min_max(struct bpf_reg_state *true_reg,
-			    struct bpf_reg_state *false_reg, u64 val,
-			    u8 opcode)
-{
-	bool value_from_signed = true;
-	bool is_range = true;
-
-	switch (opcode) {
-	case BPF_JEQ:
-		/* If this is false then we know nothing Jon Snow, but if it is
-		 * true then we know for sure.
-		 */
-		true_reg->max_value = true_reg->min_value = val;
-		is_range = false;
-		break;
-	case BPF_JNE:
-		/* If this is true we know nothing Jon Snow, but if it is false
-		 * we know the value for sure;
-		 */
-		false_reg->max_value = false_reg->min_value = val;
-		is_range = false;
-		break;
-	case BPF_JGT:
-		value_from_signed = false;
-		/* fallthrough */
-	case BPF_JSGT:
-		if (true_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(true_reg, 0);
-		if (false_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(false_reg, 0);
-		if (opcode == BPF_JGT) {
-			/* Unsigned comparison, the minimum value is 0. */
-			false_reg->min_value = 0;
-		}
-		/* If this is false then we know the maximum val is val,
-		 * otherwise we know the min val is val+1.
-		 */
-		false_reg->max_value = val;
-		false_reg->value_from_signed = value_from_signed;
-		true_reg->min_value = val + 1;
-		true_reg->value_from_signed = value_from_signed;
-		break;
-	case BPF_JGE:
-		value_from_signed = false;
-		/* fallthrough */
-	case BPF_JSGE:
-		if (true_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(true_reg, 0);
-		if (false_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(false_reg, 0);
-		if (opcode == BPF_JGE) {
-			/* Unsigned comparison, the minimum value is 0. */
-			false_reg->min_value = 0;
-		}
-		/* If this is false then we know the maximum value is val - 1,
-		 * otherwise we know the mimimum value is val.
-		 */
-		false_reg->max_value = val - 1;
-		false_reg->value_from_signed = value_from_signed;
-		true_reg->min_value = val;
-		true_reg->value_from_signed = value_from_signed;
-		break;
-	default:
-		break;
-	}
-
-	check_reg_overflow(false_reg);
-	check_reg_overflow(true_reg);
-	if (is_range) {
-		if (__is_pointer_value(false, false_reg))
-			reset_reg_range_values(false_reg, 0);
-		if (__is_pointer_value(false, true_reg))
-			reset_reg_range_values(true_reg, 0);
-	}
-}
-
-/* Same as above, but for the case that dst_reg is a CONST_IMM reg and src_reg
- * is the variable reg.
- */
-static void reg_set_min_max_inv(struct bpf_reg_state *true_reg,
-				struct bpf_reg_state *false_reg, u64 val,
-				u8 opcode)
-{
-	bool value_from_signed = true;
-	bool is_range = true;
+		/* check dest operand */
+		err = check_reg_arg(regs, insn->dst_reg, DST_OP);
+		if (err)
+			return err;
 
-	switch (opcode) {
-	case BPF_JEQ:
-		/* If this is false then we know nothing Jon Snow, but if it is
-		 * true then we know for sure.
-		 */
-		true_reg->max_value = true_reg->min_value = val;
-		is_range = false;
-		break;
-	case BPF_JNE:
-		/* If this is true we know nothing Jon Snow, but if it is false
-		 * we know the value for sure;
-		 */
-		false_reg->max_value = false_reg->min_value = val;
-		is_range = false;
-		break;
-	case BPF_JGT:
-		value_from_signed = false;
-		/* fallthrough */
-	case BPF_JSGT:
-		if (true_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(true_reg, 0);
-		if (false_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(false_reg, 0);
-		if (opcode == BPF_JGT) {
-			/* Unsigned comparison, the minimum value is 0. */
-			true_reg->min_value = 0;
+		if (stack_relative) {
+			regs[insn->dst_reg].type = PTR_TO_STACK;
+			regs[insn->dst_reg].imm = insn->imm;
 		}
-		/*
-		 * If this is false, then the val is <= the register, if it is
-		 * true the register <= to the val.
-		 */
-		false_reg->min_value = val;
-		false_reg->value_from_signed = value_from_signed;
-		true_reg->max_value = val - 1;
-		true_reg->value_from_signed = value_from_signed;
-		break;
-	case BPF_JGE:
-		value_from_signed = false;
-		/* fallthrough */
-	case BPF_JSGE:
-		if (true_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(true_reg, 0);
-		if (false_reg->value_from_signed != value_from_signed)
-			reset_reg_range_values(false_reg, 0);
-		if (opcode == BPF_JGE) {
-			/* Unsigned comparison, the minimum value is 0. */
-			true_reg->min_value = 0;
-		}
-		/* If this is false then constant < register, if it is true then
-		 * the register < constant.
-		 */
-		false_reg->min_value = val + 1;
-		false_reg->value_from_signed = value_from_signed;
-		true_reg->max_value = val;
-		true_reg->value_from_signed = value_from_signed;
-		break;
-	default:
-		break;
-	}
-
-	check_reg_overflow(false_reg);
-	check_reg_overflow(true_reg);
-	if (is_range) {
-		if (__is_pointer_value(false, false_reg))
-			reset_reg_range_values(false_reg, 0);
-		if (__is_pointer_value(false, true_reg))
-			reset_reg_range_values(true_reg, 0);
 	}
-}
-
-static void mark_map_reg(struct bpf_reg_state *regs, u32 regno, u32 id,
-			 enum bpf_reg_type type)
-{
-	struct bpf_reg_state *reg = &regs[regno];
-
-	if (reg->type == PTR_TO_MAP_VALUE_OR_NULL && reg->id == id) {
-		reg->type = type;
-		/* We don't need id from this point onwards anymore, thus we
-		 * should better reset it, so that state pruning has chances
-		 * to take effect.
-		 */
-		reg->id = 0;
-		if (type == UNKNOWN_VALUE)
-			__mark_reg_unknown_value(regs, regno);
-	}
-}
-
-/* The logic is similar to find_good_pkt_pointers(), both could eventually
- * be folded together at some point.
- */
-static void mark_map_regs(struct bpf_verifier_state *state, u32 regno,
-			  enum bpf_reg_type type)
-{
-	struct bpf_reg_state *regs = state->regs;
-	u32 id = regs[regno].id;
-	int i;
-
-	for (i = 0; i < MAX_BPF_REG; i++)
-		mark_map_reg(regs, i, id, type);
 
-	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
-		if (state->stack_slot_type[i] != STACK_SPILL)
-			continue;
-		mark_map_reg(state->spilled_regs, i / BPF_REG_SIZE, id, type);
-	}
+	return 0;
 }
 
-static int check_cond_jmp_op(struct bpf_verifier_env *env,
+static int check_cond_jmp_op(struct verifier_env *env,
 			     struct bpf_insn *insn, int *insn_idx)
 {
-	struct bpf_verifier_state *other_branch, *this_branch = &env->cur_state;
-	struct bpf_reg_state *regs = this_branch->regs, *dst_reg;
+	struct reg_state *regs = env->cur_state.regs;
+	struct verifier_state *other_branch;
 	u8 opcode = BPF_OP(insn->code);
 	int err;
 
@@ -2272,12 +1290,11 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 	if (err)
 		return err;
 
-	dst_reg = &regs[insn->dst_reg];
-
 	/* detect if R == 0 where R was initialized to zero earlier */
 	if (BPF_SRC(insn->code) == BPF_K &&
 	    (opcode == BPF_JEQ || opcode == BPF_JNE) &&
-	    dst_reg->type == CONST_IMM && dst_reg->imm == insn->imm) {
+	    regs[insn->dst_reg].type == CONST_IMM &&
+	    regs[insn->dst_reg].imm == insn->imm) {
 		if (opcode == BPF_JEQ) {
 			/* if (imm == imm) goto pc+off;
 			 * only follow the goto, ignore fall-through
@@ -2297,48 +1314,46 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 	if (!other_branch)
 		return -EFAULT;
 
-	/* detect if we are comparing against a constant value so we can adjust
-	 * our min/max values for our dst register.
-	 */
-	if (BPF_SRC(insn->code) == BPF_X) {
-		if (regs[insn->src_reg].type == CONST_IMM)
-			reg_set_min_max(&other_branch->regs[insn->dst_reg],
-					dst_reg, regs[insn->src_reg].imm,
-					opcode);
-		else if (dst_reg->type == CONST_IMM)
-			reg_set_min_max_inv(&other_branch->regs[insn->src_reg],
-					    &regs[insn->src_reg], dst_reg->imm,
-					    opcode);
-	} else {
-		reg_set_min_max(&other_branch->regs[insn->dst_reg],
-					dst_reg, insn->imm, opcode);
-	}
-
-	/* detect if R == 0 where R is returned from bpf_map_lookup_elem() */
+	/* detect if R == 0 where R is returned value from bpf_map_lookup_elem() */
 	if (BPF_SRC(insn->code) == BPF_K &&
-	    insn->imm == 0 && (opcode == BPF_JEQ || opcode == BPF_JNE) &&
-	    dst_reg->type == PTR_TO_MAP_VALUE_OR_NULL) {
-		/* Mark all identical map registers in each branch as either
-		 * safe or unknown depending R == 0 or R != 0 conditional.
-		 */
-		mark_map_regs(this_branch, insn->dst_reg,
-			      opcode == BPF_JEQ ? PTR_TO_MAP_VALUE : UNKNOWN_VALUE);
-		mark_map_regs(other_branch, insn->dst_reg,
-			      opcode == BPF_JEQ ? UNKNOWN_VALUE : PTR_TO_MAP_VALUE);
-	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JGT &&
-		   dst_reg->type == PTR_TO_PACKET &&
-		   regs[insn->src_reg].type == PTR_TO_PACKET_END) {
-		find_good_pkt_pointers(this_branch, dst_reg);
-	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JGE &&
-		   dst_reg->type == PTR_TO_PACKET_END &&
-		   regs[insn->src_reg].type == PTR_TO_PACKET) {
-		find_good_pkt_pointers(other_branch, &regs[insn->src_reg]);
+	    insn->imm == 0 && (opcode == BPF_JEQ ||
+			       opcode == BPF_JNE) &&
+	    regs[insn->dst_reg].type == PTR_TO_MAP_VALUE_OR_NULL) {
+		if (opcode == BPF_JEQ) {
+			/* next fallthrough insn can access memory via
+			 * this register
+			 */
+			regs[insn->dst_reg].type = PTR_TO_MAP_VALUE;
+			/* branch targer cannot access it, since reg == 0 */
+			other_branch->regs[insn->dst_reg].type = CONST_IMM;
+			other_branch->regs[insn->dst_reg].imm = 0;
+		} else {
+			other_branch->regs[insn->dst_reg].type = PTR_TO_MAP_VALUE;
+			regs[insn->dst_reg].type = CONST_IMM;
+			regs[insn->dst_reg].imm = 0;
+		}
 	} else if (is_pointer_value(env, insn->dst_reg)) {
 		verbose("R%d pointer comparison prohibited\n", insn->dst_reg);
 		return -EACCES;
+	} else if (BPF_SRC(insn->code) == BPF_K &&
+		   (opcode == BPF_JEQ || opcode == BPF_JNE)) {
+
+		if (opcode == BPF_JEQ) {
+			/* detect if (R == imm) goto
+			 * and in the target state recognize that R = imm
+			 */
+			other_branch->regs[insn->dst_reg].type = CONST_IMM;
+			other_branch->regs[insn->dst_reg].imm = insn->imm;
+		} else {
+			/* detect if (R != imm) goto
+			 * and in the fall-through state recognize that R = imm
+			 */
+			regs[insn->dst_reg].type = CONST_IMM;
+			regs[insn->dst_reg].imm = insn->imm;
+		}
 	}
 	if (log_level)
-		print_verifier_state(this_branch);
+		print_verifier_state(env);
 	return 0;
 }
 
@@ -2351,9 +1366,9 @@ static struct bpf_map *ld_imm64_to_map_ptr(struct bpf_insn *insn)
 }
 
 /* verify BPF_LD_IMM64 instruction */
-static int check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn)
+static int check_ld_imm(struct verifier_env *env, struct bpf_insn *insn)
 {
-	struct bpf_reg_state *regs = env->cur_state.regs;
+	struct reg_state *regs = env->cur_state.regs;
 	int err;
 
 	if (BPF_SIZE(insn->code) != BPF_DW) {
@@ -2369,19 +1384,9 @@ static int check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn)
 	if (err)
 		return err;
 
-	if (insn->src_reg == 0) {
-		/* generic move 64-bit immediate into a register,
-		 * only analyzer needs to collect the ld_imm value.
-		 */
-		u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
-
-		if (!env->analyzer_ops)
-			return 0;
-
-		regs[insn->dst_reg].type = CONST_IMM;
-		regs[insn->dst_reg].imm = imm;
+	if (insn->src_reg == 0)
+		/* generic move 64-bit immediate into a register */
 		return 0;
-	}
 
 	/* replace_map_fd_with_map_ptr() should have caught bad ld_imm64 */
 	BUG_ON(insn->src_reg != BPF_PSEUDO_MAP_FD);
@@ -2418,22 +1423,22 @@ static bool may_access_skb(enum bpf_prog_type type)
  * Output:
  *   R0 - 8/16/32-bit skb data converted to cpu endianness
  */
-static int check_ld_abs(struct bpf_verifier_env *env, struct bpf_insn *insn)
+static int check_ld_abs(struct verifier_env *env, struct bpf_insn *insn)
 {
-	struct bpf_reg_state *regs = env->cur_state.regs;
+	struct reg_state *regs = env->cur_state.regs;
 	u8 mode = BPF_MODE(insn->code);
-	struct bpf_reg_state *reg;
+	struct reg_state *reg;
 	int i, err;
 
 	if (!may_access_skb(env->prog->type)) {
-		verbose("BPF_LD_[ABS|IND] instructions not allowed for this program type\n");
+		verbose("BPF_LD_ABS|IND instructions not allowed for this program type\n");
 		return -EINVAL;
 	}
 
 	if (insn->dst_reg != BPF_REG_0 || insn->off != 0 ||
 	    BPF_SIZE(insn->code) == BPF_DW ||
 	    (mode == BPF_ABS && insn->src_reg != BPF_REG_0)) {
-		verbose("BPF_LD_[ABS|IND] uses reserved fields\n");
+		verbose("BPF_LD_ABS uses reserved fields\n");
 		return -EINVAL;
 	}
 
@@ -2508,7 +1513,7 @@ enum {
 	BRANCH = 2,
 };
 
-#define STATE_LIST_MARK ((struct bpf_verifier_state_list *) -1L)
+#define STATE_LIST_MARK ((struct verifier_state_list *) -1L)
 
 static int *insn_stack;	/* stack of insns to process */
 static int cur_stack;	/* current stack index */
@@ -2519,7 +1524,7 @@ static int *insn_state;
  * w - next instruction
  * e - edge
  */
-static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
+static int push_insn(int t, int w, int e, struct verifier_env *env)
 {
 	if (e == FALLTHROUGH && insn_state[t] >= (DISCOVERED | FALLTHROUGH))
 		return 0;
@@ -2560,7 +1565,7 @@ static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
 /* non-recursive depth-first-search to detect loops in BPF program
  * loop == back-edge in directed graph
  */
-static int check_cfg(struct bpf_verifier_env *env)
+static int check_cfg(struct verifier_env *env)
 {
 	struct bpf_insn *insns = env->prog->insnsi;
 	int insn_cnt = env->prog->len;
@@ -2597,8 +1602,6 @@ peek_stack:
 				goto peek_stack;
 			else if (ret < 0)
 				goto err_free;
-			if (t + 1 < insn_cnt)
-				env->explored_states[t + 1] = STATE_LIST_MARK;
 		} else if (opcode == BPF_JA) {
 			if (BPF_SRC(insns[t].code) != BPF_K) {
 				ret = -EINVAL;
@@ -2618,7 +1621,6 @@ peek_stack:
 				env->explored_states[t + 1] = STATE_LIST_MARK;
 		} else {
 			/* conditional jump with two edges */
-			env->explored_states[t] = STATE_LIST_MARK;
 			ret = push_insn(t, t + 1, FALLTHROUGH, env);
 			if (ret == 1)
 				goto peek_stack;
@@ -2667,59 +1669,6 @@ err_free:
 	return ret;
 }
 
-/* the following conditions reduce the number of explored insns
- * from ~140k to ~80k for ultra large programs that use a lot of ptr_to_packet
- */
-static bool compare_ptrs_to_packet(struct bpf_reg_state *old,
-				   struct bpf_reg_state *cur)
-{
-	if (old->id != cur->id)
-		return false;
-
-	/* old ptr_to_packet is more conservative, since it allows smaller
-	 * range. Ex:
-	 * old(off=0,r=10) is equal to cur(off=0,r=20), because
-	 * old(off=0,r=10) means that with range=10 the verifier proceeded
-	 * further and found no issues with the program. Now we're in the same
-	 * spot with cur(off=0,r=20), so we're safe too, since anything further
-	 * will only be looking at most 10 bytes after this pointer.
-	 */
-	if (old->off == cur->off && old->range < cur->range)
-		return true;
-
-	/* old(off=20,r=10) is equal to cur(off=22,re=22 or 5 or 0)
-	 * since both cannot be used for packet access and safe(old)
-	 * pointer has smaller off that could be used for further
-	 * 'if (ptr > data_end)' check
-	 * Ex:
-	 * old(off=20,r=10) and cur(off=22,r=22) and cur(off=22,r=0) mean
-	 * that we cannot access the packet.
-	 * The safe range is:
-	 * [ptr, ptr + range - off)
-	 * so whenever off >=range, it means no safe bytes from this pointer.
-	 * When comparing old->off <= cur->off, it means that older code
-	 * went with smaller offset and that offset was later
-	 * used to figure out the safe range after 'if (ptr > data_end)' check
-	 * Say, 'old' state was explored like:
-	 * ... R3(off=0, r=0)
-	 * R4 = R3 + 20
-	 * ... now R4(off=20,r=0)  <-- here
-	 * if (R4 > data_end)
-	 * ... R4(off=20,r=20), R3(off=0,r=20) and R3 can be used to access.
-	 * ... the code further went all the way to bpf_exit.
-	 * Now the 'cur' state at the mark 'here' has R4(off=30,r=0).
-	 * old_R4(off=20,r=0) equal to cur_R4(off=30,r=0), since if the verifier
-	 * goes further, such cur_R4 will give larger safe packet range after
-	 * 'if (R4 > data_end)' and all further insn were already good with r=20,
-	 * so they will be good with r=30 and we can prune the search.
-	 */
-	if (old->off <= cur->off &&
-	    old->off >= old->range && cur->off >= cur->range)
-		return true;
-
-	return false;
-}
-
 /* compare two verifier states
  *
  * all states stored in state_list are known to be valid, since
@@ -2746,49 +1695,19 @@ static bool compare_ptrs_to_packet(struct bpf_reg_state *old,
  * whereas register type in current state is meaningful, it means that
  * the current state will reach 'bpf_exit' instruction safely
  */
-static bool states_equal(struct bpf_verifier_env *env,
-			 struct bpf_verifier_state *old,
-			 struct bpf_verifier_state *cur)
+static bool states_equal(struct verifier_state *old, struct verifier_state *cur)
 {
-	bool varlen_map_access = env->varlen_map_value_access;
-	struct bpf_reg_state *rold, *rcur;
 	int i;
 
 	for (i = 0; i < MAX_BPF_REG; i++) {
-		rold = &old->regs[i];
-		rcur = &cur->regs[i];
-
-		if (memcmp(rold, rcur, sizeof(*rold)) == 0)
-			continue;
-
-		/* If the ranges were not the same, but everything else was and
-		 * we didn't do a variable access into a map then we are a-ok.
-		 */
-		if (!varlen_map_access &&
-		    memcmp(rold, rcur, offsetofend(struct bpf_reg_state, id)) == 0)
-			continue;
-
-		/* If we didn't map access then again we don't care about the
-		 * mismatched range values and it's ok if our old type was
-		 * UNKNOWN and we didn't go to a NOT_INIT'ed or pointer reg.
-		 */
-		if (rold->type == NOT_INIT ||
-		    (!varlen_map_access && rold->type == UNKNOWN_VALUE &&
-		     rcur->type != NOT_INIT &&
-		     !__is_pointer_value(env->allow_ptr_leaks, rcur)))
-			continue;
-
-		/* Don't care about the reg->id in this case. */
-		if (rold->type == PTR_TO_MAP_VALUE_OR_NULL &&
-		    rcur->type == PTR_TO_MAP_VALUE_OR_NULL &&
-		    rold->map_ptr == rcur->map_ptr)
-			continue;
-
-		if (rold->type == PTR_TO_PACKET && rcur->type == PTR_TO_PACKET &&
-		    compare_ptrs_to_packet(rold, rcur))
-			continue;
-
-		return false;
+		if (memcmp(&old->regs[i], &cur->regs[i],
+			   sizeof(old->regs[0])) != 0) {
+			if (old->regs[i].type == NOT_INIT ||
+			    (old->regs[i].type == UNKNOWN_VALUE &&
+			     cur->regs[i].type != NOT_INIT))
+				continue;
+			return false;
+		}
 	}
 
 	for (i = 0; i < MAX_BPF_STACK; i++) {
@@ -2810,9 +1729,9 @@ static bool states_equal(struct bpf_verifier_env *env,
 			 * the same, check that stored pointers types
 			 * are the same as well.
 			 * Ex: explored safe path could have stored
-			 * (bpf_reg_state) {.type = PTR_TO_STACK, .imm = -8}
+			 * (struct reg_state) {.type = PTR_TO_STACK, .imm = -8}
 			 * but current path has stored:
-			 * (bpf_reg_state) {.type = PTR_TO_STACK, .imm = -16}
+			 * (struct reg_state) {.type = PTR_TO_STACK, .imm = -16}
 			 * such verifier states are not equivalent.
 			 * return false to continue verification of this path
 			 */
@@ -2823,10 +1742,10 @@ static bool states_equal(struct bpf_verifier_env *env,
 	return true;
 }
 
-static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
+static int is_state_visited(struct verifier_env *env, int insn_idx)
 {
-	struct bpf_verifier_state_list *new_sl;
-	struct bpf_verifier_state_list *sl;
+	struct verifier_state_list *new_sl;
+	struct verifier_state_list *sl;
 
 	sl = env->explored_states[insn_idx];
 	if (!sl)
@@ -2836,7 +1755,7 @@ static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
 		return 0;
 
 	while (sl != STATE_LIST_MARK) {
-		if (states_equal(env, &sl->state, &env->cur_state))
+		if (states_equal(&sl->state, &env->cur_state))
 			/* reached equivalent register/stack state,
 			 * prune the search
 			 */
@@ -2850,7 +1769,7 @@ static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
 	 * it will be rejected. Since there are no loops, we won't be
 	 * seeing this 'insn_idx' instruction again on the way to bpf_exit
 	 */
-	new_sl = kmalloc(sizeof(struct bpf_verifier_state_list), GFP_USER);
+	new_sl = kmalloc(sizeof(struct verifier_state_list), GFP_USER);
 	if (!new_sl)
 		return -ENOMEM;
 
@@ -2861,20 +1780,11 @@ static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
 	return 0;
 }
 
-static int ext_analyzer_insn_hook(struct bpf_verifier_env *env,
-				  int insn_idx, int prev_insn_idx)
+static int do_check(struct verifier_env *env)
 {
-	if (!env->analyzer_ops || !env->analyzer_ops->insn_hook)
-		return 0;
-
-	return env->analyzer_ops->insn_hook(env, insn_idx, prev_insn_idx);
-}
-
-static int do_check(struct bpf_verifier_env *env)
-{
-	struct bpf_verifier_state *state = &env->cur_state;
+	struct verifier_state *state = &env->cur_state;
 	struct bpf_insn *insns = env->prog->insnsi;
-	struct bpf_reg_state *regs = state->regs;
+	struct reg_state *regs = state->regs;
 	int insn_cnt = env->prog->len;
 	int insn_idx, prev_insn_idx = 0;
 	int insn_processed = 0;
@@ -2882,7 +1792,6 @@ static int do_check(struct bpf_verifier_env *env)
 
 	init_reg_state(regs);
 	insn_idx = 0;
-	env->varlen_map_value_access = false;
 	for (;;) {
 		struct bpf_insn *insn;
 		u8 class;
@@ -2897,7 +1806,7 @@ static int do_check(struct bpf_verifier_env *env)
 		insn = &insns[insn_idx];
 		class = BPF_CLASS(insn->code);
 
-		if (++insn_processed > BPF_COMPLEXITY_LIMIT_INSNS) {
+		if (++insn_processed > 32768) {
 			verbose("BPF program is too large. Proccessed %d insn\n",
 				insn_processed);
 			return -E2BIG;
@@ -2918,15 +1827,9 @@ static int do_check(struct bpf_verifier_env *env)
 			goto process_bpf_exit;
 		}
 
-		if (signal_pending(current))
-			return -EAGAIN;
-
-		if (need_resched())
-			cond_resched();
-
 		if (log_level && do_print_state) {
 			verbose("\nfrom %d to %d:", prev_insn_idx, insn_idx);
-			print_verifier_state(&env->cur_state);
+			print_verifier_state(env);
 			do_print_state = false;
 		}
 
@@ -2935,10 +1838,6 @@ static int do_check(struct bpf_verifier_env *env)
 			print_bpf_insn(env, insn);
 		}
 
-		err = ext_analyzer_insn_hook(env, insn_idx, prev_insn_idx);
-		if (err)
-			return err;
-
 		env->insn_aux_data[insn_idx].seen = true;
 		if (class == BPF_ALU || class == BPF_ALU64) {
 			err = check_alu_op(env, insn);
@@ -2970,7 +1869,6 @@ static int do_check(struct bpf_verifier_env *env)
 			if (err)
 				return err;
 
-			reset_reg_range_values(regs, insn->dst_reg);
 			if (BPF_SIZE(insn->code) != BPF_W &&
 			    BPF_SIZE(insn->code) != BPF_DW) {
 				insn_idx++;
@@ -3148,7 +2046,6 @@ process_bpf_exit:
 				verbose("invalid BPF_LD mode\n");
 				return -EINVAL;
 			}
-			reset_reg_range_values(regs, insn->dst_reg);
 		} else {
 			verbose("unknown insn class %d\n", class);
 			return -EINVAL;
@@ -3157,32 +2054,17 @@ process_bpf_exit:
 		insn_idx++;
 	}
 
-	verbose("processed %d insns\n", insn_processed);
-	return 0;
-}
-
-static int check_map_prog_compatibility(struct bpf_map *map,
-					struct bpf_prog *prog)
-
-{
-	if (prog->type == BPF_PROG_TYPE_PERF_EVENT &&
-	    (map->map_type == BPF_MAP_TYPE_HASH ||
-	     map->map_type == BPF_MAP_TYPE_PERCPU_HASH) &&
-	    (map->map_flags & BPF_F_NO_PREALLOC)) {
-		verbose("perf_event programs can only use preallocated hash map\n");
-		return -EINVAL;
-	}
 	return 0;
 }
 
 /* look for pseudo eBPF instructions that access map FDs and
  * replace them with actual map pointers
  */
-static int replace_map_fd_with_map_ptr(struct bpf_verifier_env *env)
+static int replace_map_fd_with_map_ptr(struct verifier_env *env)
 {
 	struct bpf_insn *insn = env->prog->insnsi;
 	int insn_cnt = env->prog->len;
-	int i, j, err;
+	int i, j;
 
 	for (i = 0; i < insn_cnt; i++, insn++) {
 		if (BPF_CLASS(insn->code) == BPF_LDX &&
@@ -3226,12 +2108,6 @@ static int replace_map_fd_with_map_ptr(struct bpf_verifier_env *env)
 				return PTR_ERR(map);
 			}
 
-			err = check_map_prog_compatibility(map, env->prog);
-			if (err) {
-				fdput(f);
-				return err;
-			}
-
 			/* store map pointer inside BPF_LD_IMM64 instruction */
 			insn[0].imm = (u32) (unsigned long) map;
 			insn[1].imm = ((u64) (unsigned long) map) >> 32;
@@ -3275,7 +2151,7 @@ next_insn:
 }
 
 /* drop refcnt of maps used by the rejected program */
-static void release_maps(struct bpf_verifier_env *env)
+static void release_maps(struct verifier_env *env)
 {
 	int i;
 
@@ -3284,7 +2160,7 @@ static void release_maps(struct bpf_verifier_env *env)
 }
 
 /* convert pseudo BPF_LD_IMM64 into generic BPF_LD_IMM64 */
-static void convert_pseudo_ld_imm64(struct bpf_verifier_env *env)
+static void convert_pseudo_ld_imm64(struct verifier_env *env)
 {
 	struct bpf_insn *insn = env->prog->insnsi;
 	int insn_cnt = env->prog->len;
@@ -3299,7 +2175,7 @@ static void convert_pseudo_ld_imm64(struct bpf_verifier_env *env)
  * insni[off, off + cnt).  Adjust corresponding insn_aux_data by copying
  * [0, off) and [off, end) to new locations, so the patched range stays zero
  */
-static int adjust_insn_aux_data(struct bpf_verifier_env *env, u32 prog_len,
+static int adjust_insn_aux_data(struct verifier_env *env, u32 prog_len,
 				u32 off, u32 cnt)
 {
 	struct bpf_insn_aux_data *new_data, *old_data = env->insn_aux_data;
@@ -3320,7 +2196,7 @@ static int adjust_insn_aux_data(struct bpf_verifier_env *env, u32 prog_len,
 	return 0;
 }
 
-static struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off,
+static struct bpf_prog *bpf_patch_insn_data(struct verifier_env *env, u32 off,
 					    const struct bpf_insn *patch, u32 len)
 {
 	struct bpf_prog *new_prog;
@@ -3337,7 +2213,7 @@ static struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 of
  * branches that are dead at run time. Malicious programs can have dead code
  * too. Therefore replace all dead at-run-time code with nops.
  */
-static void sanitize_dead_code(struct bpf_verifier_env *env)
+static void sanitize_dead_code(struct verifier_env *env)
 {
 	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
 	struct bpf_insn nop = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
@@ -3355,37 +2231,21 @@ static void sanitize_dead_code(struct bpf_verifier_env *env)
 /* convert load instructions that access fields of 'struct __sk_buff'
  * into sequence of instructions that access fields of 'struct sk_buff'
  */
-static int convert_ctx_accesses(struct bpf_verifier_env *env)
+static int convert_ctx_accesses(struct verifier_env *env)
 {
-	const struct bpf_verifier_ops *ops = env->prog->aux->ops;
+	struct bpf_insn *insn = env->prog->insnsi;
 	const int insn_cnt = env->prog->len;
-	struct bpf_insn insn_buf[16], *insn;
+	struct bpf_insn insn_buf[16];
 	struct bpf_prog *new_prog;
 	enum bpf_access_type type;
-	int i, cnt, delta = 0;
-
-	if (ops->gen_prologue) {
-		cnt = ops->gen_prologue(insn_buf, env->seen_direct_write,
-					env->prog);
-		if (cnt >= ARRAY_SIZE(insn_buf)) {
-			verbose("bpf verifier is misconfigured\n");
-			return -EINVAL;
-		} else if (cnt) {
-			new_prog = bpf_patch_insn_data(env, 0, insn_buf, cnt);
-			if (!new_prog)
-				return -ENOMEM;
-
-			env->prog = new_prog;
-			delta += cnt - 1;
-		}
-	}
+	int i, delta = 0;
 
-	if (!ops->convert_ctx_access)
+	if (!env->prog->aux->ops->convert_ctx_access)
 		return 0;
 
-	insn = env->prog->insnsi + delta;
-
 	for (i = 0; i < insn_cnt; i++, insn++) {
+		u32 cnt;
+
 		if (insn->code == (BPF_LDX | BPF_MEM | BPF_W) ||
 		    insn->code == (BPF_LDX | BPF_MEM | BPF_DW))
 			type = BPF_READ;
@@ -3426,8 +2286,9 @@ static int convert_ctx_accesses(struct bpf_verifier_env *env)
 		if (env->insn_aux_data[i + delta].ptr_type != PTR_TO_CTX)
 			continue;
 
-		cnt = ops->convert_ctx_access(type, insn->dst_reg, insn->src_reg,
-					      insn->off, insn_buf, env->prog);
+		cnt = env->prog->aux->ops->
+			convert_ctx_access(type, insn->dst_reg, insn->src_reg,
+					   insn->off, insn_buf, env->prog);
 		if (cnt == 0 || cnt >= ARRAY_SIZE(insn_buf)) {
 			verbose("bpf verifier is misconfigured\n");
 			return -EINVAL;
@@ -3451,7 +2312,7 @@ static int convert_ctx_accesses(struct bpf_verifier_env *env)
  *
  * this function is called after eBPF program passed verification
  */
-static int fixup_bpf_calls(struct bpf_verifier_env *env)
+static int fixup_bpf_calls(struct verifier_env *env)
 {
 	struct bpf_prog *prog = env->prog;
 	struct bpf_insn *insn = prog->insnsi;
@@ -3462,7 +2323,6 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 	struct bpf_map *map_ptr;
 	int i, cnt, delta = 0;
 
-
 	for (i = 0; i < insn_cnt; i++, insn++) {
 		if (insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
 		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
@@ -3494,7 +2354,7 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 			 * conditional branch in the interpeter for every normal
 			 * call and to prevent accidental JITing by JIT compiler
 			 * that doesn't support bpf_tail_call yet
- 			 */
+			 */
 			insn->imm = 0;
 			insn->code |= BPF_X;
 
@@ -3540,9 +2400,9 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 	return 0;
 }
 
-static void free_states(struct bpf_verifier_env *env)
+static void free_states(struct verifier_env *env)
 {
-	struct bpf_verifier_state_list *sl, *sln;
+	struct verifier_state_list *sl, *sln;
 	int i;
 
 	if (!env->explored_states)
@@ -3565,16 +2425,16 @@ static void free_states(struct bpf_verifier_env *env)
 int bpf_check(struct bpf_prog **prog, union bpf_attr *attr)
 {
 	char __user *log_ubuf = NULL;
-	struct bpf_verifier_env *env;
+	struct verifier_env *env;
 	int ret = -EINVAL;
 
 	if ((*prog)->len <= 0 || (*prog)->len > BPF_MAXINSNS)
 		return -E2BIG;
 
-	/* 'struct bpf_verifier_env' can be global, but since it's not small,
+	/* 'struct verifier_env' can be global, but since it's not small,
 	 * allocate/free it every time bpf_check() is called
 	 */
-	env = kzalloc(sizeof(struct bpf_verifier_env), GFP_KERNEL);
+	env = kzalloc(sizeof(struct verifier_env), GFP_KERNEL);
 	if (!env)
 		return -ENOMEM;
 
@@ -3616,7 +2476,7 @@ int bpf_check(struct bpf_prog **prog, union bpf_attr *attr)
 		goto skip_full_check;
 
 	env->explored_states = kcalloc(env->prog->len,
-				       sizeof(struct bpf_verifier_state_list *),
+				       sizeof(struct verifier_state_list *),
 				       GFP_USER);
 	ret = -ENOMEM;
 	if (!env->explored_states)
@@ -3694,54 +2554,3 @@ err_free_env:
 	kfree(env);
 	return ret;
 }
-
-int bpf_analyzer(struct bpf_prog *prog, const struct bpf_ext_analyzer_ops *ops,
-		 void *priv)
-{
-	struct bpf_verifier_env *env;
-	int ret;
-
-	env = kzalloc(sizeof(struct bpf_verifier_env), GFP_KERNEL);
-	if (!env)
-		return -ENOMEM;
-
-	env->insn_aux_data = vzalloc(sizeof(struct bpf_insn_aux_data) *
-				     prog->len);
-	ret = -ENOMEM;
-	if (!env->insn_aux_data)
-		goto err_free_env;
-	env->prog = prog;
-	env->analyzer_ops = ops;
-	env->analyzer_priv = priv;
-
-	/* grab the mutex to protect few globals used by verifier */
-	mutex_lock(&bpf_verifier_lock);
-
-	log_level = 0;
-
-	env->explored_states = kcalloc(env->prog->len,
-				       sizeof(struct bpf_verifier_state_list *),
-				       GFP_KERNEL);
-	ret = -ENOMEM;
-	if (!env->explored_states)
-		goto skip_full_check;
-
-	ret = check_cfg(env);
-	if (ret < 0)
-		goto skip_full_check;
-
-	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);
-
-	ret = do_check(env);
-
-skip_full_check:
-	while (pop_stack(env, NULL) >= 0);
-	free_states(env);
-
-	mutex_unlock(&bpf_verifier_lock);
-	vfree(env->insn_aux_data);
-err_free_env:
-	kfree(env);
-	return ret;
-}
-EXPORT_SYMBOL_GPL(bpf_analyzer);
diff --git a/kernel/cgroup.c b/kernel/cgroup.c
index d36c4f914a1e..fe08e12683fe 100644
--- a/kernel/cgroup.c
+++ b/kernel/cgroup.c
@@ -59,13 +59,6 @@
 #include <linux/delay.h>
 #include <linux/cpuset.h>
 #include <linux/atomic.h>
-#include <linux/proc_ns.h>
-#include <linux/nsproxy.h>
-#include <linux/file.h>
-#include <net/sock.h>
-
-#define CREATE_TRACE_POINTS
-#include <trace/events/cgroup.h>
 
 /*
  * pidlists linger the following amount before being destroyed.  The goal
@@ -184,16 +177,10 @@ EXPORT_SYMBOL_GPL(cgrp_dfl_root);
  * The default hierarchy always exists but is hidden until mounted for the
  * first time.  This is for backward compatibility.
  */
-static bool cgrp_dfl_visible;
-
-/* Controllers blocked by the commandline in v1 */
-static u16 cgroup_no_v1_mask;
+static bool cgrp_dfl_root_visible;
 
 /* some controllers are not supported in the default hierarchy */
-static u16 cgrp_dfl_inhibit_ss_mask;
-
-/* some controllers are implicitly enabled on the default hierarchy */
-static unsigned long cgrp_dfl_implicit_ss_mask;
+static unsigned long cgrp_dfl_root_inhibit_ss_mask;
 
 /* The list of hierarchy roots */
 
@@ -217,34 +204,23 @@ static u64 css_serial_nr_next = 1;
  * fork/exit handlers to call. This avoids us having to do extra work in the
  * fork/exit path to check which subsystems have fork/exit callbacks.
  */
-static u16 have_fork_callback __read_mostly;
-static u16 have_exit_callback __read_mostly;
-static u16 have_free_callback __read_mostly;
-
-/* cgroup namespace for init task */
-struct cgroup_namespace init_cgroup_ns = {
-	.count		= { .counter = 2, },
-	.user_ns	= &init_user_ns,
-	.ns.ops		= &cgroupns_operations,
-	.ns.inum	= PROC_CGROUP_INIT_INO,
-	.root_cset	= &init_css_set,
-};
+static unsigned long have_fork_callback __read_mostly;
+static unsigned long have_exit_callback __read_mostly;
+static unsigned long have_free_callback __read_mostly;
 
 /* Ditto for the can_fork callback. */
-static u16 have_canfork_callback __read_mostly;
+static unsigned long have_canfork_callback __read_mostly;
 
 static struct file_system_type cgroup2_fs_type;
 static struct cftype cgroup_dfl_base_files[];
 static struct cftype cgroup_legacy_base_files[];
 
-static int rebind_subsystems(struct cgroup_root *dst_root, u16 ss_mask);
-static void cgroup_lock_and_drain_offline(struct cgroup *cgrp);
-static int cgroup_apply_control(struct cgroup *cgrp);
-static void cgroup_finalize_control(struct cgroup *cgrp, int ret);
+static int rebind_subsystems(struct cgroup_root *dst_root,
+			     unsigned long ss_mask);
 static void css_task_iter_advance(struct css_task_iter *it);
 static int cgroup_destroy_locked(struct cgroup *cgrp);
-static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
-					      struct cgroup_subsys *ss);
+static int create_css(struct cgroup *cgrp, struct cgroup_subsys *ss,
+		      bool visible);
 static void css_release(struct percpu_ref *ref);
 static void kill_css(struct cgroup_subsys_state *css);
 static int cgroup_addrm_files(struct cgroup_subsys_state *css,
@@ -267,11 +243,6 @@ static bool cgroup_ssid_enabled(int ssid)
 	return static_key_enabled(cgroup_subsys_enabled_key[ssid]);
 }
 
-static bool cgroup_ssid_no_v1(int ssid)
-{
-	return cgroup_no_v1_mask & (1 << ssid);
-}
-
 /**
  * cgroup_on_dfl - test whether a cgroup is on the default hierarchy
  * @cgrp: the cgroup of interest
@@ -361,30 +332,13 @@ static void cgroup_idr_remove(struct idr *idr, int id)
 	spin_unlock_bh(&cgroup_idr_lock);
 }
 
-/* subsystems visibly enabled on a cgroup */
-static u16 cgroup_control(struct cgroup *cgrp)
-{
-	struct cgroup *parent = cgroup_parent(cgrp);
-	u16 root_ss_mask = cgrp->root->subsys_mask;
-
-	if (parent)
-		return parent->subtree_control;
-
-	if (cgroup_on_dfl(cgrp))
-		root_ss_mask &= ~(cgrp_dfl_inhibit_ss_mask |
-				  cgrp_dfl_implicit_ss_mask);
-	return root_ss_mask;
-}
-
-/* subsystems enabled on a cgroup */
-static u16 cgroup_ss_mask(struct cgroup *cgrp)
+static struct cgroup *cgroup_parent(struct cgroup *cgrp)
 {
-	struct cgroup *parent = cgroup_parent(cgrp);
-
-	if (parent)
-		return parent->subtree_ss_mask;
+	struct cgroup_subsys_state *parent_css = cgrp->self.parent;
 
-	return cgrp->root->subsys_mask;
+	if (parent_css)
+		return container_of(parent_css, struct cgroup, self);
+	return NULL;
 }
 
 /**
@@ -426,15 +380,16 @@ static struct cgroup_subsys_state *cgroup_e_css(struct cgroup *cgrp,
 	if (!ss)
 		return &cgrp->self;
 
+	if (!(cgrp->root->subsys_mask & (1 << ss->id)))
+		return NULL;
+
 	/*
 	 * This function is used while updating css associations and thus
-	 * can't test the csses directly.  Test ss_mask.
+	 * can't test the csses directly.  Use ->child_subsys_mask.
 	 */
-	while (!(cgroup_ss_mask(cgrp) & (1 << ss->id))) {
+	while (cgroup_parent(cgrp) &&
+	       !(cgroup_parent(cgrp)->child_subsys_mask & (1 << ss->id)))
 		cgrp = cgroup_parent(cgrp);
-		if (!cgrp)
-			return NULL;
-	}
 
 	return cgroup_css(cgrp, ss);
 }
@@ -478,6 +433,22 @@ static inline bool cgroup_is_dead(const struct cgroup *cgrp)
 	return !(cgrp->self.flags & CSS_ONLINE);
 }
 
+static void cgroup_get(struct cgroup *cgrp)
+{
+	WARN_ON_ONCE(cgroup_is_dead(cgrp));
+	css_get(&cgrp->self);
+}
+
+static bool cgroup_tryget(struct cgroup *cgrp)
+{
+	return css_tryget(&cgrp->self);
+}
+
+static void cgroup_put(struct cgroup *cgrp)
+{
+	css_put(&cgrp->self);
+}
+
 struct cgroup_subsys_state *of_css(struct kernfs_open_file *of)
 {
 	struct cgroup *cgrp = of->kn->parent->priv;
@@ -498,6 +469,25 @@ struct cgroup_subsys_state *of_css(struct kernfs_open_file *of)
 }
 EXPORT_SYMBOL_GPL(of_css);
 
+/**
+ * cgroup_is_descendant - test ancestry
+ * @cgrp: the cgroup to be tested
+ * @ancestor: possible ancestor of @cgrp
+ *
+ * Test whether @cgrp is a descendant of @ancestor.  It also returns %true
+ * if @cgrp == @ancestor.  This function is safe to call as long as @cgrp
+ * and @ancestor are accessible.
+ */
+bool cgroup_is_descendant(struct cgroup *cgrp, struct cgroup *ancestor)
+{
+	while (cgrp) {
+		if (cgrp == ancestor)
+			return true;
+		cgrp = cgroup_parent(cgrp);
+	}
+	return false;
+}
+
 static int notify_on_release(const struct cgroup *cgrp)
 {
 	return test_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
@@ -542,28 +532,22 @@ static int notify_on_release(const struct cgroup *cgrp)
 	     (((ss) = cgroup_subsys[ssid]) || true); (ssid)++)
 
 /**
- * do_each_subsys_mask - filter for_each_subsys with a bitmask
+ * for_each_subsys_which - filter for_each_subsys with a bitmask
  * @ss: the iteration cursor
  * @ssid: the index of @ss, CGROUP_SUBSYS_COUNT after reaching the end
- * @ss_mask: the bitmask
+ * @ss_maskp: a pointer to the bitmask
  *
  * The block will only run for cases where the ssid-th bit (1 << ssid) of
- * @ss_mask is set.
+ * mask is set to 1.
  */
-#define do_each_subsys_mask(ss, ssid, ss_mask) do {			\
-	unsigned long __ss_mask = (ss_mask);				\
-	if (!CGROUP_SUBSYS_COUNT) { /* to avoid spurious gcc warning */	\
+#define for_each_subsys_which(ss, ssid, ss_maskp)			\
+	if (!CGROUP_SUBSYS_COUNT) /* to avoid spurious gcc warning */	\
 		(ssid) = 0;						\
-		break;							\
-	}								\
-	for_each_set_bit(ssid, &__ss_mask, CGROUP_SUBSYS_COUNT) {	\
-		(ss) = cgroup_subsys[ssid];				\
-		{
-
-#define while_each_subsys_mask()					\
-		}							\
-	}								\
-} while (false)
+	else								\
+		for_each_set_bit(ssid, ss_maskp, CGROUP_SUBSYS_COUNT)	\
+			if (((ss) = cgroup_subsys[ssid]) && false)	\
+				break;					\
+			else
 
 /* iterate across the hierarchies */
 #define for_each_root(root)						\
@@ -577,24 +561,6 @@ static int notify_on_release(const struct cgroup *cgrp)
 			;						\
 		else
 
-/* walk live descendants in preorder */
-#define cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp)		\
-	css_for_each_descendant_pre((d_css), cgroup_css((cgrp), NULL))	\
-		if (({ lockdep_assert_held(&cgroup_mutex);		\
-		       (dsct) = (d_css)->cgroup;			\
-		       cgroup_is_dead(dsct); }))			\
-			;						\
-		else
-
-/* walk live descendants in postorder */
-#define cgroup_for_each_live_descendant_post(dsct, d_css, cgrp)		\
-	css_for_each_descendant_post((d_css), cgroup_css((cgrp), NULL))	\
-		if (({ lockdep_assert_held(&cgroup_mutex);		\
-		       (dsct) = (d_css)->cgroup;			\
-		       cgroup_is_dead(dsct); }))			\
-			;						\
-		else
-
 static void cgroup_release_agent(struct work_struct *work);
 static void check_for_release(struct cgroup *cgrp);
 
@@ -725,9 +691,6 @@ static void css_set_move_task(struct task_struct *task,
 {
 	lockdep_assert_held(&css_set_lock);
 
-	if (to_cset && !css_set_populated(to_cset))
-		css_set_update_populated(to_cset, true);
-
 	if (from_cset) {
 		struct css_task_iter *it, *pos;
 
@@ -761,6 +724,8 @@ static void css_set_move_task(struct task_struct *task,
 		 */
 		WARN_ON_ONCE(task->flags & PF_EXITING);
 
+		if (!css_set_populated(to_cset))
+			css_set_update_populated(to_cset, true);
 		rcu_assign_pointer(task->cgroups, to_cset);
 		list_add_tail(&task->cg_list, use_mg_tasks ? &to_cset->mg_tasks :
 							     &to_cset->tasks);
@@ -1143,12 +1108,18 @@ static void cgroup_exit_root_id(struct cgroup_root *root)
 {
 	lockdep_assert_held(&cgroup_mutex);
 
-	idr_remove(&cgroup_hierarchy_idr, root->hierarchy_id);
+	if (root->hierarchy_id) {
+		idr_remove(&cgroup_hierarchy_idr, root->hierarchy_id);
+		root->hierarchy_id = 0;
+	}
 }
 
 static void cgroup_free_root(struct cgroup_root *root)
 {
 	if (root) {
+		/* hierarchy ID should already have been released */
+		WARN_ON_ONCE(root->hierarchy_id);
+
 		idr_destroy(&root->cgroup_idr);
 		kfree(root);
 	}
@@ -1159,15 +1130,13 @@ static void cgroup_destroy_root(struct cgroup_root *root)
 	struct cgroup *cgrp = &root->cgrp;
 	struct cgrp_cset_link *link, *tmp_link;
 
-	trace_cgroup_destroy_root(root);
-
-	cgroup_lock_and_drain_offline(&cgrp_dfl_root.cgrp);
+	mutex_lock(&cgroup_mutex);
 
 	BUG_ON(atomic_read(&root->nr_cgrps));
 	BUG_ON(!list_empty(&cgrp->self.children));
 
 	/* Rebind all subsystems back to the default hierarchy */
-	WARN_ON(rebind_subsystems(&cgrp_dfl_root, root->subsys_mask));
+	rebind_subsystems(&cgrp_dfl_root, root->subsys_mask);
 
 	/*
 	 * Release all the links from cset_links to this hierarchy's
@@ -1196,41 +1165,6 @@ static void cgroup_destroy_root(struct cgroup_root *root)
 	cgroup_free_root(root);
 }
 
-/*
- * look up cgroup associated with current task's cgroup namespace on the
- * specified hierarchy
- */
-static struct cgroup *
-current_cgns_cgroup_from_root(struct cgroup_root *root)
-{
-	struct cgroup *res = NULL;
-	struct css_set *cset;
-
-	lockdep_assert_held(&css_set_lock);
-
-	rcu_read_lock();
-
-	cset = current->nsproxy->cgroup_ns->root_cset;
-	if (cset == &init_css_set) {
-		res = &root->cgrp;
-	} else {
-		struct cgrp_cset_link *link;
-
-		list_for_each_entry(link, &cset->cgrp_links, cgrp_link) {
-			struct cgroup *c = link->cgrp;
-
-			if (c->root == root) {
-				res = c;
-				break;
-			}
-		}
-	}
-	rcu_read_unlock();
-
-	BUG_ON(!res);
-	return res;
-}
-
 /* look up cgroup associated with given css_set on the specified hierarchy */
 static struct cgroup *cset_cgroup_from_root(struct css_set *cset,
 					    struct cgroup_root *root)
@@ -1342,40 +1276,46 @@ static umode_t cgroup_file_mode(const struct cftype *cft)
 }
 
 /**
- * cgroup_calc_subtree_ss_mask - calculate subtree_ss_mask
+ * cgroup_calc_child_subsys_mask - calculate child_subsys_mask
+ * @cgrp: the target cgroup
  * @subtree_control: the new subtree_control mask to consider
- * @this_ss_mask: available subsystems
  *
  * On the default hierarchy, a subsystem may request other subsystems to be
  * enabled together through its ->depends_on mask.  In such cases, more
  * subsystems than specified in "cgroup.subtree_control" may be enabled.
  *
  * This function calculates which subsystems need to be enabled if
- * @subtree_control is to be applied while restricted to @this_ss_mask.
+ * @subtree_control is to be applied to @cgrp.  The returned mask is always
+ * a superset of @subtree_control and follows the usual hierarchy rules.
  */
-static u16 cgroup_calc_subtree_ss_mask(u16 subtree_control, u16 this_ss_mask)
+static unsigned long cgroup_calc_child_subsys_mask(struct cgroup *cgrp,
+						  unsigned long subtree_control)
 {
-	u16 cur_ss_mask = subtree_control;
+	struct cgroup *parent = cgroup_parent(cgrp);
+	unsigned long cur_ss_mask = subtree_control;
 	struct cgroup_subsys *ss;
 	int ssid;
 
 	lockdep_assert_held(&cgroup_mutex);
 
-	cur_ss_mask |= cgrp_dfl_implicit_ss_mask;
+	if (!cgroup_on_dfl(cgrp))
+		return cur_ss_mask;
 
 	while (true) {
-		u16 new_ss_mask = cur_ss_mask;
+		unsigned long new_ss_mask = cur_ss_mask;
 
-		do_each_subsys_mask(ss, ssid, cur_ss_mask) {
+		for_each_subsys_which(ss, ssid, &cur_ss_mask)
 			new_ss_mask |= ss->depends_on;
-		} while_each_subsys_mask();
 
 		/*
 		 * Mask out subsystems which aren't available.  This can
 		 * happen only if some depended-upon subsystems were bound
 		 * to non-default hierarchies.
 		 */
-		new_ss_mask &= this_ss_mask;
+		if (parent)
+			new_ss_mask &= parent->child_subsys_mask;
+		else
+			new_ss_mask &= cgrp->root->subsys_mask;
 
 		if (new_ss_mask == cur_ss_mask)
 			break;
@@ -1385,6 +1325,19 @@ static u16 cgroup_calc_subtree_ss_mask(u16 subtree_control, u16 this_ss_mask)
 	return cur_ss_mask;
 }
 
+/**
+ * cgroup_refresh_child_subsys_mask - update child_subsys_mask
+ * @cgrp: the target cgroup
+ *
+ * Update @cgrp->child_subsys_mask according to the current
+ * @cgrp->subtree_control using cgroup_calc_child_subsys_mask().
+ */
+static void cgroup_refresh_child_subsys_mask(struct cgroup *cgrp)
+{
+	cgrp->child_subsys_mask =
+		cgroup_calc_child_subsys_mask(cgrp, cgrp->subtree_control);
+}
+
 /**
  * cgroup_kn_unlock - unlocking helper for cgroup kernfs methods
  * @kn: the kernfs_node being serviced
@@ -1413,22 +1366,19 @@ static void cgroup_kn_unlock(struct kernfs_node *kn)
 /**
  * cgroup_kn_lock_live - locking helper for cgroup kernfs methods
  * @kn: the kernfs_node being serviced
- * @drain_offline: perform offline draining on the cgroup
  *
  * This helper is to be used by a cgroup kernfs method currently servicing
  * @kn.  It breaks the active protection, performs cgroup locking and
  * verifies that the associated cgroup is alive.  Returns the cgroup if
  * alive; otherwise, %NULL.  A successful return should be undone by a
- * matching cgroup_kn_unlock() invocation.  If @drain_offline is %true, the
- * cgroup is drained of offlining csses before return.
+ * matching cgroup_kn_unlock() invocation.
  *
  * Any cgroup kernfs method implementation which requires locking the
  * associated cgroup should use this helper.  It avoids nesting cgroup
  * locking under kernfs active protection and allows all kernfs operations
  * including self-removal.
  */
-static struct cgroup *cgroup_kn_lock_live(struct kernfs_node *kn,
-					  bool drain_offline)
+static struct cgroup *cgroup_kn_lock_live(struct kernfs_node *kn)
 {
 	struct cgroup *cgrp;
 
@@ -1447,10 +1397,7 @@ static struct cgroup *cgroup_kn_lock_live(struct kernfs_node *kn,
 		return NULL;
 	kernfs_break_active_protection(kn);
 
-	if (drain_offline)
-		cgroup_lock_and_drain_offline(cgrp);
-	else
-		mutex_lock(&cgroup_mutex);
+	mutex_lock(&cgroup_mutex);
 
 	if (!cgroup_is_dead(cgrp))
 		return cgrp;
@@ -1480,17 +1427,14 @@ static void cgroup_rm_file(struct cgroup *cgrp, const struct cftype *cft)
 /**
  * css_clear_dir - remove subsys files in a cgroup directory
  * @css: taget css
+ * @cgrp_override: specify if target cgroup is different from css->cgroup
  */
-static void css_clear_dir(struct cgroup_subsys_state *css)
+static void css_clear_dir(struct cgroup_subsys_state *css,
+			  struct cgroup *cgrp_override)
 {
-	struct cgroup *cgrp = css->cgroup;
+	struct cgroup *cgrp = cgrp_override ?: css->cgroup;
 	struct cftype *cfts;
 
-	if (!(css->flags & CSS_VISIBLE))
-		return;
-
-	css->flags &= ~CSS_VISIBLE;
-
 	list_for_each_entry(cfts, &css->ss->cfts, node)
 		cgroup_addrm_files(css, cgrp, cfts, false);
 }
@@ -1498,18 +1442,17 @@ static void css_clear_dir(struct cgroup_subsys_state *css)
 /**
  * css_populate_dir - create subsys files in a cgroup directory
  * @css: target css
+ * @cgrp_overried: specify if target cgroup is different from css->cgroup
  *
  * On failure, no file is added.
  */
-static int css_populate_dir(struct cgroup_subsys_state *css)
+static int css_populate_dir(struct cgroup_subsys_state *css,
+			    struct cgroup *cgrp_override)
 {
-	struct cgroup *cgrp = css->cgroup;
+	struct cgroup *cgrp = cgrp_override ?: css->cgroup;
 	struct cftype *cfts, *failed_cfts;
 	int ret;
 
-	if ((css->flags & CSS_VISIBLE) || !cgrp->kn)
-		return 0;
-
 	if (!css->ss) {
 		if (cgroup_on_dfl(cgrp))
 			cfts = cgroup_dfl_base_files;
@@ -1526,9 +1469,6 @@ static int css_populate_dir(struct cgroup_subsys_state *css)
 			goto err;
 		}
 	}
-
-	css->flags |= CSS_VISIBLE;
-
 	return 0;
 err:
 	list_for_each_entry(cfts, &css->ss->cfts, node) {
@@ -1539,30 +1479,67 @@ err:
 	return ret;
 }
 
-static int rebind_subsystems(struct cgroup_root *dst_root, u16 ss_mask)
+static int rebind_subsystems(struct cgroup_root *dst_root,
+			     unsigned long ss_mask)
 {
 	struct cgroup *dcgrp = &dst_root->cgrp;
 	struct cgroup_subsys *ss;
+	unsigned long tmp_ss_mask;
 	int ssid, i, ret;
 
 	lockdep_assert_held(&cgroup_mutex);
 
-	do_each_subsys_mask(ss, ssid, ss_mask) {
-		/*
-		 * If @ss has non-root csses attached to it, can't move.
-		 * If @ss is an implicit controller, it is exempt from this
-		 * rule and can be stolen.
-		 */
-		if (css_next_child(NULL, cgroup_css(&ss->root->cgrp, ss)) &&
-		    !ss->implicit_on_dfl)
+	for_each_subsys_which(ss, ssid, &ss_mask) {
+		/* if @ss has non-root csses attached to it, can't move */
+		if (css_next_child(NULL, cgroup_css(&ss->root->cgrp, ss)))
 			return -EBUSY;
 
 		/* can't move between two non-dummy roots either */
 		if (ss->root != &cgrp_dfl_root && dst_root != &cgrp_dfl_root)
 			return -EBUSY;
-	} while_each_subsys_mask();
+	}
+
+	/* skip creating root files on dfl_root for inhibited subsystems */
+	tmp_ss_mask = ss_mask;
+	if (dst_root == &cgrp_dfl_root)
+		tmp_ss_mask &= ~cgrp_dfl_root_inhibit_ss_mask;
+
+	for_each_subsys_which(ss, ssid, &tmp_ss_mask) {
+		struct cgroup *scgrp = &ss->root->cgrp;
+		int tssid;
+
+		ret = css_populate_dir(cgroup_css(scgrp, ss), dcgrp);
+		if (!ret)
+			continue;
+
+		/*
+		 * Rebinding back to the default root is not allowed to
+		 * fail.  Using both default and non-default roots should
+		 * be rare.  Moving subsystems back and forth even more so.
+		 * Just warn about it and continue.
+		 */
+		if (dst_root == &cgrp_dfl_root) {
+			if (cgrp_dfl_root_visible) {
+				pr_warn("failed to create files (%d) while rebinding 0x%lx to default root\n",
+					ret, ss_mask);
+				pr_warn("you may retry by moving them to a different hierarchy and unbinding\n");
+			}
+			continue;
+		}
 
-	do_each_subsys_mask(ss, ssid, ss_mask) {
+		for_each_subsys_which(ss, tssid, &tmp_ss_mask) {
+			if (tssid == ssid)
+				break;
+			css_clear_dir(cgroup_css(scgrp, ss), dcgrp);
+		}
+		return ret;
+	}
+
+	/*
+	 * Nothing can fail from this point on.  Remove files for the
+	 * removed subsystems and rebind each subsystem.
+	 */
+	for_each_subsys_which(ss, ssid, &ss_mask) {
 		struct cgroup_root *src_root = ss->root;
 		struct cgroup *scgrp = &src_root->cgrp;
 		struct cgroup_subsys_state *css = cgroup_css(scgrp, ss);
@@ -1570,12 +1547,8 @@ static int rebind_subsystems(struct cgroup_root *dst_root, u16 ss_mask)
 
 		WARN_ON(!css || cgroup_css(dcgrp, ss));
 
-		/* disable from the source */
-		src_root->subsys_mask &= ~(1 << ssid);
-		WARN_ON(cgroup_apply_control(scgrp));
-		cgroup_finalize_control(scgrp, 0);
+		css_clear_dir(css, NULL);
 
-		/* rebind */
 		RCU_INIT_POINTER(scgrp->subsys[ssid], NULL);
 		rcu_assign_pointer(dcgrp->subsys[ssid], css);
 		ss->root = dst_root;
@@ -1587,55 +1560,28 @@ static int rebind_subsystems(struct cgroup_root *dst_root, u16 ss_mask)
 				       &dcgrp->e_csets[ss->id]);
 		spin_unlock_irq(&css_set_lock);
 
+		src_root->subsys_mask &= ~(1 << ssid);
+		scgrp->subtree_control &= ~(1 << ssid);
+		cgroup_refresh_child_subsys_mask(scgrp);
+
 		/* default hierarchy doesn't enable controllers by default */
 		dst_root->subsys_mask |= 1 << ssid;
 		if (dst_root == &cgrp_dfl_root) {
 			static_branch_enable(cgroup_subsys_on_dfl_key[ssid]);
 		} else {
 			dcgrp->subtree_control |= 1 << ssid;
+			cgroup_refresh_child_subsys_mask(dcgrp);
 			static_branch_disable(cgroup_subsys_on_dfl_key[ssid]);
 		}
 
-		ret = cgroup_apply_control(dcgrp);
-		if (ret)
-			pr_warn("partial failure to rebind %s controller (err=%d)\n",
-				ss->name, ret);
-
 		if (ss->bind)
 			ss->bind(css);
-	} while_each_subsys_mask();
+	}
 
 	kernfs_activate(dcgrp->kn);
 	return 0;
 }
 
-static int cgroup_show_path(struct seq_file *sf, struct kernfs_node *kf_node,
-			    struct kernfs_root *kf_root)
-{
-	int len = 0;
-	char *buf = NULL;
-	struct cgroup_root *kf_cgroot = cgroup_root_from_kf(kf_root);
-	struct cgroup *ns_cgroup;
-
-	buf = kmalloc(PATH_MAX, GFP_KERNEL);
-	if (!buf)
-		return -ENOMEM;
-
-	spin_lock_bh(&css_set_lock);
-	ns_cgroup = current_cgns_cgroup_from_root(kf_cgroot);
-	len = kernfs_path_from_node(kf_node, ns_cgroup->kn, buf, PATH_MAX);
-	spin_unlock_bh(&css_set_lock);
-
-	if (len >= PATH_MAX)
-		len = -ERANGE;
-	else if (len > 0) {
-		seq_escape(sf, buf, " \t\n\\");
-		len = 0;
-	}
-	kfree(buf);
-	return len;
-}
-
 static int cgroup_show_options(struct seq_file *seq,
 			       struct kernfs_root *kf_root)
 {
@@ -1666,7 +1612,7 @@ static int cgroup_show_options(struct seq_file *seq,
 }
 
 struct cgroup_sb_opts {
-	u16 subsys_mask;
+	unsigned long subsys_mask;
 	unsigned int flags;
 	char *release_agent;
 	bool cpuset_clone_children;
@@ -1679,13 +1625,13 @@ static int parse_cgroupfs_options(char *data, struct cgroup_sb_opts *opts)
 {
 	char *token, *o = data;
 	bool all_ss = false, one_ss = false;
-	u16 mask = U16_MAX;
+	unsigned long mask = -1UL;
 	struct cgroup_subsys *ss;
 	int nr_opts = 0;
 	int i;
 
 #ifdef CONFIG_CPUSETS
-	mask = ~((u16)1 << cpuset_cgrp_id);
+	mask = ~(1U << cpuset_cgrp_id);
 #endif
 
 	memset(opts, 0, sizeof(*opts));
@@ -1760,8 +1706,6 @@ static int parse_cgroupfs_options(char *data, struct cgroup_sb_opts *opts)
 				continue;
 			if (!cgroup_ssid_enabled(i))
 				continue;
-			if (cgroup_ssid_no_v1(i))
-				continue;
 
 			/* Mutually exclusive option 'all' + subsystem name */
 			if (all_ss)
@@ -1782,7 +1726,7 @@ static int parse_cgroupfs_options(char *data, struct cgroup_sb_opts *opts)
 	 */
 	if (all_ss || (!one_ss && !opts->none && !opts->name))
 		for_each_subsys(ss, i)
-			if (cgroup_ssid_enabled(i) && !cgroup_ssid_no_v1(i))
+			if (cgroup_ssid_enabled(i))
 				opts->subsys_mask |= (1 << i);
 
 	/*
@@ -1812,14 +1756,14 @@ static int cgroup_remount(struct kernfs_root *kf_root, int *flags, char *data)
 	int ret = 0;
 	struct cgroup_root *root = cgroup_root_from_kf(kf_root);
 	struct cgroup_sb_opts opts;
-	u16 added_mask, removed_mask;
+	unsigned long added_mask, removed_mask;
 
 	if (root == &cgrp_dfl_root) {
 		pr_err("remount is not allowed\n");
 		return -EINVAL;
 	}
 
-	cgroup_lock_and_drain_offline(&cgrp_dfl_root.cgrp);
+	mutex_lock(&cgroup_mutex);
 
 	/* See what subsystems are wanted */
 	ret = parse_cgroupfs_options(data, &opts);
@@ -1852,16 +1796,13 @@ static int cgroup_remount(struct kernfs_root *kf_root, int *flags, char *data)
 	if (ret)
 		goto out_unlock;
 
-	WARN_ON(rebind_subsystems(&cgrp_dfl_root, removed_mask));
+	rebind_subsystems(&cgrp_dfl_root, removed_mask);
 
 	if (opts.release_agent) {
 		spin_lock(&release_agent_path_lock);
 		strcpy(root->release_agent_path, opts.release_agent);
 		spin_unlock(&release_agent_path_lock);
 	}
-
-	trace_cgroup_remount(root);
-
  out_unlock:
 	kfree(opts.release_agent);
 	kfree(opts.name);
@@ -1967,7 +1908,7 @@ static void init_cgroup_root(struct cgroup_root *root,
 		set_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->cgrp.flags);
 }
 
-static int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask)
+static int cgroup_setup_root(struct cgroup_root *root, unsigned long ss_mask)
 {
 	LIST_HEAD(tmp_links);
 	struct cgroup *root_cgrp = &root->cgrp;
@@ -1980,7 +1921,6 @@ static int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask)
 	if (ret < 0)
 		goto out;
 	root_cgrp->id = ret;
-	root_cgrp->ancestor_ids[0] = ret;
 
 	ret = percpu_ref_init(&root_cgrp->self.refcnt, css_release, 0,
 			      GFP_KERNEL);
@@ -1990,11 +1930,10 @@ static int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask)
 	/*
 	 * We're accessing css_set_count without locking css_set_lock here,
 	 * but that's OK - it can only be increased by someone holding
-	 * cgroup_lock, and that's us.  Later rebinding may disable
-	 * controllers on the default hierarchy and thus create new csets,
-	 * which can't be more than the existing ones.  Allocate 2x.
+	 * cgroup_lock, and that's us. The worst that can happen is that we
+	 * have some link structures left over
 	 */
-	ret = allocate_cgrp_cset_links(2 * css_set_count, &tmp_links);
+	ret = allocate_cgrp_cset_links(css_set_count, &tmp_links);
 	if (ret)
 		goto cancel_ref;
 
@@ -2011,7 +1950,7 @@ static int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask)
 	}
 	root_cgrp->kn = root->kf_root->kn;
 
-	ret = css_populate_dir(&root_cgrp->self);
+	ret = css_populate_dir(&root_cgrp->self, NULL);
 	if (ret)
 		goto destroy_root;
 
@@ -2019,11 +1958,6 @@ static int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask)
 	if (ret)
 		goto destroy_root;
 
-	ret = cgroup_bpf_inherit(root_cgrp);
-	WARN_ON_ONCE(ret);
-
-	trace_cgroup_setup_root(root);
-
 	/*
 	 * There must be no failure case after here, since rebinding takes
 	 * care of subsystems' refcounts, which are explicitly dropped in
@@ -2069,7 +2003,6 @@ static struct dentry *cgroup_mount(struct file_system_type *fs_type,
 {
 	bool is_v2 = fs_type == &cgroup2_fs_type;
 	struct super_block *pinned_sb = NULL;
-	struct cgroup_namespace *ns = current->nsproxy->cgroup_ns;
 	struct cgroup_subsys *ss;
 	struct cgroup_root *root = NULL;
 	struct cgroup_sb_opts opts;
@@ -2078,14 +2011,6 @@ static struct dentry *cgroup_mount(struct file_system_type *fs_type,
 	int i;
 	bool new_sb;
 
-	get_cgroup_ns(ns);
-
-	/* Check if the caller has permission to mount. */
-	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN)) {
-		put_cgroup_ns(ns);
-		return ERR_PTR(-EPERM);
-	}
-
 	/*
 	 * The first time anyone tries to mount a cgroup, enable the list
 	 * linking each css_set to its tasks and fix up all existing tasks.
@@ -2096,16 +2021,15 @@ static struct dentry *cgroup_mount(struct file_system_type *fs_type,
 	if (is_v2) {
 		if (data) {
 			pr_err("cgroup2: unknown option \"%s\"\n", (char *)data);
-			put_cgroup_ns(ns);
 			return ERR_PTR(-EINVAL);
 		}
-		cgrp_dfl_visible = true;
+		cgrp_dfl_root_visible = true;
 		root = &cgrp_dfl_root;
 		cgroup_get(&root->cgrp);
 		goto out_mount;
 	}
 
-	cgroup_lock_and_drain_offline(&cgrp_dfl_root.cgrp);
+	mutex_lock(&cgroup_mutex);
 
 	/* First find the desired set of subsystems */
 	ret = parse_cgroupfs_options(data, &opts);
@@ -2202,12 +2126,6 @@ static struct dentry *cgroup_mount(struct file_system_type *fs_type,
 		goto out_unlock;
 	}
 
-	/* Hierarchies may only be created in the initial cgroup namespace. */
-	if (ns != &init_cgroup_ns) {
-		ret = -EPERM;
-		goto out_unlock;
-	}
-
 	root = kzalloc(sizeof(*root), GFP_KERNEL);
 	if (!root) {
 		ret = -ENOMEM;
@@ -2226,37 +2144,12 @@ out_free:
 	kfree(opts.release_agent);
 	kfree(opts.name);
 
-	if (ret) {
-		put_cgroup_ns(ns);
+	if (ret)
 		return ERR_PTR(ret);
-	}
 out_mount:
 	dentry = kernfs_mount(fs_type, flags, root->kf_root,
 			      is_v2 ? CGROUP2_SUPER_MAGIC : CGROUP_SUPER_MAGIC,
 			      &new_sb);
-
-	/*
-	 * In non-init cgroup namespace, instead of root cgroup's
-	 * dentry, we return the dentry corresponding to the
-	 * cgroupns->root_cgrp.
-	 */
-	if (!IS_ERR(dentry) && ns != &init_cgroup_ns) {
-		struct dentry *nsdentry;
-		struct cgroup *cgrp;
-
-		mutex_lock(&cgroup_mutex);
-		spin_lock_bh(&css_set_lock);
-
-		cgrp = cset_cgroup_from_root(ns->root_cset, root);
-
-		spin_unlock_bh(&css_set_lock);
-		mutex_unlock(&cgroup_mutex);
-
-		nsdentry = kernfs_node_dentry(cgrp->kn, dentry->d_sb);
-		dput(dentry);
-		dentry = nsdentry;
-	}
-
 	if (IS_ERR(dentry) || !new_sb)
 		cgroup_put(&root->cgrp);
 
@@ -2269,7 +2162,6 @@ out_mount:
 		deactivate_super(pinned_sb);
 	}
 
-	put_cgroup_ns(ns);
 	return dentry;
 }
 
@@ -2298,41 +2190,14 @@ static struct file_system_type cgroup_fs_type = {
 	.name = "cgroup",
 	.mount = cgroup_mount,
 	.kill_sb = cgroup_kill_sb,
-	.fs_flags = FS_USERNS_MOUNT,
 };
 
 static struct file_system_type cgroup2_fs_type = {
 	.name = "cgroup2",
 	.mount = cgroup_mount,
 	.kill_sb = cgroup_kill_sb,
-	.fs_flags = FS_USERNS_MOUNT,
 };
 
-static int cgroup_path_ns_locked(struct cgroup *cgrp, char *buf, size_t buflen,
-				 struct cgroup_namespace *ns)
-{
-	struct cgroup *root = cset_cgroup_from_root(ns->root_cset, cgrp->root);
-
-	return kernfs_path_from_node(cgrp->kn, root->kn, buf, buflen);
-}
-
-int cgroup_path_ns(struct cgroup *cgrp, char *buf, size_t buflen,
-		   struct cgroup_namespace *ns)
-{
-	int ret;
-
-	mutex_lock(&cgroup_mutex);
-	spin_lock_bh(&css_set_lock);
-
-	ret = cgroup_path_ns_locked(cgrp, buf, buflen, ns);
-
-	spin_unlock_bh(&css_set_lock);
-	mutex_unlock(&cgroup_mutex);
-
-	return ret;
-}
-EXPORT_SYMBOL_GPL(cgroup_path_ns);
-
 /**
  * task_cgroup_path - cgroup path of a task in the first cgroup hierarchy
  * @task: target task
@@ -2346,12 +2211,12 @@ EXPORT_SYMBOL_GPL(cgroup_path_ns);
  *
  * Return value is the same as kernfs_path().
  */
-int task_cgroup_path(struct task_struct *task, char *buf, size_t buflen)
+char *task_cgroup_path(struct task_struct *task, char *buf, size_t buflen)
 {
 	struct cgroup_root *root;
 	struct cgroup *cgrp;
 	int hierarchy_id = 1;
-	int ret;
+	char *path = NULL;
 
 	mutex_lock(&cgroup_mutex);
 	spin_lock_irq(&css_set_lock);
@@ -2360,15 +2225,16 @@ int task_cgroup_path(struct task_struct *task, char *buf, size_t buflen)
 
 	if (root) {
 		cgrp = task_cgroup_from_root(task, root);
-		ret = cgroup_path_ns_locked(cgrp, buf, buflen, &init_cgroup_ns);
+		path = cgroup_path(cgrp, buf, buflen);
 	} else {
 		/* if no hierarchy exists, everyone is in "/" */
-		ret = strlcpy(buf, "/", buflen);
+		if (strlcpy(buf, "/", buflen) < buflen)
+			path = buf;
 	}
 
 	spin_unlock_irq(&css_set_lock);
 	mutex_unlock(&cgroup_mutex);
-	return ret;
+	return path;
 }
 EXPORT_SYMBOL_GPL(task_cgroup_path);
 
@@ -2503,38 +2369,38 @@ struct task_struct *cgroup_taskset_next(struct cgroup_taskset *tset,
 }
 
 /**
- * cgroup_taskset_migrate - migrate a taskset
+ * cgroup_taskset_migrate - migrate a taskset to a cgroup
  * @tset: taget taskset
- * @root: cgroup root the migration is taking place on
+ * @dst_cgrp: destination cgroup
  *
- * Migrate tasks in @tset as setup by migration preparation functions.
- * This function fails iff one of the ->can_attach callbacks fails and
- * guarantees that either all or none of the tasks in @tset are migrated.
- * @tset is consumed regardless of success.
+ * Migrate tasks in @tset to @dst_cgrp.  This function fails iff one of the
+ * ->can_attach callbacks fails and guarantees that either all or none of
+ * the tasks in @tset are migrated.  @tset is consumed regardless of
+ * success.
  */
 static int cgroup_taskset_migrate(struct cgroup_taskset *tset,
-				  struct cgroup_root *root)
+				  struct cgroup *dst_cgrp)
 {
-	struct cgroup_subsys *ss;
+	struct cgroup_subsys_state *css, *failed_css = NULL;
 	struct task_struct *task, *tmp_task;
 	struct css_set *cset, *tmp_cset;
-	int ssid, failed_ssid, ret;
+	int i, ret;
 
 	/* methods shouldn't be called if no task is actually migrating */
 	if (list_empty(&tset->src_csets))
 		return 0;
 
 	/* check that we can legitimately attach to the cgroup */
-	do_each_subsys_mask(ss, ssid, root->subsys_mask) {
-		if (ss->can_attach) {
-			tset->ssid = ssid;
-			ret = ss->can_attach(tset);
+	for_each_e_css(css, i, dst_cgrp) {
+		if (css->ss->can_attach) {
+			tset->ssid = i;
+			ret = css->ss->can_attach(tset);
 			if (ret) {
-				failed_ssid = ssid;
+				failed_css = css;
 				goto out_cancel_attach;
 			}
 		}
-	} while_each_subsys_mask();
+	}
 
 	/*
 	 * Now that we're guaranteed success, proceed to move all tasks to
@@ -2561,25 +2427,25 @@ static int cgroup_taskset_migrate(struct cgroup_taskset *tset,
 	 */
 	tset->csets = &tset->dst_csets;
 
-	do_each_subsys_mask(ss, ssid, root->subsys_mask) {
-		if (ss->attach) {
-			tset->ssid = ssid;
-			ss->attach(tset);
+	for_each_e_css(css, i, dst_cgrp) {
+		if (css->ss->attach) {
+			tset->ssid = i;
+			css->ss->attach(tset);
 		}
-	} while_each_subsys_mask();
+	}
 
 	ret = 0;
 	goto out_release_tset;
 
 out_cancel_attach:
-	do_each_subsys_mask(ss, ssid, root->subsys_mask) {
-		if (ssid == failed_ssid)
+	for_each_e_css(css, i, dst_cgrp) {
+		if (css == failed_css)
 			break;
-		if (ss->cancel_attach) {
-			tset->ssid = ssid;
-			ss->cancel_attach(tset);
+		if (css->ss->cancel_attach) {
+			tset->ssid = i;
+			css->ss->cancel_attach(tset);
 		}
-	} while_each_subsys_mask();
+	}
 out_release_tset:
 	spin_lock_irq(&css_set_lock);
 	list_splice_init(&tset->dst_csets, &tset->src_csets);
@@ -2591,20 +2457,6 @@ out_release_tset:
 	return ret;
 }
 
-/**
- * cgroup_may_migrate_to - verify whether a cgroup can be migration destination
- * @dst_cgrp: destination cgroup to test
- *
- * On the default hierarchy, except for the root, subtree_control must be
- * zero for migration destination cgroups with tasks so that child cgroups
- * don't compete against tasks.
- */
-static bool cgroup_may_migrate_to(struct cgroup *dst_cgrp)
-{
-	return !cgroup_on_dfl(dst_cgrp) || !cgroup_parent(dst_cgrp) ||
-		!dst_cgrp->subtree_control;
-}
-
 /**
  * cgroup_migrate_finish - cleanup after attach
  * @preloaded_csets: list of preloaded css_sets
@@ -2621,7 +2473,6 @@ static void cgroup_migrate_finish(struct list_head *preloaded_csets)
 	spin_lock_irq(&css_set_lock);
 	list_for_each_entry_safe(cset, tmp_cset, preloaded_csets, mg_preload_node) {
 		cset->mg_src_cgrp = NULL;
-		cset->mg_dst_cgrp = NULL;
 		cset->mg_dst_cset = NULL;
 		list_del_init(&cset->mg_preload_node);
 		put_css_set_locked(cset);
@@ -2668,42 +2519,52 @@ static void cgroup_migrate_add_src(struct css_set *src_cset,
 		return;
 
 	WARN_ON(src_cset->mg_src_cgrp);
-	WARN_ON(src_cset->mg_dst_cgrp);
 	WARN_ON(!list_empty(&src_cset->mg_tasks));
 	WARN_ON(!list_empty(&src_cset->mg_node));
 
 	src_cset->mg_src_cgrp = src_cgrp;
-	src_cset->mg_dst_cgrp = dst_cgrp;
 	get_css_set(src_cset);
 	list_add(&src_cset->mg_preload_node, preloaded_csets);
 }
 
 /**
  * cgroup_migrate_prepare_dst - prepare destination css_sets for migration
+ * @dst_cgrp: the destination cgroup (may be %NULL)
  * @preloaded_csets: list of preloaded source css_sets
  *
- * Tasks are about to be moved and all the source css_sets have been
- * preloaded to @preloaded_csets.  This function looks up and pins all
- * destination css_sets, links each to its source, and append them to
- * @preloaded_csets.
+ * Tasks are about to be moved to @dst_cgrp and all the source css_sets
+ * have been preloaded to @preloaded_csets.  This function looks up and
+ * pins all destination css_sets, links each to its source, and append them
+ * to @preloaded_csets.  If @dst_cgrp is %NULL, the destination of each
+ * source css_set is assumed to be its cgroup on the default hierarchy.
  *
  * This function must be called after cgroup_migrate_add_src() has been
  * called on each migration source css_set.  After migration is performed
  * using cgroup_migrate(), cgroup_migrate_finish() must be called on
  * @preloaded_csets.
  */
-static int cgroup_migrate_prepare_dst(struct list_head *preloaded_csets)
+static int cgroup_migrate_prepare_dst(struct cgroup *dst_cgrp,
+				      struct list_head *preloaded_csets)
 {
 	LIST_HEAD(csets);
 	struct css_set *src_cset, *tmp_cset;
 
 	lockdep_assert_held(&cgroup_mutex);
 
+	/*
+	 * Except for the root, child_subsys_mask must be zero for a cgroup
+	 * with tasks so that child cgroups don't compete against tasks.
+	 */
+	if (dst_cgrp && cgroup_on_dfl(dst_cgrp) && cgroup_parent(dst_cgrp) &&
+	    dst_cgrp->child_subsys_mask)
+		return -EBUSY;
+
 	/* look up the dst cset for each src cset and link it to src */
 	list_for_each_entry_safe(src_cset, tmp_cset, preloaded_csets, mg_preload_node) {
 		struct css_set *dst_cset;
 
-		dst_cset = find_css_set(src_cset, src_cset->mg_dst_cgrp);
+		dst_cset = find_css_set(src_cset,
+					dst_cgrp ?: src_cset->dfl_cgrp);
 		if (!dst_cset)
 			goto err;
 
@@ -2716,7 +2577,6 @@ static int cgroup_migrate_prepare_dst(struct list_head *preloaded_csets)
 		 */
 		if (src_cset == dst_cset) {
 			src_cset->mg_src_cgrp = NULL;
-			src_cset->mg_dst_cgrp = NULL;
 			list_del_init(&src_cset->mg_preload_node);
 			put_css_set(src_cset);
 			put_css_set(dst_cset);
@@ -2742,11 +2602,11 @@ err:
  * cgroup_migrate - migrate a process or task to a cgroup
  * @leader: the leader of the process or the task to migrate
  * @threadgroup: whether @leader points to the whole process or a single task
- * @root: cgroup root migration is taking place on
+ * @cgrp: the destination cgroup
  *
- * Migrate a process or task denoted by @leader.  If migrating a process,
- * the caller must be holding cgroup_threadgroup_rwsem.  The caller is also
- * responsible for invoking cgroup_migrate_add_src() and
+ * Migrate a process or task denoted by @leader to @cgrp.  If migrating a
+ * process, the caller must be holding cgroup_threadgroup_rwsem.  The
+ * caller is also responsible for invoking cgroup_migrate_add_src() and
  * cgroup_migrate_prepare_dst() on the targets before invoking this
  * function and following up with cgroup_migrate_finish().
  *
@@ -2757,7 +2617,7 @@ err:
  * actually starting migrating.
  */
 static int cgroup_migrate(struct task_struct *leader, bool threadgroup,
-			  struct cgroup_root *root)
+			  struct cgroup *cgrp)
 {
 	struct cgroup_taskset tset = CGROUP_TASKSET_INIT(tset);
 	struct task_struct *task;
@@ -2778,7 +2638,7 @@ static int cgroup_migrate(struct task_struct *leader, bool threadgroup,
 	rcu_read_unlock();
 	spin_unlock_irq(&css_set_lock);
 
-	return cgroup_taskset_migrate(&tset, root);
+	return cgroup_taskset_migrate(&tset, cgrp);
 }
 
 /**
@@ -2796,9 +2656,6 @@ static int cgroup_attach_task(struct cgroup *dst_cgrp,
 	struct task_struct *task;
 	int ret;
 
-	if (!cgroup_may_migrate_to(dst_cgrp))
-		return -EBUSY;
-
 	/* look up all src csets */
 	spin_lock_irq(&css_set_lock);
 	rcu_read_lock();
@@ -2813,56 +2670,14 @@ static int cgroup_attach_task(struct cgroup *dst_cgrp,
 	spin_unlock_irq(&css_set_lock);
 
 	/* prepare dst csets and commit */
-	ret = cgroup_migrate_prepare_dst(&preloaded_csets);
+	ret = cgroup_migrate_prepare_dst(dst_cgrp, &preloaded_csets);
 	if (!ret)
-		ret = cgroup_migrate(leader, threadgroup, dst_cgrp->root);
+		ret = cgroup_migrate(leader, threadgroup, dst_cgrp);
 
 	cgroup_migrate_finish(&preloaded_csets);
-
-	if (!ret)
-		trace_cgroup_attach_task(dst_cgrp, leader, threadgroup);
-
 	return ret;
 }
 
-int subsys_cgroup_allow_attach(struct cgroup_subsys_state *css, struct cgroup_taskset *tset)
-{
-	const struct cred *cred = current_cred(), *tcred;
-	struct task_struct *task;
-
-	if (capable(CAP_SYS_NICE))
-		return 0;
-
-	cgroup_taskset_for_each(task, css, tset) {
-		tcred = __task_cred(task);
-
-		if (current != task && !uid_eq(cred->euid, tcred->uid) &&
-		    !uid_eq(cred->euid, tcred->suid))
-			return -EACCES;
-	}
-
-	return 0;
-}
-
-static int cgroup_allow_attach(struct cgroup *cgrp, struct cgroup_taskset *tset)
-{
-	struct cgroup_subsys_state *css;
-	int i;
-	int ret;
-
-	for_each_css(css, i, cgrp) {
-		if (css->ss->allow_attach) {
-			ret = css->ss->allow_attach(css, tset);
-			if (ret)
-				return ret;
-		} else {
-			return -EACCES;
-		}
-	}
-
-	return 0;
-}
-
 static int cgroup_procs_write_permission(struct task_struct *task,
 					 struct cgroup *dst_cgrp,
 					 struct kernfs_open_file *of)
@@ -2878,23 +2693,8 @@ static int cgroup_procs_write_permission(struct task_struct *task,
 	if (!uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
 	    !uid_eq(cred->euid, tcred->uid) &&
 	    !uid_eq(cred->euid, tcred->suid) &&
-	    !ns_capable(tcred->user_ns, CAP_SYS_NICE)) {
-		/*
-		 * if the default permission check fails, give each
-		 * cgroup a chance to extend the permission check
-		 */
-		struct cgroup_taskset tset = {
-			.src_csets = LIST_HEAD_INIT(tset.src_csets),
-			.dst_csets = LIST_HEAD_INIT(tset.dst_csets),
-			.csets = &tset.src_csets,
-		};
-		struct css_set *cset;
-		cset = task_css_set(task);
-		list_add(&cset->mg_node, &tset.src_csets);
-		ret = cgroup_allow_attach(dst_cgrp, &tset);
-		if (ret)
-			ret = -EACCES;
-	}
+	    !ns_capable(tcred->user_ns, CAP_SYS_NICE))
+		ret = -EACCES;
 
 	if (!ret && cgroup_on_dfl(dst_cgrp)) {
 		struct super_block *sb = of->file->f_path.dentry->d_sb;
@@ -2937,7 +2737,7 @@ static ssize_t __cgroup_procs_write(struct kernfs_open_file *of, char *buf,
 	if (kstrtoint(strstrip(buf), 0, &pid) || pid < 0)
 		return -EINVAL;
 
-	cgrp = cgroup_kn_lock_live(of->kn, false);
+	cgrp = cgroup_kn_lock_live(of->kn);
 	if (!cgrp)
 		return -ENODEV;
 
@@ -3040,7 +2840,7 @@ static ssize_t cgroup_release_agent_write(struct kernfs_open_file *of,
 
 	BUILD_BUG_ON(sizeof(cgrp->root->release_agent_path) < PATH_MAX);
 
-	cgrp = cgroup_kn_lock_live(of->kn, false);
+	cgrp = cgroup_kn_lock_live(of->kn);
 	if (!cgrp)
 		return -ENODEV;
 	spin_lock(&release_agent_path_lock);
@@ -3068,28 +2868,38 @@ static int cgroup_sane_behavior_show(struct seq_file *seq, void *v)
 	return 0;
 }
 
-static void cgroup_print_ss_mask(struct seq_file *seq, u16 ss_mask)
+static void cgroup_print_ss_mask(struct seq_file *seq, unsigned long ss_mask)
 {
 	struct cgroup_subsys *ss;
 	bool printed = false;
 	int ssid;
 
-	do_each_subsys_mask(ss, ssid, ss_mask) {
+	for_each_subsys_which(ss, ssid, &ss_mask) {
 		if (printed)
 			seq_putc(seq, ' ');
 		seq_printf(seq, "%s", ss->name);
 		printed = true;
-	} while_each_subsys_mask();
+	}
 	if (printed)
 		seq_putc(seq, '\n');
 }
 
+/* show controllers which are currently attached to the default hierarchy */
+static int cgroup_root_controllers_show(struct seq_file *seq, void *v)
+{
+	struct cgroup *cgrp = seq_css(seq)->cgroup;
+
+	cgroup_print_ss_mask(seq, cgrp->root->subsys_mask &
+			     ~cgrp_dfl_root_inhibit_ss_mask);
+	return 0;
+}
+
 /* show controllers which are enabled from the parent */
 static int cgroup_controllers_show(struct seq_file *seq, void *v)
 {
 	struct cgroup *cgrp = seq_css(seq)->cgroup;
 
-	cgroup_print_ss_mask(seq, cgroup_control(cgrp));
+	cgroup_print_ss_mask(seq, cgroup_parent(cgrp)->subtree_control);
 	return 0;
 }
 
@@ -3106,17 +2916,16 @@ static int cgroup_subtree_control_show(struct seq_file *seq, void *v)
  * cgroup_update_dfl_csses - update css assoc of a subtree in default hierarchy
  * @cgrp: root of the subtree to update csses for
  *
- * @cgrp's control masks have changed and its subtree's css associations
- * need to be updated accordingly.  This function looks up all css_sets
- * which are attached to the subtree, creates the matching updated css_sets
- * and migrates the tasks to the new ones.
+ * @cgrp's child_subsys_mask has changed and its subtree's (self excluded)
+ * css associations need to be updated accordingly.  This function looks up
+ * all css_sets which are attached to the subtree, creates the matching
+ * updated css_sets and migrates the tasks to the new ones.
  */
 static int cgroup_update_dfl_csses(struct cgroup *cgrp)
 {
 	LIST_HEAD(preloaded_csets);
 	struct cgroup_taskset tset = CGROUP_TASKSET_INIT(tset);
-	struct cgroup_subsys_state *d_css;
-	struct cgroup *dsct;
+	struct cgroup_subsys_state *css;
 	struct css_set *src_cset;
 	int ret;
 
@@ -3126,17 +2935,21 @@ static int cgroup_update_dfl_csses(struct cgroup *cgrp)
 
 	/* look up all csses currently attached to @cgrp's subtree */
 	spin_lock_irq(&css_set_lock);
-	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
+	css_for_each_descendant_pre(css, cgroup_css(cgrp, NULL)) {
 		struct cgrp_cset_link *link;
 
-		list_for_each_entry(link, &dsct->cset_links, cset_link)
-			cgroup_migrate_add_src(link->cset, dsct,
+		/* self is not affected by child_subsys_mask change */
+		if (css->cgroup == cgrp)
+			continue;
+
+		list_for_each_entry(link, &css->cgroup->cset_links, cset_link)
+			cgroup_migrate_add_src(link->cset, cgrp,
 					       &preloaded_csets);
 	}
 	spin_unlock_irq(&css_set_lock);
 
 	/* NULL dst indicates self on default hierarchy */
-	ret = cgroup_migrate_prepare_dst(&preloaded_csets);
+	ret = cgroup_migrate_prepare_dst(NULL, &preloaded_csets);
 	if (ret)
 		goto out_finish;
 
@@ -3154,272 +2967,20 @@ static int cgroup_update_dfl_csses(struct cgroup *cgrp)
 	}
 	spin_unlock_irq(&css_set_lock);
 
-	ret = cgroup_taskset_migrate(&tset, cgrp->root);
+	ret = cgroup_taskset_migrate(&tset, cgrp);
 out_finish:
 	cgroup_migrate_finish(&preloaded_csets);
 	percpu_up_write(&cgroup_threadgroup_rwsem);
 	return ret;
 }
 
-/**
- * cgroup_lock_and_drain_offline - lock cgroup_mutex and drain offlined csses
- * @cgrp: root of the target subtree
- *
- * Because css offlining is asynchronous, userland may try to re-enable a
- * controller while the previous css is still around.  This function grabs
- * cgroup_mutex and drains the previous css instances of @cgrp's subtree.
- */
-static void cgroup_lock_and_drain_offline(struct cgroup *cgrp)
-	__acquires(&cgroup_mutex)
-{
-	struct cgroup *dsct;
-	struct cgroup_subsys_state *d_css;
-	struct cgroup_subsys *ss;
-	int ssid;
-
-restart:
-	mutex_lock(&cgroup_mutex);
-
-	cgroup_for_each_live_descendant_post(dsct, d_css, cgrp) {
-		for_each_subsys(ss, ssid) {
-			struct cgroup_subsys_state *css = cgroup_css(dsct, ss);
-			DEFINE_WAIT(wait);
-
-			if (!css || !percpu_ref_is_dying(&css->refcnt))
-				continue;
-
-			cgroup_get(dsct);
-			prepare_to_wait(&dsct->offline_waitq, &wait,
-					TASK_UNINTERRUPTIBLE);
-
-			mutex_unlock(&cgroup_mutex);
-			schedule();
-			finish_wait(&dsct->offline_waitq, &wait);
-
-			cgroup_put(dsct);
-			goto restart;
-		}
-	}
-}
-
-/**
- * cgroup_save_control - save control masks of a subtree
- * @cgrp: root of the target subtree
- *
- * Save ->subtree_control and ->subtree_ss_mask to the respective old_
- * prefixed fields for @cgrp's subtree including @cgrp itself.
- */
-static void cgroup_save_control(struct cgroup *cgrp)
-{
-	struct cgroup *dsct;
-	struct cgroup_subsys_state *d_css;
-
-	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
-		dsct->old_subtree_control = dsct->subtree_control;
-		dsct->old_subtree_ss_mask = dsct->subtree_ss_mask;
-	}
-}
-
-/**
- * cgroup_propagate_control - refresh control masks of a subtree
- * @cgrp: root of the target subtree
- *
- * For @cgrp and its subtree, ensure ->subtree_ss_mask matches
- * ->subtree_control and propagate controller availability through the
- * subtree so that descendants don't have unavailable controllers enabled.
- */
-static void cgroup_propagate_control(struct cgroup *cgrp)
-{
-	struct cgroup *dsct;
-	struct cgroup_subsys_state *d_css;
-
-	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
-		dsct->subtree_control &= cgroup_control(dsct);
-		dsct->subtree_ss_mask =
-			cgroup_calc_subtree_ss_mask(dsct->subtree_control,
-						    cgroup_ss_mask(dsct));
-	}
-}
-
-/**
- * cgroup_restore_control - restore control masks of a subtree
- * @cgrp: root of the target subtree
- *
- * Restore ->subtree_control and ->subtree_ss_mask from the respective old_
- * prefixed fields for @cgrp's subtree including @cgrp itself.
- */
-static void cgroup_restore_control(struct cgroup *cgrp)
-{
-	struct cgroup *dsct;
-	struct cgroup_subsys_state *d_css;
-
-	cgroup_for_each_live_descendant_post(dsct, d_css, cgrp) {
-		dsct->subtree_control = dsct->old_subtree_control;
-		dsct->subtree_ss_mask = dsct->old_subtree_ss_mask;
-	}
-}
-
-static bool css_visible(struct cgroup_subsys_state *css)
-{
-	struct cgroup_subsys *ss = css->ss;
-	struct cgroup *cgrp = css->cgroup;
-
-	if (cgroup_control(cgrp) & (1 << ss->id))
-		return true;
-	if (!(cgroup_ss_mask(cgrp) & (1 << ss->id)))
-		return false;
-	return cgroup_on_dfl(cgrp) && ss->implicit_on_dfl;
-}
-
-/**
- * cgroup_apply_control_enable - enable or show csses according to control
- * @cgrp: root of the target subtree
- *
- * Walk @cgrp's subtree and create new csses or make the existing ones
- * visible.  A css is created invisible if it's being implicitly enabled
- * through dependency.  An invisible css is made visible when the userland
- * explicitly enables it.
- *
- * Returns 0 on success, -errno on failure.  On failure, csses which have
- * been processed already aren't cleaned up.  The caller is responsible for
- * cleaning up with cgroup_apply_control_disble().
- */
-static int cgroup_apply_control_enable(struct cgroup *cgrp)
-{
-	struct cgroup *dsct;
-	struct cgroup_subsys_state *d_css;
-	struct cgroup_subsys *ss;
-	int ssid, ret;
-
-	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
-		for_each_subsys(ss, ssid) {
-			struct cgroup_subsys_state *css = cgroup_css(dsct, ss);
-
-			WARN_ON_ONCE(css && percpu_ref_is_dying(&css->refcnt));
-
-			if (!(cgroup_ss_mask(dsct) & (1 << ss->id)))
-				continue;
-
-			if (!css) {
-				css = css_create(dsct, ss);
-				if (IS_ERR(css))
-					return PTR_ERR(css);
-			}
-
-			if (css_visible(css)) {
-				ret = css_populate_dir(css);
-				if (ret)
-					return ret;
-			}
-		}
-	}
-
-	return 0;
-}
-
-/**
- * cgroup_apply_control_disable - kill or hide csses according to control
- * @cgrp: root of the target subtree
- *
- * Walk @cgrp's subtree and kill and hide csses so that they match
- * cgroup_ss_mask() and cgroup_visible_mask().
- *
- * A css is hidden when the userland requests it to be disabled while other
- * subsystems are still depending on it.  The css must not actively control
- * resources and be in the vanilla state if it's made visible again later.
- * Controllers which may be depended upon should provide ->css_reset() for
- * this purpose.
- */
-static void cgroup_apply_control_disable(struct cgroup *cgrp)
-{
-	struct cgroup *dsct;
-	struct cgroup_subsys_state *d_css;
-	struct cgroup_subsys *ss;
-	int ssid;
-
-	cgroup_for_each_live_descendant_post(dsct, d_css, cgrp) {
-		for_each_subsys(ss, ssid) {
-			struct cgroup_subsys_state *css = cgroup_css(dsct, ss);
-
-			WARN_ON_ONCE(css && percpu_ref_is_dying(&css->refcnt));
-
-			if (!css)
-				continue;
-
-			if (css->parent &&
-			    !(cgroup_ss_mask(dsct) & (1 << ss->id))) {
-				kill_css(css);
-			} else if (!css_visible(css)) {
-				css_clear_dir(css);
-				if (ss->css_reset)
-					ss->css_reset(css);
-			}
-		}
-	}
-}
-
-/**
- * cgroup_apply_control - apply control mask updates to the subtree
- * @cgrp: root of the target subtree
- *
- * subsystems can be enabled and disabled in a subtree using the following
- * steps.
- *
- * 1. Call cgroup_save_control() to stash the current state.
- * 2. Update ->subtree_control masks in the subtree as desired.
- * 3. Call cgroup_apply_control() to apply the changes.
- * 4. Optionally perform other related operations.
- * 5. Call cgroup_finalize_control() to finish up.
- *
- * This function implements step 3 and propagates the mask changes
- * throughout @cgrp's subtree, updates csses accordingly and perform
- * process migrations.
- */
-static int cgroup_apply_control(struct cgroup *cgrp)
-{
-	int ret;
-
-	cgroup_propagate_control(cgrp);
-
-	ret = cgroup_apply_control_enable(cgrp);
-	if (ret)
-		return ret;
-
-	/*
-	 * At this point, cgroup_e_css() results reflect the new csses
-	 * making the following cgroup_update_dfl_csses() properly update
-	 * css associations of all tasks in the subtree.
-	 */
-	ret = cgroup_update_dfl_csses(cgrp);
-	if (ret)
-		return ret;
-
-	return 0;
-}
-
-/**
- * cgroup_finalize_control - finalize control mask update
- * @cgrp: root of the target subtree
- * @ret: the result of the update
- *
- * Finalize control mask update.  See cgroup_apply_control() for more info.
- */
-static void cgroup_finalize_control(struct cgroup *cgrp, int ret)
-{
-	if (ret) {
-		cgroup_restore_control(cgrp);
-		cgroup_propagate_control(cgrp);
-	}
-
-	cgroup_apply_control_disable(cgrp);
-}
-
 /* change the enabled child controllers for a cgroup in the default hierarchy */
 static ssize_t cgroup_subtree_control_write(struct kernfs_open_file *of,
 					    char *buf, size_t nbytes,
 					    loff_t off)
 {
-	u16 enable = 0, disable = 0;
+	unsigned long enable = 0, disable = 0;
+	unsigned long css_enable, css_disable, old_sc, new_sc, old_ss, new_ss;
 	struct cgroup *cgrp, *child;
 	struct cgroup_subsys *ss;
 	char *tok;
@@ -3431,9 +2992,11 @@ static ssize_t cgroup_subtree_control_write(struct kernfs_open_file *of,
 	 */
 	buf = strstrip(buf);
 	while ((tok = strsep(&buf, " "))) {
+		unsigned long tmp_ss_mask = ~cgrp_dfl_root_inhibit_ss_mask;
+
 		if (tok[0] == '\0')
 			continue;
-		do_each_subsys_mask(ss, ssid, ~cgrp_dfl_inhibit_ss_mask) {
+		for_each_subsys_which(ss, ssid, &tmp_ss_mask) {
 			if (!cgroup_ssid_enabled(ssid) ||
 			    strcmp(tok + 1, ss->name))
 				continue;
@@ -3448,12 +3011,12 @@ static ssize_t cgroup_subtree_control_write(struct kernfs_open_file *of,
 				return -EINVAL;
 			}
 			break;
-		} while_each_subsys_mask();
+		}
 		if (ssid == CGROUP_SUBSYS_COUNT)
 			return -EINVAL;
 	}
 
-	cgrp = cgroup_kn_lock_live(of->kn, true);
+	cgrp = cgroup_kn_lock_live(of->kn);
 	if (!cgrp)
 		return -ENODEV;
 
@@ -3464,7 +3027,10 @@ static ssize_t cgroup_subtree_control_write(struct kernfs_open_file *of,
 				continue;
 			}
 
-			if (!(cgroup_control(cgrp) & (1 << ssid))) {
+			/* unavailable or not enabled on the parent? */
+			if (!(cgrp_dfl_root.subsys_mask & (1 << ssid)) ||
+			    (cgroup_parent(cgrp) &&
+			     !(cgroup_parent(cgrp)->subtree_control & (1 << ssid)))) {
 				ret = -ENOENT;
 				goto out_unlock;
 			}
@@ -3493,45 +3059,155 @@ static ssize_t cgroup_subtree_control_write(struct kernfs_open_file *of,
 	 * Except for the root, subtree_control must be zero for a cgroup
 	 * with tasks so that child cgroups don't compete against tasks.
 	 */
-	if (enable && cgroup_parent(cgrp)) {
-		struct cgrp_cset_link *link;
+	if (enable && cgroup_parent(cgrp) && !list_empty(&cgrp->cset_links)) {
+		ret = -EBUSY;
+		goto out_unlock;
+	}
 
-		/*
-		 * Because namespaces pin csets too, @cgrp->cset_links
-		 * might not be empty even when @cgrp is empty.  Walk and
-		 * verify each cset.
-		 */
-		spin_lock_irq(&css_set_lock);
+	/*
+	 * Update subsys masks and calculate what needs to be done.  More
+	 * subsystems than specified may need to be enabled or disabled
+	 * depending on subsystem dependencies.
+	 */
+	old_sc = cgrp->subtree_control;
+	old_ss = cgrp->child_subsys_mask;
+	new_sc = (old_sc | enable) & ~disable;
+	new_ss = cgroup_calc_child_subsys_mask(cgrp, new_sc);
 
-		ret = 0;
-		list_for_each_entry(link, &cgrp->cset_links, cset_link) {
-			if (css_set_populated(link->cset)) {
-				ret = -EBUSY;
-				break;
-			}
+	css_enable = ~old_ss & new_ss;
+	css_disable = old_ss & ~new_ss;
+	enable |= css_enable;
+	disable |= css_disable;
+
+	/*
+	 * Because css offlining is asynchronous, userland might try to
+	 * re-enable the same controller while the previous instance is
+	 * still around.  In such cases, wait till it's gone using
+	 * offline_waitq.
+	 */
+	for_each_subsys_which(ss, ssid, &css_enable) {
+		cgroup_for_each_live_child(child, cgrp) {
+			DEFINE_WAIT(wait);
+
+			if (!cgroup_css(child, ss))
+				continue;
+
+			cgroup_get(child);
+			prepare_to_wait(&child->offline_waitq, &wait,
+					TASK_UNINTERRUPTIBLE);
+			cgroup_kn_unlock(of->kn);
+			schedule();
+			finish_wait(&child->offline_waitq, &wait);
+			cgroup_put(child);
+
+			return restart_syscall();
 		}
+	}
 
-		spin_unlock_irq(&css_set_lock);
+	cgrp->subtree_control = new_sc;
+	cgrp->child_subsys_mask = new_ss;
 
-		if (ret)
-			goto out_unlock;
+	/*
+	 * Create new csses or make the existing ones visible.  A css is
+	 * created invisible if it's being implicitly enabled through
+	 * dependency.  An invisible css is made visible when the userland
+	 * explicitly enables it.
+	 */
+	for_each_subsys(ss, ssid) {
+		if (!(enable & (1 << ssid)))
+			continue;
+
+		cgroup_for_each_live_child(child, cgrp) {
+			if (css_enable & (1 << ssid))
+				ret = create_css(child, ss,
+					cgrp->subtree_control & (1 << ssid));
+			else
+				ret = css_populate_dir(cgroup_css(child, ss),
+						       NULL);
+			if (ret)
+				goto err_undo_css;
+		}
 	}
 
-	/* save and update control masks and prepare csses */
-	cgroup_save_control(cgrp);
+	/*
+	 * At this point, cgroup_e_css() results reflect the new csses
+	 * making the following cgroup_update_dfl_csses() properly update
+	 * css associations of all tasks in the subtree.
+	 */
+	ret = cgroup_update_dfl_csses(cgrp);
+	if (ret)
+		goto err_undo_css;
+
+	/*
+	 * All tasks are migrated out of disabled csses.  Kill or hide
+	 * them.  A css is hidden when the userland requests it to be
+	 * disabled while other subsystems are still depending on it.  The
+	 * css must not actively control resources and be in the vanilla
+	 * state if it's made visible again later.  Controllers which may
+	 * be depended upon should provide ->css_reset() for this purpose.
+	 */
+	for_each_subsys(ss, ssid) {
+		if (!(disable & (1 << ssid)))
+			continue;
+
+		cgroup_for_each_live_child(child, cgrp) {
+			struct cgroup_subsys_state *css = cgroup_css(child, ss);
+
+			if (css_disable & (1 << ssid)) {
+				kill_css(css);
+			} else {
+				css_clear_dir(css, NULL);
+				if (ss->css_reset)
+					ss->css_reset(css);
+			}
+		}
+	}
 
-	cgrp->subtree_control |= enable;
-	cgrp->subtree_control &= ~disable;
+	/*
+	 * The effective csses of all the descendants (excluding @cgrp) may
+	 * have changed.  Subsystems can optionally subscribe to this event
+	 * by implementing ->css_e_css_changed() which is invoked if any of
+	 * the effective csses seen from the css's cgroup may have changed.
+	 */
+	for_each_subsys(ss, ssid) {
+		struct cgroup_subsys_state *this_css = cgroup_css(cgrp, ss);
+		struct cgroup_subsys_state *css;
 
-	ret = cgroup_apply_control(cgrp);
+		if (!ss->css_e_css_changed || !this_css)
+			continue;
 
-	cgroup_finalize_control(cgrp, ret);
+		css_for_each_descendant_pre(css, this_css)
+			if (css != this_css)
+				ss->css_e_css_changed(css);
+	}
 
 	kernfs_activate(cgrp->kn);
 	ret = 0;
 out_unlock:
 	cgroup_kn_unlock(of->kn);
 	return ret ?: nbytes;
+
+err_undo_css:
+	cgrp->subtree_control = old_sc;
+	cgrp->child_subsys_mask = old_ss;
+
+	for_each_subsys(ss, ssid) {
+		if (!(enable & (1 << ssid)))
+			continue;
+
+		cgroup_for_each_live_child(child, cgrp) {
+			struct cgroup_subsys_state *css = cgroup_css(child, ss);
+
+			if (!css)
+				continue;
+
+			if (css_enable & (1 << ssid))
+				kill_css(css);
+			else
+				css_clear_dir(css, NULL);
+		}
+	}
+	goto out_unlock;
 }
 
 static int cgroup_events_show(struct seq_file *seq, void *v)
@@ -3541,23 +3217,6 @@ static int cgroup_events_show(struct seq_file *seq, void *v)
 	return 0;
 }
 
-static int cgroup_file_open(struct kernfs_open_file *of)
-{
-	struct cftype *cft = of->kn->priv;
-
-	if (cft->open)
-		return cft->open(of);
-	return 0;
-}
-
-static void cgroup_file_release(struct kernfs_open_file *of)
-{
-	struct cftype *cft = of->kn->priv;
-
-	if (cft->release)
-		cft->release(of);
-}
-
 static ssize_t cgroup_file_write(struct kernfs_open_file *of, char *buf,
 				 size_t nbytes, loff_t off)
 {
@@ -3596,16 +3255,6 @@ static ssize_t cgroup_file_write(struct kernfs_open_file *of, char *buf,
 	return ret ?: nbytes;
 }
 
-static unsigned int cgroup_file_poll(struct kernfs_open_file *of, poll_table *pt)
-{
-	struct cftype *cft = of->kn->priv;
-
-	if (cft->poll)
-		return cft->poll(of, pt);
-
-	return kernfs_generic_poll(of, pt);
-}
-
 static void *cgroup_seqfile_start(struct seq_file *seq, loff_t *ppos)
 {
 	return seq_cft(seq)->seq_start(seq, ppos);
@@ -3618,8 +3267,7 @@ static void *cgroup_seqfile_next(struct seq_file *seq, void *v, loff_t *ppos)
 
 static void cgroup_seqfile_stop(struct seq_file *seq, void *v)
 {
-	if (seq_cft(seq)->seq_stop)
-		seq_cft(seq)->seq_stop(seq, v);
+	seq_cft(seq)->seq_stop(seq, v);
 }
 
 static int cgroup_seqfile_show(struct seq_file *m, void *arg)
@@ -3641,19 +3289,13 @@ static int cgroup_seqfile_show(struct seq_file *m, void *arg)
 
 static struct kernfs_ops cgroup_kf_single_ops = {
 	.atomic_write_len	= PAGE_SIZE,
-	.open			= cgroup_file_open,
-	.release		= cgroup_file_release,
 	.write			= cgroup_file_write,
-	.poll			= cgroup_file_poll,
 	.seq_show		= cgroup_seqfile_show,
 };
 
 static struct kernfs_ops cgroup_kf_ops = {
 	.atomic_write_len	= PAGE_SIZE,
-	.open			= cgroup_file_open,
-	.release		= cgroup_file_release,
 	.write			= cgroup_file_write,
-	.poll			= cgroup_file_poll,
 	.seq_start		= cgroup_seqfile_start,
 	.seq_next		= cgroup_seqfile_next,
 	.seq_stop		= cgroup_seqfile_stop,
@@ -3696,8 +3338,6 @@ static int cgroup_rename(struct kernfs_node *kn, struct kernfs_node *new_parent,
 	mutex_lock(&cgroup_mutex);
 
 	ret = kernfs_rename(kn, new_parent, new_name_str);
-	if (!ret)
-		trace_cgroup_rename(cgrp);
 
 	mutex_unlock(&cgroup_mutex);
 
@@ -3769,7 +3409,7 @@ static int cgroup_addrm_files(struct cgroup_subsys_state *css,
 			      bool is_add)
 {
 	struct cftype *cft, *cft_end = NULL;
-	int ret = 0;
+	int ret;
 
 	lockdep_assert_held(&cgroup_mutex);
 
@@ -3798,7 +3438,7 @@ restart:
 			cgroup_rm_file(cgrp, cft);
 		}
 	}
-	return ret;
+	return 0;
 }
 
 static int cgroup_apply_cftypes(struct cftype *cfts, bool is_add)
@@ -3815,7 +3455,7 @@ static int cgroup_apply_cftypes(struct cftype *cfts, bool is_add)
 	css_for_each_descendant_pre(css, cgroup_css(root, ss)) {
 		struct cgroup *cgrp = css->cgroup;
 
-		if (!(css->flags & CSS_VISIBLE))
+		if (cgroup_is_dead(cgrp))
 			continue;
 
 		ret = cgroup_addrm_files(css, cgrp, cfts, is_add);
@@ -4005,9 +3645,7 @@ void cgroup_file_notify(struct cgroup_file *cfile)
  * cgroup_task_count - count the number of tasks in a cgroup.
  * @cgrp: the cgroup in question
  *
- * Return the number of tasks in the cgroup.  The returned number can be
- * higher than the actual number of tasks due to css_set references from
- * namespace roots and temporary usages.
+ * Return the number of tasks in the cgroup.
  */
 static int cgroup_task_count(const struct cgroup *cgrp)
 {
@@ -4438,9 +4076,6 @@ int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from)
 	struct task_struct *task;
 	int ret;
 
-	if (!cgroup_may_migrate_to(to))
-		return -EBUSY;
-
 	mutex_lock(&cgroup_mutex);
 
 	percpu_down_write(&cgroup_threadgroup_rwsem);
@@ -4451,12 +4086,12 @@ int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from)
 		cgroup_migrate_add_src(link->cset, to, &preloaded_csets);
 	spin_unlock_irq(&css_set_lock);
 
-	ret = cgroup_migrate_prepare_dst(&preloaded_csets);
+	ret = cgroup_migrate_prepare_dst(to, &preloaded_csets);
 	if (ret)
 		goto out_err;
 
 	/*
-	 * Migrate tasks one-by-one until @from is empty.  This fails iff
+	 * Migrate tasks one-by-one until @form is empty.  This fails iff
 	 * ->can_attach() fails.
 	 */
 	do {
@@ -4471,9 +4106,7 @@ int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from)
 		css_task_iter_end(&it);
 
 		if (task) {
-			ret = cgroup_migrate(task, false, to->root);
-			if (!ret)
-				trace_cgroup_transfer_tasks(to, task, false);
+			ret = cgroup_migrate(task, false, to);
 			put_task_struct(task);
 		}
 	} while (task && !ret);
@@ -4981,6 +4614,12 @@ static struct cftype cgroup_dfl_base_files[] = {
 	},
 	{
 		.name = "cgroup.controllers",
+		.flags = CFTYPE_ONLY_ON_ROOT,
+		.seq_show = cgroup_root_controllers_show,
+	},
+	{
+		.name = "cgroup.controllers",
+		.flags = CFTYPE_NOT_ON_ROOT,
 		.seq_show = cgroup_controllers_show,
 	},
 	{
@@ -5139,8 +4778,6 @@ static void css_release_work_fn(struct work_struct *work)
 			ss->css_released(css);
 	} else {
 		/* cgroup release path */
-		trace_cgroup_release(cgrp);
-
 		cgroup_idr_remove(&cgrp->root->cgroup_idr, cgrp->id);
 		cgrp->id = -1;
 
@@ -5151,11 +4788,7 @@ static void css_release_work_fn(struct work_struct *work)
 		 * Those are supported by RCU protecting clearing of
 		 * cgrp->kn->priv backpointer.
 		 */
-		if (cgrp->kn)
-			RCU_INIT_POINTER(*(void __rcu __force **)&cgrp->kn->priv,
-					 NULL);
-
-		cgroup_bpf_put(cgrp);
+		RCU_INIT_POINTER(*(void __rcu __force **)&cgrp->kn->priv, NULL);
 	}
 
 	mutex_unlock(&cgroup_mutex);
@@ -5227,9 +4860,6 @@ static void offline_css(struct cgroup_subsys_state *css)
 	if (!(css->flags & CSS_ONLINE))
 		return;
 
-	if (ss->css_reset)
-		ss->css_reset(css);
-
 	if (ss->css_offline)
 		ss->css_offline(css);
 
@@ -5240,16 +4870,17 @@ static void offline_css(struct cgroup_subsys_state *css)
 }
 
 /**
- * css_create - create a cgroup_subsys_state
+ * create_css - create a cgroup_subsys_state
  * @cgrp: the cgroup new css will be associated with
  * @ss: the subsys of new css
+ * @visible: whether to create control knobs for the new css or not
  *
  * Create a new css associated with @cgrp - @ss pair.  On success, the new
- * css is online and installed in @cgrp.  This function doesn't create the
- * interface files.  Returns 0 on success, -errno on failure.
+ * css is online and installed in @cgrp with all interface files created if
+ * @visible.  Returns 0 on success, -errno on failure.
  */
-static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
-					      struct cgroup_subsys *ss)
+static int create_css(struct cgroup *cgrp, struct cgroup_subsys *ss,
+		      bool visible)
 {
 	struct cgroup *parent = cgroup_parent(cgrp);
 	struct cgroup_subsys_state *parent_css = cgroup_css(parent, ss);
@@ -5259,10 +4890,8 @@ static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
 	lockdep_assert_held(&cgroup_mutex);
 
 	css = ss->css_alloc(parent_css);
-	if (!css)
-		css = ERR_PTR(-ENOMEM);
 	if (IS_ERR(css))
-		return css;
+		return PTR_ERR(css);
 
 	init_and_link_css(css, ss, cgrp);
 
@@ -5272,9 +4901,15 @@ static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
 
 	err = cgroup_idr_alloc(&ss->css_idr, NULL, 2, 0, GFP_KERNEL);
 	if (err < 0)
-		goto err_free_css;
+		goto err_free_percpu_ref;
 	css->id = err;
 
+	if (visible) {
+		err = css_populate_dir(css, NULL);
+		if (err)
+			goto err_free_id;
+	}
+
 	/* @css is ready to be brought online now, make it visible */
 	list_add_tail_rcu(&css->sibling, &parent_css->children);
 	cgroup_idr_replace(&ss->css_idr, css, css->id);
@@ -5292,34 +4927,47 @@ static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
 		ss->warned_broken_hierarchy = true;
 	}
 
-	return css;
+	return 0;
 
 err_list_del:
 	list_del_rcu(&css->sibling);
+	css_clear_dir(css, NULL);
+err_free_id:
+	cgroup_idr_remove(&ss->css_idr, css->id);
+err_free_percpu_ref:
+	percpu_ref_exit(&css->refcnt);
 err_free_css:
 	call_rcu(&css->rcu_head, css_free_rcu_fn);
-	return ERR_PTR(err);
+	return err;
 }
 
-/*
- * The returned cgroup is fully initialized including its control mask, but
- * it isn't associated with its kernfs_node and doesn't have the control
- * mask applied.
- */
-static struct cgroup *cgroup_create(struct cgroup *parent)
+static int cgroup_mkdir(struct kernfs_node *parent_kn, const char *name,
+			umode_t mode)
 {
-	struct cgroup_root *root = parent->root;
-	struct cgroup *cgrp, *tcgrp;
-	int level = parent->level + 1;
-	int ret;
+	struct cgroup *parent, *cgrp;
+	struct cgroup_root *root;
+	struct cgroup_subsys *ss;
+	struct kernfs_node *kn;
+	int ssid, ret;
 
-	/* allocate the cgroup and its ID, 0 is reserved for the root */
-	cgrp = kzalloc(sizeof(*cgrp) +
-		       sizeof(cgrp->ancestor_ids[0]) * (level + 1), GFP_KERNEL);
-	if (!cgrp)
-		return ERR_PTR(-ENOMEM);
+	/* Do not accept '\n' to prevent making /proc/<pid>/cgroup unparsable.
+	 */
+	if (strchr(name, '\n'))
+		return -EINVAL;
 
-	ret = percpu_ref_init(&cgrp->self.refcnt, css_release, 0, GFP_KERNEL);
+	parent = cgroup_kn_lock_live(parent_kn);
+	if (!parent)
+		return -ENODEV;
+	root = parent->root;
+
+	/* allocate the cgroup and its ID, 0 is reserved for the root */
+	cgrp = kzalloc(sizeof(*cgrp), GFP_KERNEL);
+	if (!cgrp) {
+		ret = -ENOMEM;
+		goto out_unlock;
+	}
+
+	ret = percpu_ref_init(&cgrp->self.refcnt, css_release, 0, GFP_KERNEL);
 	if (ret)
 		goto out_free_cgrp;
 
@@ -5337,15 +4985,6 @@ static struct cgroup *cgroup_create(struct cgroup *parent)
 
 	cgrp->self.parent = &parent->self;
 	cgrp->root = root;
-	cgrp->level = level;
-	ret = cgroup_bpf_inherit(cgrp);
-	if (ret) {
-		cgroup_idr_remove(&root->cgroup_idr, cgrp->id);
-		goto out_cancel_ref;
-	}
-
-	for (tcgrp = cgrp; tcgrp; tcgrp = cgroup_parent(tcgrp))
-		cgrp->ancestor_ids[tcgrp->level] = tcgrp->id;
 
 	if (notify_on_release(parent))
 		set_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
@@ -5353,63 +4992,11 @@ static struct cgroup *cgroup_create(struct cgroup *parent)
 	if (test_bit(CGRP_CPUSET_CLONE_CHILDREN, &parent->flags))
 		set_bit(CGRP_CPUSET_CLONE_CHILDREN, &cgrp->flags);
 
-	cgrp->self.serial_nr = css_serial_nr_next++;
-
-	/* allocation complete, commit to creation */
-	list_add_tail_rcu(&cgrp->self.sibling, &cgroup_parent(cgrp)->self.children);
-	atomic_inc(&root->nr_cgrps);
-	cgroup_get(parent);
-
-	/*
-	 * @cgrp is now fully operational.  If something fails after this
-	 * point, it'll be released via the normal destruction path.
-	 */
-	cgroup_idr_replace(&root->cgroup_idr, cgrp, cgrp->id);
-
-	/*
-	 * On the default hierarchy, a child doesn't automatically inherit
-	 * subtree_control from the parent.  Each is configured manually.
-	 */
-	if (!cgroup_on_dfl(cgrp))
-		cgrp->subtree_control = cgroup_control(cgrp);
-
-	cgroup_propagate_control(cgrp);
-
-	return cgrp;
-
-out_cancel_ref:
-	percpu_ref_exit(&cgrp->self.refcnt);
-out_free_cgrp:
-	kfree(cgrp);
-	return ERR_PTR(ret);
-}
-
-static int cgroup_mkdir(struct kernfs_node *parent_kn, const char *name,
-			umode_t mode)
-{
-	struct cgroup *parent, *cgrp;
-	struct kernfs_node *kn;
-	int ret;
-
-	/* do not accept '\n' to prevent making /proc/<pid>/cgroup unparsable */
-	if (strchr(name, '\n'))
-		return -EINVAL;
-
-	parent = cgroup_kn_lock_live(parent_kn, false);
-	if (!parent)
-		return -ENODEV;
-
-	cgrp = cgroup_create(parent);
-	if (IS_ERR(cgrp)) {
-		ret = PTR_ERR(cgrp);
-		goto out_unlock;
-	}
-
 	/* create the directory */
 	kn = kernfs_create_dir(parent->kn, name, mode, cgrp);
 	if (IS_ERR(kn)) {
 		ret = PTR_ERR(kn);
-		goto out_destroy;
+		goto out_free_id;
 	}
 	cgrp->kn = kn;
 
@@ -5419,31 +5006,64 @@ static int cgroup_mkdir(struct kernfs_node *parent_kn, const char *name,
 	 */
 	kernfs_get(kn);
 
+	cgrp->self.serial_nr = css_serial_nr_next++;
+
+	/* allocation complete, commit to creation */
+	list_add_tail_rcu(&cgrp->self.sibling, &cgroup_parent(cgrp)->self.children);
+	atomic_inc(&root->nr_cgrps);
+	cgroup_get(parent);
+
+	/*
+	 * @cgrp is now fully operational.  If something fails after this
+	 * point, it'll be released via the normal destruction path.
+	 */
+	cgroup_idr_replace(&root->cgroup_idr, cgrp, cgrp->id);
+
 	ret = cgroup_kn_set_ugid(kn);
 	if (ret)
 		goto out_destroy;
 
-	ret = css_populate_dir(&cgrp->self);
+	ret = css_populate_dir(&cgrp->self, NULL);
 	if (ret)
 		goto out_destroy;
 
-	ret = cgroup_apply_control_enable(cgrp);
-	if (ret)
-		goto out_destroy;
+	/* let's create and online css's */
+	for_each_subsys(ss, ssid) {
+		if (parent->child_subsys_mask & (1 << ssid)) {
+			ret = create_css(cgrp, ss,
+					 parent->subtree_control & (1 << ssid));
+			if (ret)
+				goto out_destroy;
+		}
+	}
 
-	trace_cgroup_mkdir(cgrp);
+	/*
+	 * On the default hierarchy, a child doesn't automatically inherit
+	 * subtree_control from the parent.  Each is configured manually.
+	 */
+	if (!cgroup_on_dfl(cgrp)) {
+		cgrp->subtree_control = parent->subtree_control;
+		cgroup_refresh_child_subsys_mask(cgrp);
+	}
 
-	/* let's create and online css's */
 	kernfs_activate(kn);
 
 	ret = 0;
 	goto out_unlock;
 
-out_destroy:
-	cgroup_destroy_locked(cgrp);
+out_free_id:
+	cgroup_idr_remove(&root->cgroup_idr, cgrp->id);
+out_cancel_ref:
+	percpu_ref_exit(&cgrp->self.refcnt);
+out_free_cgrp:
+	kfree(cgrp);
 out_unlock:
 	cgroup_kn_unlock(parent_kn);
 	return ret;
+
+out_destroy:
+	cgroup_destroy_locked(cgrp);
+	goto out_unlock;
 }
 
 /*
@@ -5497,7 +5117,7 @@ static void kill_css(struct cgroup_subsys_state *css)
 	 * This must happen before css is disassociated with its cgroup.
 	 * See seq_css() for details.
 	 */
-	css_clear_dir(css);
+	css_clear_dir(css, NULL);
 
 	/*
 	 * Killing would put the base ref, but we need to keep it alive
@@ -5602,15 +5222,12 @@ static int cgroup_rmdir(struct kernfs_node *kn)
 	struct cgroup *cgrp;
 	int ret = 0;
 
-	cgrp = cgroup_kn_lock_live(kn, false);
+	cgrp = cgroup_kn_lock_live(kn);
 	if (!cgrp)
 		return 0;
 
 	ret = cgroup_destroy_locked(cgrp);
 
-	if (!ret)
-		trace_cgroup_rmdir(cgrp);
-
 	cgroup_kn_unlock(kn);
 	return ret;
 }
@@ -5621,14 +5238,13 @@ static struct kernfs_syscall_ops cgroup_kf_syscall_ops = {
 	.mkdir			= cgroup_mkdir,
 	.rmdir			= cgroup_rmdir,
 	.rename			= cgroup_rename,
-	.show_path		= cgroup_show_path,
 };
 
 static void __init cgroup_init_subsys(struct cgroup_subsys *ss, bool early)
 {
 	struct cgroup_subsys_state *css;
 
-	pr_debug("Initializing cgroup subsys %s\n", ss->name);
+	printk(KERN_INFO "Initializing cgroup subsys %s\n", ss->name);
 
 	mutex_lock(&cgroup_mutex);
 
@@ -5696,7 +5312,7 @@ int __init cgroup_init_early(void)
 
 	for_each_subsys(ss, i) {
 		WARN(!ss->css_alloc || !ss->css_free || ss->name || ss->id,
-		     "invalid cgroup_subsys %d:%s css_alloc=%p css_free=%p id:name=%d:%s\n",
+		     "invalid cgroup_subsys %d:%s css_alloc=%p css_free=%p name:id=%d:%s\n",
 		     i, cgroup_subsys_name[i], ss->css_alloc, ss->css_free,
 		     ss->id, ss->name);
 		WARN(strlen(cgroup_subsys_name[i]) > MAX_CGROUP_TYPE_NAMELEN,
@@ -5713,7 +5329,7 @@ int __init cgroup_init_early(void)
 	return 0;
 }
 
-static u16 cgroup_disable_mask __initdata;
+static unsigned long cgroup_disable_mask __initdata;
 
 /**
  * cgroup_init - cgroup initialization
@@ -5724,9 +5340,9 @@ static u16 cgroup_disable_mask __initdata;
 int __init cgroup_init(void)
 {
 	struct cgroup_subsys *ss;
+	unsigned long key;
 	int ssid;
 
-	BUILD_BUG_ON(CGROUP_SUBSYS_COUNT > 16);
 	BUG_ON(percpu_init_rwsem(&cgroup_threadgroup_rwsem));
 	BUG_ON(cgroup_init_cftypes(NULL, cgroup_dfl_base_files));
 	BUG_ON(cgroup_init_cftypes(NULL, cgroup_legacy_base_files));
@@ -5737,16 +5353,11 @@ int __init cgroup_init(void)
 	 */
 	rcu_sync_enter_start(&cgroup_threadgroup_rwsem.rss);
 
-	get_user_ns(init_cgroup_ns.user_ns);
-
 	mutex_lock(&cgroup_mutex);
 
-	/*
-	 * Add init_css_set to the hash table so that dfl_root can link to
-	 * it during init.
-	 */
-	hash_add(css_set_table, &init_css_set.hlist,
-		 css_set_hash(init_css_set.subsys));
+	/* Add init_css_set to the hash table */
+	key = css_set_hash(init_css_set.subsys);
+	hash_add(css_set_table, &init_css_set.hlist, key);
 
 	BUG_ON(cgroup_setup_root(&cgrp_dfl_root, 0));
 
@@ -5779,16 +5390,10 @@ int __init cgroup_init(void)
 			continue;
 		}
 
-		if (cgroup_ssid_no_v1(ssid))
-			printk(KERN_INFO "Disabling %s control group subsystem in v1 mounts\n",
-			       ss->name);
-
 		cgrp_dfl_root.subsys_mask |= 1 << ss->id;
 
-		if (ss->implicit_on_dfl)
-			cgrp_dfl_implicit_ss_mask |= 1 << ss->id;
-		else if (!ss->dfl_cftypes)
-			cgrp_dfl_inhibit_ss_mask |= 1 << ss->id;
+		if (!ss->dfl_cftypes)
+			cgrp_dfl_root_inhibit_ss_mask |= 1 << ss->id;
 
 		if (ss->dfl_cftypes == ss->legacy_cftypes) {
 			WARN_ON(cgroup_add_cftypes(ss, ss->dfl_cftypes));
@@ -5801,11 +5406,6 @@ int __init cgroup_init(void)
 			ss->bind(init_css_set.subsys[ssid]);
 	}
 
-	/* init_css_set.subsys[] has been updated, re-hash */
-	hash_del(&init_css_set.hlist);
-	hash_add(css_set_table, &init_css_set.hlist,
-		 css_set_hash(init_css_set.subsys));
-
 	WARN_ON(sysfs_create_mount_point(fs_kobj, "cgroup"));
 	WARN_ON(register_filesystem(&cgroup_fs_type));
 	WARN_ON(register_filesystem(&cgroup2_fs_type));
@@ -5847,7 +5447,7 @@ core_initcall(cgroup_wq_init);
 int proc_cgroup_show(struct seq_file *m, struct pid_namespace *ns,
 		     struct pid *pid, struct task_struct *tsk)
 {
-	char *buf;
+	char *buf, *path;
 	int retval;
 	struct cgroup_root *root;
 
@@ -5864,7 +5464,7 @@ int proc_cgroup_show(struct seq_file *m, struct pid_namespace *ns,
 		struct cgroup *cgrp;
 		int ssid, count = 0;
 
-		if (root == &cgrp_dfl_root && !cgrp_dfl_visible)
+		if (root == &cgrp_dfl_root && !cgrp_dfl_root_visible)
 			continue;
 
 		seq_printf(m, "%d:", root->hierarchy_id);
@@ -5890,18 +5490,17 @@ int proc_cgroup_show(struct seq_file *m, struct pid_namespace *ns,
 		 * " (deleted)" is appended to the cgroup path.
 		 */
 		if (cgroup_on_dfl(cgrp) || !(tsk->flags & PF_EXITING)) {
-			retval = cgroup_path_ns_locked(cgrp, buf, PATH_MAX,
-						current->nsproxy->cgroup_ns);
-			if (retval >= PATH_MAX)
+			path = cgroup_path(cgrp, buf, PATH_MAX);
+			if (!path) {
 				retval = -ENAMETOOLONG;
-			if (retval < 0)
 				goto out_unlock;
-
-			seq_puts(m, buf);
+			}
 		} else {
-			seq_puts(m, "/");
+			path = "/";
 		}
 
+		seq_puts(m, path);
+
 		if (cgroup_on_dfl(cgrp) && cgroup_is_dead(cgrp))
 			seq_puts(m, " (deleted)\n");
 		else
@@ -5953,6 +5552,19 @@ static const struct file_operations proc_cgroupstats_operations = {
 	.release = single_release,
 };
 
+static void **subsys_canfork_priv_p(void *ss_priv[CGROUP_CANFORK_COUNT], int i)
+{
+	if (CGROUP_CANFORK_START <= i && i < CGROUP_CANFORK_END)
+		return &ss_priv[i - CGROUP_CANFORK_START];
+	return NULL;
+}
+
+static void *subsys_canfork_priv(void *ss_priv[CGROUP_CANFORK_COUNT], int i)
+{
+	void **private = subsys_canfork_priv_p(ss_priv, i);
+	return private ? *private : NULL;
+}
+
 /**
  * cgroup_fork - initialize cgroup related fields during copy_process()
  * @child: pointer to task_struct of forking parent process.
@@ -5975,16 +5587,17 @@ void cgroup_fork(struct task_struct *child)
  * returns an error, the fork aborts with that error code. This allows for
  * a cgroup subsystem to conditionally allow or deny new forks.
  */
-int cgroup_can_fork(struct task_struct *child)
+int cgroup_can_fork(struct task_struct *child,
+		    void *ss_priv[CGROUP_CANFORK_COUNT])
 {
 	struct cgroup_subsys *ss;
 	int i, j, ret;
 
-	do_each_subsys_mask(ss, i, have_canfork_callback) {
-		ret = ss->can_fork(child);
+	for_each_subsys_which(ss, i, &have_canfork_callback) {
+		ret = ss->can_fork(child, subsys_canfork_priv_p(ss_priv, i));
 		if (ret)
 			goto out_revert;
-	} while_each_subsys_mask();
+	}
 
 	return 0;
 
@@ -5993,7 +5606,7 @@ out_revert:
 		if (j >= i)
 			break;
 		if (ss->cancel_fork)
-			ss->cancel_fork(child);
+			ss->cancel_fork(child, subsys_canfork_priv(ss_priv, j));
 	}
 
 	return ret;
@@ -6006,14 +5619,15 @@ out_revert:
  * This calls the cancel_fork() callbacks if a fork failed *after*
  * cgroup_can_fork() succeded.
  */
-void cgroup_cancel_fork(struct task_struct *child)
+void cgroup_cancel_fork(struct task_struct *child,
+			void *ss_priv[CGROUP_CANFORK_COUNT])
 {
 	struct cgroup_subsys *ss;
 	int i;
 
 	for_each_subsys(ss, i)
 		if (ss->cancel_fork)
-			ss->cancel_fork(child);
+			ss->cancel_fork(child, subsys_canfork_priv(ss_priv, i));
 }
 
 /**
@@ -6026,7 +5640,8 @@ void cgroup_cancel_fork(struct task_struct *child)
  * cgroup_task_iter_start() - to guarantee that the new task ends up on its
  * list.
  */
-void cgroup_post_fork(struct task_struct *child)
+void cgroup_post_fork(struct task_struct *child,
+		      void *old_ss_priv[CGROUP_CANFORK_COUNT])
 {
 	struct cgroup_subsys *ss;
 	int i;
@@ -6069,9 +5684,8 @@ void cgroup_post_fork(struct task_struct *child)
 	 * css_set; otherwise, @child might change state between ->fork()
 	 * and addition to css_set.
 	 */
-	do_each_subsys_mask(ss, i, have_fork_callback) {
-		ss->fork(child);
-	} while_each_subsys_mask();
+	for_each_subsys_which(ss, i, &have_fork_callback)
+		ss->fork(child, subsys_canfork_priv(old_ss_priv, i));
 }
 
 /**
@@ -6117,9 +5731,8 @@ void cgroup_exit(struct task_struct *tsk)
 	spin_unlock_irq(&css_set_lock);
 
 	/* see cgroup_post_fork() for details */
-	do_each_subsys_mask(ss, i, have_exit_callback) {
+	for_each_subsys_which(ss, i, &have_exit_callback)
 		ss->exit(tsk);
-	} while_each_subsys_mask();
 }
 
 void cgroup_free(struct task_struct *task)
@@ -6128,9 +5741,8 @@ void cgroup_free(struct task_struct *task)
 	struct cgroup_subsys *ss;
 	int ssid;
 
-	do_each_subsys_mask(ss, ssid, have_free_callback) {
+	for_each_subsys_which(ss, ssid, &have_free_callback)
 		ss->free(task);
-	} while_each_subsys_mask();
 
 	put_css_set(cset);
 }
@@ -6169,9 +5781,8 @@ static void cgroup_release_agent(struct work_struct *work)
 {
 	struct cgroup *cgrp =
 		container_of(work, struct cgroup, release_agent_work);
-	char *pathbuf = NULL, *agentbuf = NULL;
+	char *pathbuf = NULL, *agentbuf = NULL, *path;
 	char *argv[3], *envp[3];
-	int ret;
 
 	mutex_lock(&cgroup_mutex);
 
@@ -6181,13 +5792,13 @@ static void cgroup_release_agent(struct work_struct *work)
 		goto out;
 
 	spin_lock_irq(&css_set_lock);
-	ret = cgroup_path_ns_locked(cgrp, pathbuf, PATH_MAX, &init_cgroup_ns);
+	path = cgroup_path(cgrp, pathbuf, PATH_MAX);
 	spin_unlock_irq(&css_set_lock);
-	if (ret < 0 || ret >= PATH_MAX)
+	if (!path)
 		goto out;
 
 	argv[0] = agentbuf;
-	argv[1] = pathbuf;
+	argv[1] = path;
 	argv[2] = NULL;
 
 	/* minimal command environment */
@@ -6226,33 +5837,6 @@ static int __init cgroup_disable(char *str)
 }
 __setup("cgroup_disable=", cgroup_disable);
 
-static int __init cgroup_no_v1(char *str)
-{
-	struct cgroup_subsys *ss;
-	char *token;
-	int i;
-
-	while ((token = strsep(&str, ",")) != NULL) {
-		if (!*token)
-			continue;
-
-		if (!strcmp(token, "all")) {
-			cgroup_no_v1_mask = U16_MAX;
-			break;
-		}
-
-		for_each_subsys(ss, i) {
-			if (strcmp(token, ss->name) &&
-			    strcmp(token, ss->legacy_name))
-				continue;
-
-			cgroup_no_v1_mask |= 1 << i;
-		}
-	}
-	return 1;
-}
-__setup("cgroup_no_v1=", cgroup_no_v1);
-
 /**
  * css_tryget_online_from_dir - get corresponding css from a cgroup dentry
  * @dentry: directory dentry of interest
@@ -6266,13 +5850,12 @@ struct cgroup_subsys_state *css_tryget_online_from_dir(struct dentry *dentry,
 						       struct cgroup_subsys *ss)
 {
 	struct kernfs_node *kn = kernfs_node_from_dentry(dentry);
-	struct file_system_type *s_type = dentry->d_sb->s_type;
 	struct cgroup_subsys_state *css = NULL;
 	struct cgroup *cgrp;
 
 	/* is @dentry a cgroup dir? */
-	if ((s_type != &cgroup_fs_type && s_type != &cgroup2_fs_type) ||
-	    !kn || kernfs_type(kn) != KERNFS_DIR)
+	if (dentry->d_sb->s_type != &cgroup_fs_type || !kn ||
+	    kernfs_type(kn) != KERNFS_DIR)
 		return ERR_PTR(-EBADF);
 
 	rcu_read_lock();
@@ -6304,306 +5887,8 @@ struct cgroup_subsys_state *css_tryget_online_from_dir(struct dentry *dentry,
 struct cgroup_subsys_state *css_from_id(int id, struct cgroup_subsys *ss)
 {
 	WARN_ON_ONCE(!rcu_read_lock_held());
-	return idr_find(&ss->css_idr, id);
-}
-
-/**
- * cgroup_get_from_path - lookup and get a cgroup from its default hierarchy path
- * @path: path on the default hierarchy
- *
- * Find the cgroup at @path on the default hierarchy, increment its
- * reference count and return it.  Returns pointer to the found cgroup on
- * success, ERR_PTR(-ENOENT) if @path doens't exist and ERR_PTR(-ENOTDIR)
- * if @path points to a non-directory.
- */
-struct cgroup *cgroup_get_from_path(const char *path)
-{
-	struct kernfs_node *kn;
-	struct cgroup *cgrp;
-
-	mutex_lock(&cgroup_mutex);
-
-	kn = kernfs_walk_and_get(cgrp_dfl_root.cgrp.kn, path);
-	if (kn) {
-		if (kernfs_type(kn) == KERNFS_DIR) {
-			cgrp = kn->priv;
-			cgroup_get(cgrp);
-		} else {
-			cgrp = ERR_PTR(-ENOTDIR);
-		}
-		kernfs_put(kn);
-	} else {
-		cgrp = ERR_PTR(-ENOENT);
-	}
-
-	mutex_unlock(&cgroup_mutex);
-	return cgrp;
-}
-EXPORT_SYMBOL_GPL(cgroup_get_from_path);
-
-/**
- * cgroup_get_from_fd - get a cgroup pointer from a fd
- * @fd: fd obtained by open(cgroup2_dir)
- *
- * Find the cgroup from a fd which should be obtained
- * by opening a cgroup directory.  Returns a pointer to the
- * cgroup on success. ERR_PTR is returned if the cgroup
- * cannot be found.
- */
-struct cgroup *cgroup_get_from_fd(int fd)
-{
-	struct cgroup_subsys_state *css;
-	struct cgroup *cgrp;
-	struct file *f;
-
-	f = fget_raw(fd);
-	if (!f)
-		return ERR_PTR(-EBADF);
-
-	css = css_tryget_online_from_dir(f->f_path.dentry, NULL);
-	fput(f);
-	if (IS_ERR(css))
-		return ERR_CAST(css);
-
-	cgrp = css->cgroup;
-	if (!cgroup_on_dfl(cgrp)) {
-		cgroup_put(cgrp);
-		return ERR_PTR(-EBADF);
-	}
-
-	return cgrp;
-}
-EXPORT_SYMBOL_GPL(cgroup_get_from_fd);
-
-/*
- * sock->sk_cgrp_data handling.  For more info, see sock_cgroup_data
- * definition in cgroup-defs.h.
- */
-#ifdef CONFIG_SOCK_CGROUP_DATA
-
-#if defined(CONFIG_CGROUP_NET_PRIO) || defined(CONFIG_CGROUP_NET_CLASSID)
-
-DEFINE_SPINLOCK(cgroup_sk_update_lock);
-static bool cgroup_sk_alloc_disabled __read_mostly;
-
-void cgroup_sk_alloc_disable(void)
-{
-	if (cgroup_sk_alloc_disabled)
-		return;
-	pr_info("cgroup: disabling cgroup2 socket matching due to net_prio or net_cls activation\n");
-	cgroup_sk_alloc_disabled = true;
-}
-
-#else
-
-#define cgroup_sk_alloc_disabled	false
-
-#endif
-
-void cgroup_sk_alloc(struct sock_cgroup_data *skcd)
-{
-	if (cgroup_sk_alloc_disabled) {
-		skcd->no_refcnt = 1;
-		return;
-	}
-
-	/* Don't associate the sock with unrelated interrupted task's cgroup. */
-	if (in_interrupt())
-		return;
-
-	rcu_read_lock();
-
-	while (true) {
-		struct css_set *cset;
-
-		cset = task_css_set(current);
-		if (likely(cgroup_tryget(cset->dfl_cgrp))) {
-			skcd->val = (unsigned long)cset->dfl_cgrp;
-			break;
-		}
-		cpu_relax();
-	}
-
-	rcu_read_unlock();
-}
-
-void cgroup_sk_clone(struct sock_cgroup_data *skcd)
-{
-	/* Socket clone path */
-	if (skcd->val) {
-		if (skcd->no_refcnt)
-			return;
-		/*
-		 * We might be cloning a socket which is left in an empty
-		 * cgroup and the cgroup might have already been rmdir'd.
-		 * Don't use cgroup_get_live().
-		 */
-		cgroup_get(sock_cgroup_ptr(skcd));
-	}
-}
-
-void cgroup_sk_free(struct sock_cgroup_data *skcd)
-{
-	if (skcd->no_refcnt)
-		return;
-
-	cgroup_put(sock_cgroup_ptr(skcd));
-}
-
-#endif	/* CONFIG_SOCK_CGROUP_DATA */
-
-/* cgroup namespaces */
-
-static struct cgroup_namespace *alloc_cgroup_ns(void)
-{
-	struct cgroup_namespace *new_ns;
-	int ret;
-
-	new_ns = kzalloc(sizeof(struct cgroup_namespace), GFP_KERNEL);
-	if (!new_ns)
-		return ERR_PTR(-ENOMEM);
-	ret = ns_alloc_inum(&new_ns->ns);
-	if (ret) {
-		kfree(new_ns);
-		return ERR_PTR(ret);
-	}
-	atomic_set(&new_ns->count, 1);
-	new_ns->ns.ops = &cgroupns_operations;
-	return new_ns;
-}
-
-void free_cgroup_ns(struct cgroup_namespace *ns)
-{
-	put_css_set(ns->root_cset);
-	put_user_ns(ns->user_ns);
-	ns_free_inum(&ns->ns);
-	kfree(ns);
-}
-EXPORT_SYMBOL(free_cgroup_ns);
-
-struct cgroup_namespace *copy_cgroup_ns(unsigned long flags,
-					struct user_namespace *user_ns,
-					struct cgroup_namespace *old_ns)
-{
-	struct cgroup_namespace *new_ns;
-	struct css_set *cset;
-
-	BUG_ON(!old_ns);
-
-	if (!(flags & CLONE_NEWCGROUP)) {
-		get_cgroup_ns(old_ns);
-		return old_ns;
-	}
-
-	/* Allow only sysadmin to create cgroup namespace. */
-	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
-		return ERR_PTR(-EPERM);
-
-	/* It is not safe to take cgroup_mutex here */
-	spin_lock_irq(&css_set_lock);
-	cset = task_css_set(current);
-	get_css_set(cset);
-	spin_unlock_irq(&css_set_lock);
-
-	new_ns = alloc_cgroup_ns();
-	if (IS_ERR(new_ns)) {
-		put_css_set(cset);
-		return new_ns;
-	}
-
-	new_ns->user_ns = get_user_ns(user_ns);
-	new_ns->root_cset = cset;
-
-	return new_ns;
-}
-
-static inline struct cgroup_namespace *to_cg_ns(struct ns_common *ns)
-{
-	return container_of(ns, struct cgroup_namespace, ns);
-}
-
-static int cgroupns_install(struct nsproxy *nsproxy, struct ns_common *ns)
-{
-	struct cgroup_namespace *cgroup_ns = to_cg_ns(ns);
-
-	if (!ns_capable(current_user_ns(), CAP_SYS_ADMIN) ||
-	    !ns_capable(cgroup_ns->user_ns, CAP_SYS_ADMIN))
-		return -EPERM;
-
-	/* Don't need to do anything if we are attaching to our own cgroupns. */
-	if (cgroup_ns == nsproxy->cgroup_ns)
-		return 0;
-
-	get_cgroup_ns(cgroup_ns);
-	put_cgroup_ns(nsproxy->cgroup_ns);
-	nsproxy->cgroup_ns = cgroup_ns;
-
-	return 0;
-}
-
-static struct ns_common *cgroupns_get(struct task_struct *task)
-{
-	struct cgroup_namespace *ns = NULL;
-	struct nsproxy *nsproxy;
-
-	task_lock(task);
-	nsproxy = task->nsproxy;
-	if (nsproxy) {
-		ns = nsproxy->cgroup_ns;
-		get_cgroup_ns(ns);
-	}
-	task_unlock(task);
-
-	return ns ? &ns->ns : NULL;
-}
-
-static void cgroupns_put(struct ns_common *ns)
-{
-	put_cgroup_ns(to_cg_ns(ns));
-}
-
-static struct user_namespace *cgroupns_owner(struct ns_common *ns)
-{
-	return to_cg_ns(ns)->user_ns;
-}
-
-const struct proc_ns_operations cgroupns_operations = {
-	.name		= "cgroup",
-	.type		= CLONE_NEWCGROUP,
-	.get		= cgroupns_get,
-	.put		= cgroupns_put,
-	.install	= cgroupns_install,
-	.owner		= cgroupns_owner,
-};
-
-static __init int cgroup_namespaces_init(void)
-{
-	return 0;
-}
-subsys_initcall(cgroup_namespaces_init);
-
-#ifdef CONFIG_CGROUP_BPF
-int cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
-		      enum bpf_attach_type type, u32 flags)
-{
-	int ret;
-
-	mutex_lock(&cgroup_mutex);
-	ret = __cgroup_bpf_attach(cgrp, prog, type, flags);
-	mutex_unlock(&cgroup_mutex);
-	return ret;
-}
-int cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
-		      enum bpf_attach_type type, u32 flags)
-{
-	int ret;
-
-	mutex_lock(&cgroup_mutex);
-	ret = __cgroup_bpf_detach(cgrp, prog, type, flags);
-	mutex_unlock(&cgroup_mutex);
-	return ret;
+	return id > 0 ? idr_find(&ss->css_idr, id) : NULL;
 }
-#endif /* CONFIG_CGROUP_BPF */
 
 #ifdef CONFIG_CGROUP_DEBUG
 static struct cgroup_subsys_state *
diff --git a/kernel/cgroup_freezer.c b/kernel/cgroup_freezer.c
index 1b72d56edce5..2d3df82c54f2 100644
--- a/kernel/cgroup_freezer.c
+++ b/kernel/cgroup_freezer.c
@@ -200,7 +200,7 @@ static void freezer_attach(struct cgroup_taskset *tset)
  * to do anything as freezer_attach() will put @task into the appropriate
  * state.
  */
-static void freezer_fork(struct task_struct *task)
+static void freezer_fork(struct task_struct *task, void *private)
 {
 	struct freezer *freezer;
 
diff --git a/kernel/cgroup_pids.c b/kernel/cgroup_pids.c
index d1806c89c237..ea8cb03dbf72 100644
--- a/kernel/cgroup_pids.c
+++ b/kernel/cgroup_pids.c
@@ -210,7 +210,7 @@ static void pids_cancel_attach(struct cgroup_taskset *tset)
  * task_css_check(true) in pids_can_fork() and pids_cancel_fork() relies
  * on threadgroup_change_begin() held by the copy_process().
  */
-static int pids_can_fork(struct task_struct *task)
+static int pids_can_fork(struct task_struct *task, void **priv_p)
 {
 	struct cgroup_subsys_state *css;
 	struct pids_cgroup *pids;
@@ -220,7 +220,7 @@ static int pids_can_fork(struct task_struct *task)
 	return pids_try_charge(pids, 1);
 }
 
-static void pids_cancel_fork(struct task_struct *task)
+static void pids_cancel_fork(struct task_struct *task, void *priv)
 {
 	struct cgroup_subsys_state *css;
 	struct pids_cgroup *pids;
diff --git a/kernel/cpuset.c b/kernel/cpuset.c
index 9ba129440baa..2ce1a5297b92 100644
--- a/kernel/cpuset.c
+++ b/kernel/cpuset.c
@@ -2767,7 +2767,7 @@ void __cpuset_memory_pressure_bump(void)
 int proc_cpuset_show(struct seq_file *m, struct pid_namespace *ns,
 		     struct pid *pid, struct task_struct *tsk)
 {
-	char *buf;
+	char *buf, *p;
 	struct cgroup_subsys_state *css;
 	int retval;
 
@@ -2777,19 +2777,19 @@ int proc_cpuset_show(struct seq_file *m, struct pid_namespace *ns,
 		goto out;
 
 	retval = -ENAMETOOLONG;
-	css = task_get_css(tsk, cpuset_cgrp_id);
-	retval = cgroup_path_ns(css->cgroup, buf, PATH_MAX,
-				current->nsproxy->cgroup_ns);
-	css_put(css);
-	if (retval >= PATH_MAX)
+	rcu_read_lock();
+	css = task_css(tsk, cpuset_cgrp_id);
+	p = cgroup_path(css->cgroup, buf, PATH_MAX);
+	rcu_read_unlock();
+	if (!p)
 		goto out_free;
-	seq_puts(m, buf);
+	seq_puts(m, p);
 	seq_putc(m, '\n');
 	retval = 0;
 out_free:
 	kfree(buf);
 out:
-	return 0;
+	return retval;
 }
 #endif /* CONFIG_PROC_PID_CPUSET */
 
diff --git a/kernel/events/callchain.c b/kernel/events/callchain.c
index 53c9e9839a2b..75f835d353db 100644
--- a/kernel/events/callchain.c
+++ b/kernel/events/callchain.c
@@ -18,26 +18,18 @@ struct callchain_cpus_entries {
 	struct perf_callchain_entry	*cpu_entries[0];
 };
 
-int sysctl_perf_event_max_stack __read_mostly = PERF_MAX_STACK_DEPTH;
-
-static inline size_t perf_callchain_entry__sizeof(void)
-{
-	return (sizeof(struct perf_callchain_entry) +
-		sizeof(__u64) * sysctl_perf_event_max_stack);
-}
-
 static DEFINE_PER_CPU(int, callchain_recursion[PERF_NR_CONTEXTS]);
 static atomic_t nr_callchain_events;
 static DEFINE_MUTEX(callchain_mutex);
 static struct callchain_cpus_entries *callchain_cpus_entries;
 
 
-__weak void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
+__weak void perf_callchain_kernel(struct perf_callchain_entry *entry,
 				  struct pt_regs *regs)
 {
 }
 
-__weak void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
+__weak void perf_callchain_user(struct perf_callchain_entry *entry,
 				struct pt_regs *regs)
 {
 }
@@ -81,7 +73,7 @@ static int alloc_callchain_buffers(void)
 	if (!entries)
 		return -ENOMEM;
 
-	size = perf_callchain_entry__sizeof() * PERF_NR_CONTEXTS;
+	size = sizeof(struct perf_callchain_entry) * PERF_NR_CONTEXTS;
 
 	for_each_possible_cpu(cpu) {
 		entries->cpu_entries[cpu] = kmalloc_node(size, GFP_KERNEL,
@@ -102,7 +94,7 @@ fail:
 	return -ENOMEM;
 }
 
-int get_callchain_buffers(int event_max_stack)
+int get_callchain_buffers(void)
 {
 	int err = 0;
 	int count;
@@ -149,8 +141,7 @@ static struct perf_callchain_entry *get_callchain_entry(int *rctx)
 
 	cpu = smp_processor_id();
 
-	return (((void *)entries->cpu_entries[cpu]) +
-		(*rctx * perf_callchain_entry__sizeof()));
+	return &entries->cpu_entries[cpu][*rctx];
 }
 
 static void
@@ -162,26 +153,15 @@ put_callchain_entry(int rctx)
 struct perf_callchain_entry *
 perf_callchain(struct perf_event *event, struct pt_regs *regs)
 {
-	bool kernel = !event->attr.exclude_callchain_kernel;
-	bool user   = !event->attr.exclude_callchain_user;
-	/* Disallow cross-task user callchains. */
-	bool crosstask = event->ctx->task && event->ctx->task != current;
-	const u32 max_stack = event->attr.sample_max_stack;
+	int rctx;
+	struct perf_callchain_entry *entry;
+
+	int kernel = !event->attr.exclude_callchain_kernel;
+	int user   = !event->attr.exclude_callchain_user;
 
 	if (!kernel && !user)
 		return NULL;
 
-	return get_perf_callchain(regs, 0, kernel, user, max_stack, crosstask, true);
-}
-
-struct perf_callchain_entry *
-get_perf_callchain(struct pt_regs *regs, u32 init_nr, bool kernel, bool user,
-		   u32 max_stack, bool crosstask, bool add_mark)
-{
-	struct perf_callchain_entry *entry;
-	struct perf_callchain_entry_ctx ctx;
-	int rctx;
-
 	entry = get_callchain_entry(&rctx);
 	if (rctx == -1)
 		return NULL;
@@ -189,15 +169,11 @@ get_perf_callchain(struct pt_regs *regs, u32 init_nr, bool kernel, bool user,
 	if (!entry)
 		goto exit_put;
 
-	ctx.entry     = entry;
-	ctx.max_stack = max_stack;
-
-	entry->nr = init_nr;
+	entry->nr = 0;
 
 	if (kernel && !user_mode(regs)) {
-		if (add_mark)
-			perf_callchain_store(&ctx, PERF_CONTEXT_KERNEL);
-		perf_callchain_kernel(&ctx, regs);
+		perf_callchain_store(entry, PERF_CONTEXT_KERNEL);
+		perf_callchain_kernel(entry, regs);
 	}
 
 	if (user) {
@@ -209,12 +185,14 @@ get_perf_callchain(struct pt_regs *regs, u32 init_nr, bool kernel, bool user,
 		}
 
 		if (regs) {
-			if (crosstask)
+			/*
+			 * Disallow cross-task user callchains.
+			 */
+			if (event->ctx->task && event->ctx->task != current)
 				goto exit_put;
 
-			if (add_mark)
-				perf_callchain_store(&ctx, PERF_CONTEXT_USER);
-			perf_callchain_user(&ctx, regs);
+			perf_callchain_store(entry, PERF_CONTEXT_USER);
+			perf_callchain_user(entry, regs);
 		}
 	}
 
@@ -223,25 +201,3 @@ exit_put:
 
 	return entry;
 }
-
-int perf_event_max_stack_handler(struct ctl_table *table, int write,
-				 void __user *buffer, size_t *lenp, loff_t *ppos)
-{
-	int new_value = sysctl_perf_event_max_stack, ret;
-	struct ctl_table new_table = *table;
-
-	new_table.data = &new_value;
-	ret = proc_dointvec_minmax(&new_table, write, buffer, lenp, ppos);
-	if (ret || !write)
-		return ret;
-
-	mutex_lock(&callchain_mutex);
-	if (atomic_read(&nr_callchain_events))
-		ret = -EBUSY;
-	else
-		sysctl_perf_event_max_stack = new_value;
-
-	mutex_unlock(&callchain_mutex);
-
-	return ret;
-}
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 1f8403632d9d..769d9f408d32 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6700,7 +6700,10 @@ static int __perf_event_overflow(struct perf_event *event,
 		irq_work_queue(&event->pending);
 	}
 
-	READ_ONCE(event->overflow_handler)(event, data, regs);
+	if (event->overflow_handler)
+		event->overflow_handler(event, data, regs);
+	else
+		perf_event_output(event, data, regs);
 
 	if (*perf_event_fasync(event) && event->pending_kill) {
 		event->pending_wakeup = 1;
@@ -6933,7 +6936,7 @@ int perf_swevent_get_recursion_context(void)
 }
 EXPORT_SYMBOL_GPL(perf_swevent_get_recursion_context);
 
-void perf_swevent_put_recursion_context(int rctx)
+inline void perf_swevent_put_recursion_context(int rctx)
 {
 	struct swevent_htable *swhash = this_cpu_ptr(&swevent_htable);
 
@@ -7198,24 +7201,7 @@ static int perf_tp_event_match(struct perf_event *event,
 	return 1;
 }
 
-void perf_trace_run_bpf_submit(void *raw_data, int size, int rctx,
-			       struct trace_event_call *call, u64 count,
-			       struct pt_regs *regs, struct hlist_head *head,
-			       struct task_struct *task)
-{
-	if (bpf_prog_array_valid(call)) {
-		*(struct pt_regs **)raw_data = regs;
-		if (!trace_call_bpf(call, raw_data) || hlist_empty(head)) {
-			perf_swevent_put_recursion_context(rctx);
-			return;
-		}
-	}
-	perf_tp_event(call->event.type, count, raw_data, size, regs, head,
-		      rctx, task);
-}
-EXPORT_SYMBOL_GPL(perf_trace_run_bpf_submit);
-
-void perf_tp_event(u16 event_type, u64 count, void *record, int entry_size,
+void perf_tp_event(u64 addr, u64 count, void *record, int entry_size,
 		   struct pt_regs *regs, struct hlist_head *head, int rctx,
 		   struct task_struct *task)
 {
@@ -7227,11 +7213,9 @@ void perf_tp_event(u16 event_type, u64 count, void *record, int entry_size,
 		.data = record,
 	};
 
-	perf_sample_data_init(&data, 0, 0);
+	perf_sample_data_init(&data, addr, 0);
 	data.raw = &raw;
 
-	perf_trace_buf_update(record, event_type);
-
 	hlist_for_each_entry_rcu(event, head, hlist_entry) {
 		if (perf_tp_event_match(event, &data, regs))
 			perf_swevent_event(event, count, &data, regs);
@@ -7336,126 +7320,48 @@ static void perf_event_free_filter(struct perf_event *event)
 	ftrace_profile_free_filter(event);
 }
 
-#ifdef CONFIG_BPF_SYSCALL
-static void bpf_overflow_handler(struct perf_event *event,
-				 struct perf_sample_data *data,
-				 struct pt_regs *regs)
-{
-	struct bpf_perf_event_data_kern ctx = {
-		.data = data,
-		.regs = regs,
-	};
-	int ret = 0;
-
-	preempt_disable();
-	if (unlikely(__this_cpu_inc_return(bpf_prog_active) != 1))
-		goto out;
-	rcu_read_lock();
-	ret = BPF_PROG_RUN(event->prog, (void *)&ctx);
-	rcu_read_unlock();
-out:
-	__this_cpu_dec(bpf_prog_active);
-	preempt_enable();
-	if (!ret)
-		return;
-
-	event->orig_overflow_handler(event, data, regs);
-}
-
-static int perf_event_set_bpf_handler(struct perf_event *event, u32 prog_fd)
-{
-	struct bpf_prog *prog;
-
-	if (event->overflow_handler_context)
-		/* hw breakpoint or kernel counter */
-		return -EINVAL;
-
-	if (event->prog)
-		return -EEXIST;
-
-	prog = bpf_prog_get_type(prog_fd, BPF_PROG_TYPE_PERF_EVENT);
-	if (IS_ERR(prog))
-		return PTR_ERR(prog);
-
-	event->prog = prog;
-	event->orig_overflow_handler = READ_ONCE(event->overflow_handler);
-	WRITE_ONCE(event->overflow_handler, bpf_overflow_handler);
-	return 0;
-}
-
-static void perf_event_free_bpf_handler(struct perf_event *event)
-{
-	struct bpf_prog *prog = event->prog;
-
-	if (!prog)
-		return;
-
-	WRITE_ONCE(event->overflow_handler, event->orig_overflow_handler);
-	event->prog = NULL;
-	bpf_prog_put(prog);
-}
-#else
-static int perf_event_set_bpf_handler(struct perf_event *event, u32 prog_fd)
-{
-	return -EOPNOTSUPP;
-}
-static void perf_event_free_bpf_handler(struct perf_event *event)
-{
-}
-#endif
-
 static int perf_event_set_bpf_prog(struct perf_event *event, u32 prog_fd)
 {
-	bool is_kprobe, is_tracepoint;
 	struct bpf_prog *prog;
-	int ret;
-
-	if (event->attr.type == PERF_TYPE_HARDWARE ||
-	    event->attr.type == PERF_TYPE_SOFTWARE)
-		return perf_event_set_bpf_handler(event, prog_fd);
 
 	if (event->attr.type != PERF_TYPE_TRACEPOINT)
 		return -EINVAL;
 
-	is_kprobe = event->tp_event->flags & TRACE_EVENT_FL_UKPROBE;
-	is_tracepoint = event->tp_event->flags & TRACE_EVENT_FL_TRACEPOINT;
-	if (!is_kprobe && !is_tracepoint)
-		/* bpf programs can only be attached to u/kprobe or tracepoint */
+	if (event->tp_event->prog)
+		return -EEXIST;
+
+	if (!(event->tp_event->flags & TRACE_EVENT_FL_UKPROBE))
+		/* bpf programs can only be attached to u/kprobes */
 		return -EINVAL;
 
 	prog = bpf_prog_get(prog_fd);
 	if (IS_ERR(prog))
 		return PTR_ERR(prog);
 
-	if ((is_kprobe && prog->type != BPF_PROG_TYPE_KPROBE) ||
-	    (is_tracepoint && prog->type != BPF_PROG_TYPE_TRACEPOINT)) {
+	if (prog->type != BPF_PROG_TYPE_KPROBE) {
 		/* valid fd, but invalid bpf program type */
 		bpf_prog_put(prog);
 		return -EINVAL;
 	}
 
-	if (is_tracepoint) {
-		int off = trace_event_get_offsets(event->tp_event);
+	event->tp_event->prog = prog;
+	event->tp_event->bpf_prog_owner = event;
 
-		if (prog->aux->max_ctx_offset > off) {
-			bpf_prog_put(prog);
-			return -EACCES;
-		}
-	}
-
-	ret = perf_event_attach_bpf_prog(event, prog);
-	if (ret)
-		bpf_prog_put(prog);
-	return ret;
+	return 0;
 }
 
 static void perf_event_free_bpf_prog(struct perf_event *event)
 {
-	if (event->attr.type != PERF_TYPE_TRACEPOINT) {
-		perf_event_free_bpf_handler(event);
+	struct bpf_prog *prog;
+
+	if (!event->tp_event)
 		return;
+
+	prog = event->tp_event->prog;
+	if (prog && event->tp_event->bpf_prog_owner == event) {
+		event->tp_event->prog = NULL;
+		bpf_prog_put(prog);
 	}
-	perf_event_detach_bpf_prog(event);
 }
 
 #else
@@ -8286,28 +8192,10 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 	if (!overflow_handler && parent_event) {
 		overflow_handler = parent_event->overflow_handler;
 		context = parent_event->overflow_handler_context;
-#if defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_EVENT_TRACING)
-		if (overflow_handler == bpf_overflow_handler) {
-			struct bpf_prog *prog = bpf_prog_inc(parent_event->prog);
-
-			if (IS_ERR(prog)) {
-				err = PTR_ERR(prog);
-				goto err_ns;
-			}
-			event->prog = prog;
-			event->orig_overflow_handler =
-				parent_event->orig_overflow_handler;
-		}
-#endif
 	}
 
-	if (overflow_handler) {
-		event->overflow_handler	= overflow_handler;
-		event->overflow_handler_context = context;
-	} else {
-		event->overflow_handler = perf_event_output;
-		event->overflow_handler_context = NULL;
-	}
+	event->overflow_handler	= overflow_handler;
+	event->overflow_handler_context = context;
 
 	perf_event__state_init(event);
 
@@ -8351,7 +8239,7 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 	if (!event->parent) {
 		if (event->attr.sample_type & PERF_SAMPLE_CALLCHAIN) {
-			err = get_callchain_buffers(attr->sample_max_stack);
+			err = get_callchain_buffers();
 			if (err)
 				goto err_per_task;
 		}
@@ -8700,9 +8588,6 @@ SYSCALL_DEFINE5(perf_event_open,
 			return -EINVAL;
 	}
 
-	if (!attr.sample_max_stack)
-		attr.sample_max_stack = sysctl_perf_event_max_stack;
-
 	/*
 	 * In cgroup mode, the pid argument is used to pass the fd
 	 * opened to the cgroup directory in cgroupfs. The cpu argument
@@ -9447,20 +9332,21 @@ void perf_event_delayed_put(struct task_struct *task)
 		WARN_ON_ONCE(task->perf_event_ctxp[ctxn]);
 }
 
-struct file *perf_event_get(unsigned int fd)
+struct perf_event *perf_event_get(unsigned int fd)
 {
-	struct file *file;
+	int err;
+	struct fd f;
+	struct perf_event *event;
 
-	file = fget_raw(fd);
-	if (!file)
-		return ERR_PTR(-EBADF);
+	err = perf_fget_light(fd, &f);
+	if (err)
+		return ERR_PTR(err);
 
-	if (file->f_op != &perf_fops) {
-		fput(file);
-		return ERR_PTR(-EBADF);
-	}
+	event = f.file->private_data;
+	atomic_long_inc(&event->refcount);
+	fdput(f);
 
-	return file;
+	return event;
 }
 
 const struct perf_event_attr *perf_event_attrs(struct perf_event *event)
diff --git a/kernel/events/internal.h b/kernel/events/internal.h
index 03db6fc85ae7..7e59e583e1a3 100644
--- a/kernel/events/internal.h
+++ b/kernel/events/internal.h
@@ -181,6 +181,8 @@ DEFINE_OUTPUT_COPY(__output_copy_user, arch_perf_out_copy_user)
 /* Callchain handling */
 extern struct perf_callchain_entry *
 perf_callchain(struct perf_event *event, struct pt_regs *regs);
+extern int get_callchain_buffers(void);
+extern void put_callchain_buffers(void);
 
 static inline int get_recursion_context(int *recursion)
 {
diff --git a/kernel/fork.c b/kernel/fork.c
index 7f910a45dfab..1ccf9356f876 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -1313,6 +1313,7 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 {
 	int retval;
 	struct task_struct *p;
+	void *cgrp_ss_priv[CGROUP_CANFORK_COUNT] = {};
 
 	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
 		return ERR_PTR(-EINVAL);
@@ -1585,7 +1586,7 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	 * between here and cgroup_post_fork() if an organisation operation is in
 	 * progress.
 	 */
-	retval = cgroup_can_fork(p);
+	retval = cgroup_can_fork(p, cgrp_ss_priv);
 	if (retval)
 		goto bad_fork_free_pid;
 
@@ -1685,7 +1686,7 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	write_unlock_irq(&tasklist_lock);
 
 	proc_fork_connector(p);
-	cgroup_post_fork(p);
+	cgroup_post_fork(p, cgrp_ss_priv);
 	threadgroup_change_end(current);
 	perf_event_fork(p);
 
@@ -1697,7 +1698,7 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 bad_fork_cancel_cgroup:
 	spin_unlock(&current->sighand->siglock);
 	write_unlock_irq(&tasklist_lock);
-	cgroup_cancel_fork(p);
+	cgroup_cancel_fork(p, cgrp_ss_priv);
 bad_fork_free_pid:
 	threadgroup_change_end(current);
 	if (pid != &init_struct_pid)
@@ -1963,7 +1964,7 @@ static int check_unshare_flags(unsigned long unshare_flags)
 	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|
 				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|
 				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|
-				CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWCGROUP))
+				CLONE_NEWUSER|CLONE_NEWPID))
 		return -EINVAL;
 	/*
 	 * Not implemented, but pretend it works if there is nothing
diff --git a/kernel/nsproxy.c b/kernel/nsproxy.c
index 782102e59eed..49746c81ad8d 100644
--- a/kernel/nsproxy.c
+++ b/kernel/nsproxy.c
@@ -25,7 +25,6 @@
 #include <linux/proc_ns.h>
 #include <linux/file.h>
 #include <linux/syscalls.h>
-#include <linux/cgroup.h>
 
 static struct kmem_cache *nsproxy_cachep;
 
@@ -40,9 +39,6 @@ struct nsproxy init_nsproxy = {
 #ifdef CONFIG_NET
 	.net_ns			= &init_net,
 #endif
-#ifdef CONFIG_CGROUPS
-	.cgroup_ns		= &init_cgroup_ns,
-#endif
 };
 
 static inline struct nsproxy *create_nsproxy(void)
@@ -96,13 +92,6 @@ static struct nsproxy *create_new_namespaces(unsigned long flags,
 		goto out_pid;
 	}
 
-	new_nsp->cgroup_ns = copy_cgroup_ns(flags, user_ns,
-					    tsk->nsproxy->cgroup_ns);
-	if (IS_ERR(new_nsp->cgroup_ns)) {
-		err = PTR_ERR(new_nsp->cgroup_ns);
-		goto out_cgroup;
-	}
-
 	new_nsp->net_ns = copy_net_ns(flags, user_ns, tsk->nsproxy->net_ns);
 	if (IS_ERR(new_nsp->net_ns)) {
 		err = PTR_ERR(new_nsp->net_ns);
@@ -112,8 +101,6 @@ static struct nsproxy *create_new_namespaces(unsigned long flags,
 	return new_nsp;
 
 out_net:
-	put_cgroup_ns(new_nsp->cgroup_ns);
-out_cgroup:
 	if (new_nsp->pid_ns_for_children)
 		put_pid_ns(new_nsp->pid_ns_for_children);
 out_pid:
@@ -141,8 +128,7 @@ int copy_namespaces(unsigned long flags, struct task_struct *tsk)
 	struct nsproxy *new_ns;
 
 	if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
-			      CLONE_NEWPID | CLONE_NEWNET |
-			      CLONE_NEWCGROUP)))) {
+			      CLONE_NEWPID | CLONE_NEWNET)))) {
 		get_nsproxy(old_ns);
 		return 0;
 	}
@@ -179,7 +165,6 @@ void free_nsproxy(struct nsproxy *ns)
 		put_ipc_ns(ns->ipc_ns);
 	if (ns->pid_ns_for_children)
 		put_pid_ns(ns->pid_ns_for_children);
-	put_cgroup_ns(ns->cgroup_ns);
 	put_net(ns->net_ns);
 	kmem_cache_free(nsproxy_cachep, ns);
 }
@@ -195,7 +180,7 @@ int unshare_nsproxy_namespaces(unsigned long unshare_flags,
 	int err = 0;
 
 	if (!(unshare_flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
-			       CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWCGROUP)))
+			       CLONE_NEWNET | CLONE_NEWPID)))
 		return 0;
 
 	user_ns = new_cred ? new_cred->user_ns : current_user_ns();
diff --git a/kernel/pid_namespace.c b/kernel/pid_namespace.c
index a22e3288e2b5..6353372801f2 100644
--- a/kernel/pid_namespace.c
+++ b/kernel/pid_namespace.c
@@ -388,18 +388,12 @@ static int pidns_install(struct nsproxy *nsproxy, struct ns_common *ns)
 	return 0;
 }
 
-static struct user_namespace *pidns_owner(struct ns_common *ns)
-{
-	return to_pid_ns(ns)->user_ns;
-}
-
 const struct proc_ns_operations pidns_operations = {
 	.name		= "pid",
 	.type		= CLONE_NEWPID,
 	.get		= pidns_get,
 	.put		= pidns_put,
 	.install	= pidns_install,
-	.owner		= pidns_owner,
 };
 
 static __init int pid_namespaces_init(void)
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index da5ed19e16e4..15110a8bdcbb 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -8674,7 +8674,7 @@ static void cpu_cgroup_css_free(struct cgroup_subsys_state *css)
  * This is called before wake_up_new_task(), therefore we really only
  * have to set its group bits, all the other stuff does not apply.
  */
-static void cpu_cgroup_fork(struct task_struct *task)
+static void cpu_cgroup_fork(struct task_struct *task, void *private)
 {
 	unsigned long flags;
 	struct rq *rq;
diff --git a/kernel/sched/debug.c b/kernel/sched/debug.c
index 439a55f52b7c..acaa061beec0 100644
--- a/kernel/sched/debug.c
+++ b/kernel/sched/debug.c
@@ -235,8 +235,7 @@ static char *task_group_path(struct task_group *tg)
 	if (autogroup_path(tg, group_path, PATH_MAX))
 		return group_path;
 
-	cgroup_path(tg->css.cgroup, group_path, PATH_MAX);
-	return group_path;
+	return cgroup_path(tg->css.cgroup, group_path, PATH_MAX);
 }
 #endif
 
diff --git a/kernel/sysctl.c b/kernel/sysctl.c
index 671220f309ee..a2f7f0e54e1e 100644
--- a/kernel/sysctl.c
+++ b/kernel/sysctl.c
@@ -138,9 +138,6 @@ static int one_hundred = 100;
 #ifdef CONFIG_PRINTK
 static int ten_thousand = 10000;
 #endif
-#ifdef CONFIG_PERF_EVENTS
-static int six_hundred_forty_kb = 640 * 1024;
-#endif
 
 /* this is needed for the proc_doulongvec_minmax of vm_dirty_bytes */
 static unsigned long dirty_bytes_min = 2 * PAGE_SIZE;
@@ -1240,15 +1237,6 @@ static struct ctl_table kern_table[] = {
 		.extra1		= &zero,
 		.extra2		= &one_hundred,
 	},
-	{
-		.procname	= "perf_event_max_stack",
-		.data		= NULL, /* filled in by handler */
-		.maxlen		= sizeof(sysctl_perf_event_max_stack),
-		.mode		= 0644,
-		.proc_handler	= perf_event_max_stack_handler,
-		.extra1		= &zero,
-		.extra2		= &six_hundred_forty_kb,
-	},
 #endif
 #ifdef CONFIG_KMEMCHECK
 	{
diff --git a/kernel/trace/bpf_trace.c b/kernel/trace/bpf_trace.c
index 045bde1a64ac..a71bdad638d5 100644
--- a/kernel/trace/bpf_trace.c
+++ b/kernel/trace/bpf_trace.c
@@ -1,5 +1,4 @@
 /* Copyright (c) 2011-2015 PLUMgrid, http://plumgrid.com
- * Copyright (c) 2016 Facebook
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -9,15 +8,16 @@
 #include <linux/types.h>
 #include <linux/slab.h>
 #include <linux/bpf.h>
-#include <linux/bpf_perf_event.h>
 #include <linux/filter.h>
 #include <linux/uaccess.h>
 #include <linux/ctype.h>
 #include "trace.h"
 
+static DEFINE_PER_CPU(int, bpf_prog_active);
+
 /**
  * trace_call_bpf - invoke BPF program
- * @call: tracepoint event
+ * @prog: BPF program
  * @ctx: opaque context pointer
  *
  * kprobe handlers execute BPF programs via this helper.
@@ -29,7 +29,7 @@
  * 1 - store kprobe event into ring buffer
  * Other values are reserved and currently alias to 1
  */
-unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx)
+unsigned int trace_call_bpf(struct bpf_prog *prog, void *ctx)
 {
 	unsigned int ret;
 
@@ -49,22 +49,9 @@ unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx)
 		goto out;
 	}
 
-	/*
-	 * Instead of moving rcu_read_lock/rcu_dereference/rcu_read_unlock
-	 * to all call sites, we did a bpf_prog_array_valid() there to check
-	 * whether call->prog_array is empty or not, which is
-	 * a heurisitc to speed up execution.
-	 *
-	 * If bpf_prog_array_valid() fetched prog_array was
-	 * non-NULL, we go into trace_call_bpf() and do the actual
-	 * proper rcu_dereference() under RCU lock.
-	 * If it turns out that prog_array is NULL then, we bail out.
-	 * For the opposite, if the bpf_prog_array_valid() fetched pointer
-	 * was NULL, you'll skip the prog_array with the risk of missing
-	 * out of events when it was updated in between this and the
-	 * rcu_dereference() which is accepted risk.
-	 */
-	ret = BPF_PROG_RUN_ARRAY_CHECK(call->prog_array, ctx, BPF_PROG_RUN);
+	rcu_read_lock();
+	ret = BPF_PROG_RUN(prog, ctx);
+	rcu_read_unlock();
 
  out:
 	__this_cpu_dec(bpf_prog_active);
@@ -74,73 +61,31 @@ unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx)
 }
 EXPORT_SYMBOL_GPL(trace_call_bpf);
 
-BPF_CALL_3(bpf_probe_read, void *, dst, u32, size, const void *, unsafe_ptr)
+static u64 bpf_probe_read(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
-	int ret;
+	void *dst = (void *) (long) r1;
+	int size = (int) r2;
+	void *unsafe_ptr = (void *) (long) r3;
 
-	ret = probe_kernel_read(dst, unsafe_ptr, size);
-	if (unlikely(ret < 0))
-		memset(dst, 0, size);
-
-	return ret;
+	return probe_kernel_read(dst, unsafe_ptr, size);
 }
 
 static const struct bpf_func_proto bpf_probe_read_proto = {
 	.func		= bpf_probe_read,
 	.gpl_only	= true,
 	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_RAW_STACK,
+	.arg1_type	= ARG_PTR_TO_STACK,
 	.arg2_type	= ARG_CONST_STACK_SIZE,
 	.arg3_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_3(bpf_probe_write_user, void *, unsafe_ptr, const void *, src,
-	   u32, size)
-{
-	/*
-	 * Ensure we're in user context which is safe for the helper to
-	 * run. This helper has no business in a kthread.
-	 *
-	 * access_ok() should prevent writing to non-user memory, but in
-	 * some situations (nommu, temporary switch, etc) access_ok() does
-	 * not provide enough validation, hence the check on KERNEL_DS.
-	 */
-
-	if (unlikely(in_interrupt() ||
-		     current->flags & (PF_KTHREAD | PF_EXITING)))
-		return -EPERM;
-	if (unlikely(segment_eq(get_fs(), KERNEL_DS)))
-		return -EPERM;
-	if (!access_ok(VERIFY_WRITE, unsafe_ptr, size))
-		return -EPERM;
-
-	return probe_kernel_write(unsafe_ptr, src, size);
-}
-
-static const struct bpf_func_proto bpf_probe_write_user_proto = {
-	.func		= bpf_probe_write_user,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_ANYTHING,
-	.arg2_type	= ARG_PTR_TO_STACK,
-	.arg3_type	= ARG_CONST_STACK_SIZE,
-};
-
-static const struct bpf_func_proto *bpf_get_probe_write_proto(void)
-{
-	pr_warn_ratelimited("%s[%d] is installing a program with bpf_probe_write_user helper that may corrupt user memory!",
-			    current->comm, task_pid_nr(current));
-
-	return &bpf_probe_write_user_proto;
-}
-
 /*
  * limited trace_printk()
  * only %d %u %x %ld %lu %lx %lld %llu %llx %p %s conversion specifiers allowed
  */
-BPF_CALL_5(bpf_trace_printk, char *, fmt, u32, fmt_size, u64, arg1,
-	   u64, arg2, u64, arg3)
+static u64 bpf_trace_printk(u64 r1, u64 fmt_size, u64 r3, u64 r4, u64 r5)
 {
+	char *fmt = (char *) (long) r1;
 	bool str_seen = false;
 	int mod[3] = {};
 	int fmt_cnt = 0;
@@ -188,16 +133,16 @@ BPF_CALL_5(bpf_trace_printk, char *, fmt, u32, fmt_size, u64, arg1,
 
 				switch (fmt_cnt) {
 				case 1:
-					unsafe_addr = arg1;
-					arg1 = (long) buf;
+					unsafe_addr = r3;
+					r3 = (long) buf;
 					break;
 				case 2:
-					unsafe_addr = arg2;
-					arg2 = (long) buf;
+					unsafe_addr = r4;
+					r4 = (long) buf;
 					break;
 				case 3:
-					unsafe_addr = arg3;
-					arg3 = (long) buf;
+					unsafe_addr = r5;
+					r5 = (long) buf;
 					break;
 				}
 				buf[0] = 0;
@@ -219,9 +164,9 @@ BPF_CALL_5(bpf_trace_printk, char *, fmt, u32, fmt_size, u64, arg1,
 	}
 
 	return __trace_printk(1/* fake ip will not be printed */, fmt,
-			      mod[0] == 2 ? arg1 : mod[0] == 1 ? (long) arg1 : (u32) arg1,
-			      mod[1] == 2 ? arg2 : mod[1] == 1 ? (long) arg2 : (u32) arg2,
-			      mod[2] == 2 ? arg3 : mod[2] == 1 ? (long) arg3 : (u32) arg3);
+			      mod[0] == 2 ? r3 : mod[0] == 1 ? (long) r3 : (u32) r3,
+			      mod[1] == 2 ? r4 : mod[1] == 1 ? (long) r4 : (u32) r4,
+			      mod[2] == 2 ? r5 : mod[2] == 1 ? (long) r5 : (u32) r5);
 }
 
 static const struct bpf_func_proto bpf_trace_printk_proto = {
@@ -243,24 +188,19 @@ const struct bpf_func_proto *bpf_get_trace_printk_proto(void)
 	return &bpf_trace_printk_proto;
 }
 
-BPF_CALL_2(bpf_perf_event_read, struct bpf_map *, map, u64, flags)
+static u64 bpf_perf_event_read(u64 r1, u64 index, u64 r3, u64 r4, u64 r5)
 {
+	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
 	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	struct bpf_event_entry *ee;
 	struct perf_event *event;
 
 	if (unlikely(index >= array->map.max_entries))
 		return -E2BIG;
 
-	ee = READ_ONCE(array->ptrs[index]);
-	if (!ee)
+	event = (struct perf_event *)array->ptrs[index];
+	if (!event)
 		return -ENOENT;
 
-	event = ee->event;
-	if (unlikely(event->attr.type != PERF_TYPE_HARDWARE &&
-		     event->attr.type != PERF_TYPE_RAW))
-		return -EINVAL;
-
 	/* make sure event is local and doesn't have pmu::count */
 	if (event->oncpu != smp_processor_id() ||
 	    event->pmu->count)
@@ -286,26 +226,26 @@ static const struct bpf_func_proto bpf_perf_event_read_proto = {
 	.arg2_type	= ARG_ANYTHING,
 };
 
-static __always_inline u64
-__bpf_perf_event_output(struct pt_regs *regs, struct bpf_map *map,
-			u64 flags, struct perf_raw_record *raw)
+static u64 bpf_perf_event_output(u64 r1, u64 r2, u64 index, u64 r4, u64 size)
 {
+	struct pt_regs *regs = (struct pt_regs *) (long) r1;
+	struct bpf_map *map = (struct bpf_map *) (long) r2;
 	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	u64 index = flags & BPF_F_INDEX_MASK;
+	void *data = (void *) (long) r4;
 	struct perf_sample_data sample_data;
-	struct bpf_event_entry *ee;
 	struct perf_event *event;
+	struct perf_raw_record raw = {
+		.size = size,
+		.data = data,
+	};
 
-	if (index == BPF_F_CURRENT_CPU)
-		index = raw_smp_processor_id();
 	if (unlikely(index >= array->map.max_entries))
 		return -E2BIG;
 
-	ee = READ_ONCE(array->ptrs[index]);
-	if (!ee)
+	event = (struct perf_event *)array->ptrs[index];
+	if (unlikely(!event))
 		return -ENOENT;
 
-	event = ee->event;
 	if (unlikely(event->attr.type != PERF_TYPE_SOFTWARE ||
 		     event->attr.config != PERF_COUNT_SW_BPF_OUTPUT))
 		return -EINVAL;
@@ -314,27 +254,11 @@ __bpf_perf_event_output(struct pt_regs *regs, struct bpf_map *map,
 		return -EOPNOTSUPP;
 
 	perf_sample_data_init(&sample_data, 0, 0);
-	sample_data.raw = raw;
+	sample_data.raw = &raw;
 	perf_event_output(event, &sample_data, regs);
 	return 0;
 }
 
-BPF_CALL_5(bpf_perf_event_output, struct pt_regs *, regs, struct bpf_map *, map,
-	   u64, flags, void *, data, u64, size)
-{
-	struct perf_raw_record raw = {
-		.frag = {
-			.size = size,
-			.data = data,
-		},
-	};
-
-	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
-		return -EINVAL;
-
-	return __bpf_perf_event_output(regs, map, flags, &raw);
-}
-
 static const struct bpf_func_proto bpf_perf_event_output_proto = {
 	.func		= bpf_perf_event_output,
 	.gpl_only	= true,
@@ -346,69 +270,7 @@ static const struct bpf_func_proto bpf_perf_event_output_proto = {
 	.arg5_type	= ARG_CONST_STACK_SIZE,
 };
 
-static DEFINE_PER_CPU(struct pt_regs, bpf_pt_regs);
-
-u64 bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
-		     void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy)
-{
-	struct pt_regs *regs = this_cpu_ptr(&bpf_pt_regs);
-	struct perf_raw_frag frag = {
-		.copy		= ctx_copy,
-		.size		= ctx_size,
-		.data		= ctx,
-	};
-	struct perf_raw_record raw = {
-		.frag = {
-			{
-				.next	= ctx_size ? &frag : NULL,
-			},
-			.size	= meta_size,
-			.data	= meta,
-		},
-	};
-
-	perf_fetch_caller_regs(regs);
-
-	return __bpf_perf_event_output(regs, map, flags, &raw);
-}
-
-BPF_CALL_0(bpf_get_current_task)
-{
-	return (long) current;
-}
-
-static const struct bpf_func_proto bpf_get_current_task_proto = {
-	.func		= bpf_get_current_task,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-};
-
-BPF_CALL_2(bpf_current_task_under_cgroup, struct bpf_map *, map, u32, idx)
-{
-	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	struct cgroup *cgrp;
-
-	if (unlikely(in_interrupt()))
-		return -EINVAL;
-	if (unlikely(idx >= array->map.max_entries))
-		return -E2BIG;
-
-	cgrp = READ_ONCE(array->ptrs[idx]);
-	if (unlikely(!cgrp))
-		return -EAGAIN;
-
-	return task_under_cgroup_hierarchy(current, cgrp);
-}
-
-static const struct bpf_func_proto bpf_current_task_under_cgroup_proto = {
-	.func           = bpf_current_task_under_cgroup,
-	.gpl_only       = false,
-	.ret_type       = RET_INTEGER,
-	.arg1_type      = ARG_CONST_MAP_PTR,
-	.arg2_type      = ARG_ANYTHING,
-};
-
-static const struct bpf_func_proto *tracing_func_proto(enum bpf_func_id func_id)
+static const struct bpf_func_proto *kprobe_prog_func_proto(enum bpf_func_id func_id)
 {
 	switch (func_id) {
 	case BPF_FUNC_map_lookup_elem:
@@ -425,8 +287,6 @@ static const struct bpf_func_proto *tracing_func_proto(enum bpf_func_id func_id)
 		return &bpf_tail_call_proto;
 	case BPF_FUNC_get_current_pid_tgid:
 		return &bpf_get_current_pid_tgid_proto;
-	case BPF_FUNC_get_current_task:
-		return &bpf_get_current_task_proto;
 	case BPF_FUNC_get_current_uid_gid:
 		return &bpf_get_current_uid_gid_proto;
 	case BPF_FUNC_get_current_comm:
@@ -437,39 +297,28 @@ static const struct bpf_func_proto *tracing_func_proto(enum bpf_func_id func_id)
 		return &bpf_get_smp_processor_id_proto;
 	case BPF_FUNC_perf_event_read:
 		return &bpf_perf_event_read_proto;
-	case BPF_FUNC_probe_write_user:
-		return bpf_get_probe_write_proto();
-	case BPF_FUNC_current_task_under_cgroup:
-		return &bpf_current_task_under_cgroup_proto;
-	case BPF_FUNC_get_prandom_u32:
-		return &bpf_get_prandom_u32_proto;
-	default:
-		return NULL;
-	}
-}
-
-static const struct bpf_func_proto *kprobe_prog_func_proto(enum bpf_func_id func_id)
-{
-	switch (func_id) {
 	case BPF_FUNC_perf_event_output:
 		return &bpf_perf_event_output_proto;
-	case BPF_FUNC_get_stackid:
-		return &bpf_get_stackid_proto;
 	default:
-		return tracing_func_proto(func_id);
+		return NULL;
 	}
 }
 
 /* bpf+kprobe programs can access fields of 'struct pt_regs' */
-static bool kprobe_prog_is_valid_access(int off, int size, enum bpf_access_type type,
-					enum bpf_reg_type *reg_type)
+static bool kprobe_prog_is_valid_access(int off, int size, enum bpf_access_type type)
 {
+	/* check bounds */
 	if (off < 0 || off >= sizeof(struct pt_regs))
 		return false;
+
+	/* only read is allowed */
 	if (type != BPF_READ)
 		return false;
+
+	/* disallow misaligned access */
 	if (off % size != 0)
 		return false;
+
 	return true;
 }
 
@@ -483,209 +332,9 @@ static struct bpf_prog_type_list kprobe_tl = {
 	.type	= BPF_PROG_TYPE_KPROBE,
 };
 
-BPF_CALL_5(bpf_perf_event_output_tp, void *, tp_buff, struct bpf_map *, map,
-	   u64, flags, void *, data, u64, size)
-{
-	struct pt_regs *regs = *(struct pt_regs **)tp_buff;
-
-	/*
-	 * r1 points to perf tracepoint buffer where first 8 bytes are hidden
-	 * from bpf program and contain a pointer to 'struct pt_regs'. Fetch it
-	 * from there and call the same bpf_perf_event_output() helper inline.
-	 */
-	return ____bpf_perf_event_output(regs, map, flags, data, size);
-}
-
-static const struct bpf_func_proto bpf_perf_event_output_proto_tp = {
-	.func		= bpf_perf_event_output_tp,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_CONST_MAP_PTR,
-	.arg3_type	= ARG_ANYTHING,
-	.arg4_type	= ARG_PTR_TO_STACK,
-	.arg5_type	= ARG_CONST_STACK_SIZE,
-};
-
-BPF_CALL_3(bpf_get_stackid_tp, void *, tp_buff, struct bpf_map *, map,
-	   u64, flags)
-{
-	struct pt_regs *regs = *(struct pt_regs **)tp_buff;
-
-	/*
-	 * Same comment as in bpf_perf_event_output_tp(), only that this time
-	 * the other helper's function body cannot be inlined due to being
-	 * external, thus we need to call raw helper function.
-	 */
-	return bpf_get_stackid((unsigned long) regs, (unsigned long) map,
-			       flags, 0, 0);
-}
-
-static const struct bpf_func_proto bpf_get_stackid_proto_tp = {
-	.func		= bpf_get_stackid_tp,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_CONST_MAP_PTR,
-	.arg3_type	= ARG_ANYTHING,
-};
-
-static const struct bpf_func_proto *tp_prog_func_proto(enum bpf_func_id func_id)
-{
-	switch (func_id) {
-	case BPF_FUNC_perf_event_output:
-		return &bpf_perf_event_output_proto_tp;
-	case BPF_FUNC_get_stackid:
-		return &bpf_get_stackid_proto_tp;
-	default:
-		return tracing_func_proto(func_id);
-	}
-}
-
-static bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type,
-				    enum bpf_reg_type *reg_type)
-{
-	if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
-		return false;
-	if (type != BPF_READ)
-		return false;
-	if (off % size != 0)
-		return false;
-	return true;
-}
-
-static const struct bpf_verifier_ops tracepoint_prog_ops = {
-	.get_func_proto  = tp_prog_func_proto,
-	.is_valid_access = tp_prog_is_valid_access,
-};
-
-static struct bpf_prog_type_list tracepoint_tl = {
-	.ops	= &tracepoint_prog_ops,
-	.type	= BPF_PROG_TYPE_TRACEPOINT,
-};
-
-static bool pe_prog_is_valid_access(int off, int size, enum bpf_access_type type,
-				    enum bpf_reg_type *reg_type)
-{
-	if (off < 0 || off >= sizeof(struct bpf_perf_event_data))
-		return false;
-	if (type != BPF_READ)
-		return false;
-	if (off % size != 0)
-		return false;
-	if (off == offsetof(struct bpf_perf_event_data, sample_period)) {
-		if (size != sizeof(u64))
-			return false;
-	} else {
-		if (size != sizeof(long))
-			return false;
-	}
-	return true;
-}
-
-static u32 pe_prog_convert_ctx_access(enum bpf_access_type type, int dst_reg,
-				      int src_reg, int ctx_off,
-				      struct bpf_insn *insn_buf,
-				      struct bpf_prog *prog)
-{
-	struct bpf_insn *insn = insn_buf;
-
-	switch (ctx_off) {
-	case offsetof(struct bpf_perf_event_data, sample_period):
-		BUILD_BUG_ON(FIELD_SIZEOF(struct perf_sample_data, period) != sizeof(u64));
-
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_perf_event_data_kern,
-						       data), dst_reg, src_reg,
-				      offsetof(struct bpf_perf_event_data_kern, data));
-		*insn++ = BPF_LDX_MEM(BPF_DW, dst_reg, dst_reg,
-				      offsetof(struct perf_sample_data, period));
-		break;
-	default:
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_perf_event_data_kern,
-						       regs), dst_reg, src_reg,
-				      offsetof(struct bpf_perf_event_data_kern, regs));
-		*insn++ = BPF_LDX_MEM(BPF_SIZEOF(long), dst_reg, dst_reg, ctx_off);
-		break;
-	}
-
-	return insn - insn_buf;
-}
-
-static const struct bpf_verifier_ops perf_event_prog_ops = {
-	.get_func_proto		= tp_prog_func_proto,
-	.is_valid_access	= pe_prog_is_valid_access,
-	.convert_ctx_access	= pe_prog_convert_ctx_access,
-};
-
-static DEFINE_MUTEX(bpf_event_mutex);
-
-int perf_event_attach_bpf_prog(struct perf_event *event,
-			       struct bpf_prog *prog)
-{
-	struct bpf_prog_array __rcu *old_array;
-	struct bpf_prog_array *new_array;
-	int ret = -EEXIST;
-
-	mutex_lock(&bpf_event_mutex);
-
-	if (event->prog)
-		goto out;
-
-	old_array = rcu_dereference_protected(event->tp_event->prog_array,
-					      lockdep_is_held(&bpf_event_mutex));
-	ret = bpf_prog_array_copy(old_array, NULL, prog, &new_array);
-	if (ret < 0)
-		goto out;
-
-	/* set the new array to event->tp_event and set event->prog */
-	event->prog = prog;
-	rcu_assign_pointer(event->tp_event->prog_array, new_array);
-	bpf_prog_array_free(old_array);
-
-out:
-	mutex_unlock(&bpf_event_mutex);
-	return ret;
-}
-
-void perf_event_detach_bpf_prog(struct perf_event *event)
-{
-	struct bpf_prog_array __rcu *old_array;
-	struct bpf_prog_array *new_array;
-	int ret;
-
-	mutex_lock(&bpf_event_mutex);
-
-	if (!event->prog)
-		goto out;
-
-	old_array = rcu_dereference_protected(event->tp_event->prog_array,
-					      lockdep_is_held(&bpf_event_mutex));
-
-	ret = bpf_prog_array_copy(old_array, event->prog, NULL, &new_array);
-	if (ret < 0) {
-		bpf_prog_array_delete_safe(old_array, event->prog);
-	} else {
-		rcu_assign_pointer(event->tp_event->prog_array, new_array);
-		bpf_prog_array_free(old_array);
-	}
-
-	bpf_prog_put(event->prog);
-	event->prog = NULL;
-
-out:
-	mutex_unlock(&bpf_event_mutex);
-}
-
-static struct bpf_prog_type_list perf_event_tl = {
-	.ops	= &perf_event_prog_ops,
-	.type	= BPF_PROG_TYPE_PERF_EVENT,
-};
-
 static int __init register_kprobe_prog_ops(void)
 {
 	bpf_register_prog_type(&kprobe_tl);
-	bpf_register_prog_type(&tracepoint_tl);
-	bpf_register_prog_type(&perf_event_tl);
 	return 0;
 }
 late_initcall(register_kprobe_prog_ops);
diff --git a/kernel/trace/trace_event_perf.c b/kernel/trace/trace_event_perf.c
index c40a72bf8953..731f6484b811 100644
--- a/kernel/trace/trace_event_perf.c
+++ b/kernel/trace/trace_event_perf.c
@@ -261,43 +261,42 @@ void perf_trace_del(struct perf_event *p_event, int flags)
 	tp_event->class->reg(tp_event, TRACE_REG_PERF_DEL, p_event);
 }
 
-void *perf_trace_buf_alloc(int size, struct pt_regs **regs, int *rctxp)
+void *perf_trace_buf_prepare(int size, unsigned short type,
+			     struct pt_regs **regs, int *rctxp)
 {
+	struct trace_entry *entry;
+	unsigned long flags;
 	char *raw_data;
-	int rctx;
+	int pc;
 
 	BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % sizeof(unsigned long));
 
 	if (WARN_ONCE(size > PERF_MAX_TRACE_SIZE,
-		      "perf buffer not large enough"))
+			"perf buffer not large enough"))
 		return NULL;
 
-	*rctxp = rctx = perf_swevent_get_recursion_context();
-	if (rctx < 0)
+	pc = preempt_count();
+
+	*rctxp = perf_swevent_get_recursion_context();
+	if (*rctxp < 0)
 		return NULL;
 
 	if (regs)
-		*regs = this_cpu_ptr(&__perf_regs[rctx]);
-	raw_data = this_cpu_ptr(perf_trace_buf[rctx]);
+		*regs = this_cpu_ptr(&__perf_regs[*rctxp]);
+	raw_data = this_cpu_ptr(perf_trace_buf[*rctxp]);
 
 	/* zero the dead bytes from align to not leak stack to user */
 	memset(&raw_data[size - sizeof(u64)], 0, sizeof(u64));
-	return raw_data;
-}
-EXPORT_SYMBOL_GPL(perf_trace_buf_alloc);
-NOKPROBE_SYMBOL(perf_trace_buf_alloc);
-
-void perf_trace_buf_update(void *record, u16 type)
-{
-	struct trace_entry *entry = record;
-	int pc = preempt_count();
-	unsigned long flags;
 
+	entry = (struct trace_entry *)raw_data;
 	local_save_flags(flags);
 	tracing_generic_entry_update(entry, flags, pc);
 	entry->type = type;
+
+	return raw_data;
 }
-NOKPROBE_SYMBOL(perf_trace_buf_update);
+EXPORT_SYMBOL_GPL(perf_trace_buf_prepare);
+NOKPROBE_SYMBOL(perf_trace_buf_prepare);
 
 #ifdef CONFIG_FUNCTION_TRACER
 static void
@@ -320,13 +319,13 @@ perf_ftrace_function_call(unsigned long ip, unsigned long parent_ip,
 
 	perf_fetch_caller_regs(&regs);
 
-	entry = perf_trace_buf_alloc(ENTRY_SIZE, NULL, &rctx);
+	entry = perf_trace_buf_prepare(ENTRY_SIZE, TRACE_FN, NULL, &rctx);
 	if (!entry)
 		return;
 
 	entry->ip = ip;
 	entry->parent_ip = parent_ip;
-	perf_trace_buf_submit(entry, ENTRY_SIZE, rctx, TRACE_FN,
+	perf_trace_buf_submit(entry, ENTRY_SIZE, rctx, 0,
 			      1, &regs, head, NULL);
 
 #undef ENTRY_SIZE
diff --git a/kernel/trace/trace_events.c b/kernel/trace/trace_events.c
index e882a55d59b2..15ca669ea5d5 100644
--- a/kernel/trace/trace_events.c
+++ b/kernel/trace/trace_events.c
@@ -204,24 +204,6 @@ static void trace_destroy_fields(struct trace_event_call *call)
 	}
 }
 
-/*
- * run-time version of trace_event_get_offsets_<call>() that returns the last
- * accessible offset of trace fields excluding __dynamic_array bytes
- */
-int trace_event_get_offsets(struct trace_event_call *call)
-{
-	struct ftrace_event_field *tail;
-	struct list_head *head;
-
-	head = trace_get_fields(call);
-	/*
-	 * head->next points to the last field with the largest offset,
-	 * since it was added last by trace_define_field()
-	 */
-	tail = list_first_entry(head, struct ftrace_event_field, link);
-	return tail->offset + tail->size;
-}
-
 int trace_event_raw_init(struct trace_event_call *call)
 {
 	int id;
diff --git a/kernel/trace/trace_kprobe.c b/kernel/trace/trace_kprobe.c
index 5db1a3eec84d..f0ee722be520 100644
--- a/kernel/trace/trace_kprobe.c
+++ b/kernel/trace/trace_kprobe.c
@@ -1129,12 +1129,13 @@ static void
 kprobe_perf_func(struct trace_kprobe *tk, struct pt_regs *regs)
 {
 	struct trace_event_call *call = &tk->tp.call;
+	struct bpf_prog *prog = call->prog;
 	struct kprobe_trace_entry_head *entry;
 	struct hlist_head *head;
 	int size, __size, dsize;
 	int rctx;
 
-	if (bpf_prog_array_valid(call) && !trace_call_bpf(call, regs))
+	if (prog && !trace_call_bpf(prog, regs))
 		return;
 
 	head = this_cpu_ptr(call->perf_events);
@@ -1146,15 +1147,14 @@ kprobe_perf_func(struct trace_kprobe *tk, struct pt_regs *regs)
 	size = ALIGN(__size + sizeof(u32), sizeof(u64));
 	size -= sizeof(u32);
 
-	entry = perf_trace_buf_alloc(size, NULL, &rctx);
+	entry = perf_trace_buf_prepare(size, call->event.type, NULL, &rctx);
 	if (!entry)
 		return;
 
 	entry->ip = (unsigned long)tk->rp.kp.addr;
 	memset(&entry[1], 0, dsize);
 	store_trace_args(sizeof(*entry), &tk->tp, regs, (u8 *)&entry[1], dsize);
-	perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs,
-			      head, NULL);
+	perf_trace_buf_submit(entry, size, rctx, 0, 1, regs, head, NULL);
 }
 NOKPROBE_SYMBOL(kprobe_perf_func);
 
@@ -1164,12 +1164,13 @@ kretprobe_perf_func(struct trace_kprobe *tk, struct kretprobe_instance *ri,
 		    struct pt_regs *regs)
 {
 	struct trace_event_call *call = &tk->tp.call;
+	struct bpf_prog *prog = call->prog;
 	struct kretprobe_trace_entry_head *entry;
 	struct hlist_head *head;
 	int size, __size, dsize;
 	int rctx;
 
-	if (bpf_prog_array_valid(call) && !trace_call_bpf(call, regs))
+	if (prog && !trace_call_bpf(prog, regs))
 		return;
 
 	head = this_cpu_ptr(call->perf_events);
@@ -1181,15 +1182,14 @@ kretprobe_perf_func(struct trace_kprobe *tk, struct kretprobe_instance *ri,
 	size = ALIGN(__size + sizeof(u32), sizeof(u64));
 	size -= sizeof(u32);
 
-	entry = perf_trace_buf_alloc(size, NULL, &rctx);
+	entry = perf_trace_buf_prepare(size, call->event.type, NULL, &rctx);
 	if (!entry)
 		return;
 
 	entry->func = (unsigned long)tk->rp.kp.addr;
 	entry->ret_ip = (unsigned long)ri->ret_addr;
 	store_trace_args(sizeof(*entry), &tk->tp, regs, (u8 *)&entry[1], dsize);
-	perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs,
-			      head, NULL);
+	perf_trace_buf_submit(entry, size, rctx, 0, 1, regs, head, NULL);
 }
 NOKPROBE_SYMBOL(kretprobe_perf_func);
 #endif	/* CONFIG_PERF_EVENTS */
diff --git a/kernel/trace/trace_syscalls.c b/kernel/trace/trace_syscalls.c
index e8540540ecab..a01740a98afa 100644
--- a/kernel/trace/trace_syscalls.c
+++ b/kernel/trace/trace_syscalls.c
@@ -551,7 +551,6 @@ static void perf_syscall_enter(void *ignore, struct pt_regs *regs, long id)
 	struct syscall_metadata *sys_data;
 	struct syscall_trace_enter *rec;
 	struct hlist_head *head;
-	bool valid_prog_array;
 	int syscall_nr;
 	int rctx;
 	int size;
@@ -567,8 +566,7 @@ static void perf_syscall_enter(void *ignore, struct pt_regs *regs, long id)
 		return;
 
 	head = this_cpu_ptr(sys_data->enter_event->perf_events);
-	valid_prog_array = bpf_prog_array_valid(sys_data->enter_event);
-	if (!valid_prog_array && hlist_empty(head))
+	if (hlist_empty(head))
 		return;
 
 	/* get the size after alignment with the u32 buffer size field */
@@ -576,16 +574,15 @@ static void perf_syscall_enter(void *ignore, struct pt_regs *regs, long id)
 	size = ALIGN(size + sizeof(u32), sizeof(u64));
 	size -= sizeof(u32);
 
-	rec = perf_trace_buf_alloc(size, NULL, &rctx);
+	rec = (struct syscall_trace_enter *)perf_trace_buf_prepare(size,
+				sys_data->enter_event->event.type, NULL, &rctx);
 	if (!rec)
 		return;
 
 	rec->nr = syscall_nr;
 	syscall_get_arguments(current, regs, 0, sys_data->nb_args,
 			       (unsigned long *)&rec->args);
-	perf_trace_buf_submit(rec, size, rctx,
-			      sys_data->enter_event->event.type, 1, regs,
-			      head, NULL);
+	perf_trace_buf_submit(rec, size, rctx, 0, 1, regs, head, NULL);
 }
 
 static int perf_sysenter_enable(struct trace_event_call *call)
@@ -628,7 +625,6 @@ static void perf_syscall_exit(void *ignore, struct pt_regs *regs, long ret)
 	struct syscall_metadata *sys_data;
 	struct syscall_trace_exit *rec;
 	struct hlist_head *head;
-	bool valid_prog_array;
 	int syscall_nr;
 	int rctx;
 	int size;
@@ -644,22 +640,21 @@ static void perf_syscall_exit(void *ignore, struct pt_regs *regs, long ret)
 		return;
 
 	head = this_cpu_ptr(sys_data->exit_event->perf_events);
-	valid_prog_array = bpf_prog_array_valid(sys_data->exit_event);
-	if (!valid_prog_array && hlist_empty(head))
+	if (hlist_empty(head))
 		return;
 
 	/* We can probably do that at build time */
 	size = ALIGN(sizeof(*rec) + sizeof(u32), sizeof(u64));
 	size -= sizeof(u32);
 
-	rec = perf_trace_buf_alloc(size, NULL, &rctx);
+	rec = (struct syscall_trace_exit *)perf_trace_buf_prepare(size,
+				sys_data->exit_event->event.type, NULL, &rctx);
 	if (!rec)
 		return;
 
 	rec->nr = syscall_nr;
 	rec->ret = syscall_get_return_value(current, regs);
-	perf_trace_buf_submit(rec, size, rctx, sys_data->exit_event->event.type,
-			      1, regs, head, NULL);
+	perf_trace_buf_submit(rec, size, rctx, 0, 1, regs, head, NULL);
 }
 
 static int perf_sysexit_enable(struct trace_event_call *call)
diff --git a/kernel/trace/trace_uprobe.c b/kernel/trace/trace_uprobe.c
index d86cc7d768f1..0839129fbbd8 100644
--- a/kernel/trace/trace_uprobe.c
+++ b/kernel/trace/trace_uprobe.c
@@ -1119,12 +1119,13 @@ static void __uprobe_perf_func(struct trace_uprobe *tu,
 {
 	struct trace_event_call *call = &tu->tp.call;
 	struct uprobe_trace_entry_head *entry;
+	struct bpf_prog *prog = call->prog;
 	struct hlist_head *head;
 	void *data;
 	int size, esize;
 	int rctx;
 
-	if (bpf_prog_array_valid(call) && !trace_call_bpf(call, regs))
+	if (prog && !trace_call_bpf(prog, regs))
 		return;
 
 	esize = SIZEOF_TRACE_ENTRY(is_ret_probe(tu));
@@ -1139,7 +1140,7 @@ static void __uprobe_perf_func(struct trace_uprobe *tu,
 	if (hlist_empty(head))
 		goto out;
 
-	entry = perf_trace_buf_alloc(size, NULL, &rctx);
+	entry = perf_trace_buf_prepare(size, call->event.type, NULL, &rctx);
 	if (!entry)
 		goto out;
 
@@ -1160,8 +1161,7 @@ static void __uprobe_perf_func(struct trace_uprobe *tu,
 		memset(data + len, 0, size - esize - len);
 	}
 
-	perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs,
-			      head, NULL);
+	perf_trace_buf_submit(entry, size, rctx, 0, 1, regs, head, NULL);
  out:
 	preempt_enable();
 }
diff --git a/kernel/user_namespace.c b/kernel/user_namespace.c
index 74a8e4aead9a..a965df4b54f5 100644
--- a/kernel/user_namespace.c
+++ b/kernel/user_namespace.c
@@ -944,20 +944,6 @@ bool userns_may_setgroups(const struct user_namespace *ns)
 	return allowed;
 }
 
-/*
- * Returns true if @ns is the same namespace as or a descendant of
- * @target_ns.
- */
-bool current_in_userns(const struct user_namespace *target_ns)
-{
-	struct user_namespace *ns;
-	for (ns = current_user_ns(); ns; ns = ns->parent) {
-		if (ns == target_ns)
-			return true;
-	}
-	return false;
-}
-
 static inline struct user_namespace *to_user_ns(struct ns_common *ns)
 {
 	return container_of(ns, struct user_namespace, ns);
@@ -1010,36 +996,12 @@ static int userns_install(struct nsproxy *nsproxy, struct ns_common *ns)
 	return commit_creds(cred);
 }
 
-struct ns_common *ns_get_owner(struct ns_common *ns)
-{
-	struct user_namespace *my_user_ns = current_user_ns();
-	struct user_namespace *owner, *p;
-
-	/* See if the owner is in the current user namespace */
-	owner = p = ns->ops->owner(ns);
-	for (;;) {
-		if (!p)
-			return ERR_PTR(-EPERM);
-		if (p == my_user_ns)
-			break;
-		p = p->parent;
-	}
-
-	return &get_user_ns(owner)->ns;
-}
-
-static struct user_namespace *userns_owner(struct ns_common *ns)
-{
-	return to_user_ns(ns)->parent;
-}
-
 const struct proc_ns_operations userns_operations = {
 	.name		= "user",
 	.type		= CLONE_NEWUSER,
 	.get		= userns_get,
 	.put		= userns_put,
 	.install	= userns_install,
-	.owner		= userns_owner,
 };
 
 static __init int user_namespaces_init(void)
diff --git a/kernel/utsname.c b/kernel/utsname.c
index e1211a8a5c18..831ea7108232 100644
--- a/kernel/utsname.c
+++ b/kernel/utsname.c
@@ -130,16 +130,10 @@ static int utsns_install(struct nsproxy *nsproxy, struct ns_common *new)
 	return 0;
 }
 
-static struct user_namespace *utsns_owner(struct ns_common *ns)
-{
-	return to_uts_ns(ns)->user_ns;
-}
-
 const struct proc_ns_operations utsns_operations = {
 	.name		= "uts",
 	.type		= CLONE_NEWUTS,
 	.get		= utsns_get,
 	.put		= utsns_put,
 	.install	= utsns_install,
-	.owner		= utsns_owner,
 };
diff --git a/lib/test_bpf.c b/lib/test_bpf.c
index c74e8744722b..1a0d1e771e6c 100644
--- a/lib/test_bpf.c
+++ b/lib/test_bpf.c
@@ -5345,10 +5345,7 @@ static struct bpf_prog *generate_filter(int which, int *err)
 		fp->type = BPF_PROG_TYPE_SOCKET_FILTER;
 		memcpy(fp->insnsi, fptr, fp->len * sizeof(struct bpf_insn));
 
-		/* We cannot error here as we don't need type compatibility
-		 * checks.
-		 */
-		fp = bpf_prog_select_runtime(fp, err);
+		*err = bpf_prog_select_runtime(fp);
 		if (*err) {
 			pr_cont("FAIL to select_runtime err=%d\n", *err);
 			return NULL;
diff --git a/net/Kconfig b/net/Kconfig
index 00820cdb6c95..de3c9ce12771 100644
--- a/net/Kconfig
+++ b/net/Kconfig
@@ -271,7 +271,6 @@ config XPS
 config CGROUP_NET_PRIO
 	bool "Network priority cgroup"
 	depends on CGROUPS
-	select SOCK_CGROUP_DATA
 	---help---
 	  Cgroup subsystem for use in assigning processes to network priorities on
 	  a per-interface basis.
@@ -279,7 +278,6 @@ config CGROUP_NET_PRIO
 config CGROUP_NET_CLASSID
 	bool "Network classid cgroup"
 	depends on CGROUPS
-	select SOCK_CGROUP_DATA
 	---help---
 	  Cgroup subsystem for use as general purpose socket classid marker that is
 	  being used in cls_cgroup and for netfilter matching.
@@ -302,11 +300,8 @@ config BPF_JIT
 	  Berkeley Packet Filter filtering capabilities are normally handled
 	  by an interpreter. This option allows kernel to generate a native
 	  code when filter is loaded in memory. This should speedup
-	  packet sniffing (libpcap/tcpdump).
-
-	  Note, admin should enable this feature changing:
-	  /proc/sys/net/core/bpf_jit_enable
-	  /proc/sys/net/core/bpf_jit_harden (optional)
+	  packet sniffing (libpcap/tcpdump). Note : Admin should enable
+	  this feature changing /proc/sys/net/core/bpf_jit_enable
 
 config NET_FLOW_LIMIT
 	bool
@@ -426,3 +421,6 @@ endif   # if NET
 # Used by archs to tell that they support BPF_JIT
 config HAVE_BPF_JIT
 	bool
+
+config HAVE_EBPF_JIT
+	bool
diff --git a/net/core/Makefile b/net/core/Makefile
index 5e3c5fe87379..0d35bba614a9 100644
--- a/net/core/Makefile
+++ b/net/core/Makefile
@@ -9,7 +9,7 @@ obj-$(CONFIG_SYSCTL) += sysctl_net_core.o
 
 obj-y		     += dev.o ethtool.o dev_addr_lists.o dst.o netevent.o \
 			neighbour.o rtnetlink.o utils.o link_watch.o filter.o \
-			sock_diag.o dev_ioctl.o tso.o sock_reuseport.o
+			sock_diag.o dev_ioctl.o tso.o
 
 obj-$(CONFIG_XFRM) += flow.o
 obj-y += net-sysfs.o
diff --git a/net/core/dev.c b/net/core/dev.c
index 845e06b4434e..d82394243781 100644
--- a/net/core/dev.c
+++ b/net/core/dev.c
@@ -3010,8 +3010,7 @@ static void skb_update_prio(struct sk_buff *skb)
 	struct netprio_map *map = rcu_dereference_bh(skb->dev->priomap);
 
 	if (!skb->priority && skb->sk && map) {
-		unsigned int prioidx =
-			sock_cgroup_prioidx(&skb->sk->sk_cgrp_data);
+		unsigned int prioidx = skb->sk->sk_cgrp_prioidx;
 
 		if (prioidx < map->priomap_len)
 			skb->priority = map->priomap[prioidx];
@@ -3024,6 +3023,8 @@ static void skb_update_prio(struct sk_buff *skb)
 DEFINE_PER_CPU(int, xmit_recursion);
 EXPORT_SYMBOL(xmit_recursion);
 
+#define RECURSION_LIMIT 8
+
 /**
  *	dev_loopback_xmit - loop back @skb
  *	@net: network namespace this loopback is happening in
@@ -3215,8 +3216,8 @@ static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
 		int cpu = smp_processor_id(); /* ok because BHs are off */
 
 		if (txq->xmit_lock_owner != cpu) {
-			if (unlikely(__this_cpu_read(xmit_recursion) >
-				     XMIT_RECURSION_LIMIT))
+
+			if (__this_cpu_read(xmit_recursion) > RECURSION_LIMIT)
 				goto recursion_alert;
 
 			skb = validate_xmit_skb(skb, dev);
diff --git a/net/core/filter.c b/net/core/filter.c
index bfc5ab6ad10c..3c5f51198c41 100644
--- a/net/core/filter.c
+++ b/net/core/filter.c
@@ -26,7 +26,6 @@
 #include <linux/mm.h>
 #include <linux/fcntl.h>
 #include <linux/socket.h>
-#include <linux/sock_diag.h>
 #include <linux/in.h>
 #include <linux/inet.h>
 #include <linux/netdevice.h>
@@ -51,7 +50,6 @@
 #include <net/cls_cgroup.h>
 #include <net/dst_metadata.h>
 #include <net/dst.h>
-#include <net/sock_reuseport.h>
 
 /**
  *	sk_filter_trim_cap - run a packet through a socket filter
@@ -86,13 +84,8 @@ int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
 	rcu_read_lock();
 	filter = rcu_dereference(sk->sk_filter);
 	if (filter) {
-		struct sock *save_sk = skb->sk;
-		unsigned int pkt_len;
-
-		skb->sk = sk;
-		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
+		unsigned int pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
 		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
-		skb->sk = save_sk;
 	}
 	rcu_read_unlock();
 
@@ -100,13 +93,14 @@ int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
 }
 EXPORT_SYMBOL(sk_filter_trim_cap);
 
-BPF_CALL_1(__skb_get_pay_offset, struct sk_buff *, skb)
+static u64 __skb_get_pay_offset(u64 ctx, u64 a, u64 x, u64 r4, u64 r5)
 {
-	return skb_get_poff(skb);
+	return skb_get_poff((struct sk_buff *)(unsigned long) ctx);
 }
 
-BPF_CALL_3(__skb_get_nlattr, struct sk_buff *, skb, u32, a, u32, x)
+static u64 __skb_get_nlattr(u64 ctx, u64 a, u64 x, u64 r4, u64 r5)
 {
+	struct sk_buff *skb = (struct sk_buff *)(unsigned long) ctx;
 	struct nlattr *nla;
 
 	if (skb_is_nonlinear(skb))
@@ -125,8 +119,9 @@ BPF_CALL_3(__skb_get_nlattr, struct sk_buff *, skb, u32, a, u32, x)
 	return 0;
 }
 
-BPF_CALL_3(__skb_get_nlattr_nest, struct sk_buff *, skb, u32, a, u32, x)
+static u64 __skb_get_nlattr_nest(u64 ctx, u64 a, u64 x, u64 r4, u64 r5)
 {
+	struct sk_buff *skb = (struct sk_buff *)(unsigned long) ctx;
 	struct nlattr *nla;
 
 	if (skb_is_nonlinear(skb))
@@ -149,17 +144,11 @@ BPF_CALL_3(__skb_get_nlattr_nest, struct sk_buff *, skb, u32, a, u32, x)
 	return 0;
 }
 
-BPF_CALL_0(__get_raw_cpu_id)
+static u64 __get_raw_cpu_id(u64 ctx, u64 a, u64 x, u64 r4, u64 r5)
 {
 	return raw_smp_processor_id();
 }
 
-static const struct bpf_func_proto bpf_get_raw_smp_processor_id_proto = {
-	.func		= __get_raw_cpu_id,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-};
-
 static u32 convert_skb_access(int skb_field, int dst_reg, int src_reg,
 			      struct bpf_insn *insn_buf)
 {
@@ -237,8 +226,9 @@ static bool convert_bpf_extensions(struct sock_filter *fp,
 	case SKF_AD_OFF + SKF_AD_HATYPE:
 		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);
 		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, type) != 2);
+		BUILD_BUG_ON(bytes_to_bpf_size(FIELD_SIZEOF(struct sk_buff, dev)) < 0);
 
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
+		*insn++ = BPF_LDX_MEM(bytes_to_bpf_size(FIELD_SIZEOF(struct sk_buff, dev)),
 				      BPF_REG_TMP, BPF_REG_CTX,
 				      offsetof(struct sk_buff, dev));
 		/* if (tmp != 0) goto pc + 1 */
@@ -358,6 +348,12 @@ static bool convert_bpf_extensions(struct sock_filter *fp,
  *    jump offsets, 2nd pass remapping:
  *   new_prog = kmalloc(sizeof(struct bpf_insn) * new_len);
  *   bpf_convert_filter(old_prog, old_len, new_prog, &new_len);
+ *
+ * User BPF's register A is mapped to our BPF register 6, user BPF
+ * register X is mapped to BPF register 7; frame pointer is always
+ * register 10; Context 'void *ctx' is stored in register 1, that is,
+ * for socket filters: ctx == 'struct sk_buff *', for seccomp:
+ * ctx == 'struct seccomp_data *'.
  */
 static int bpf_convert_filter(struct sock_filter *prog, int len,
 			      struct bpf_insn *new_prog, int *new_len)
@@ -385,22 +381,9 @@ do_pass:
 	new_insn = new_prog;
 	fp = prog;
 
-	/* Classic BPF related prologue emission. */
-	if (new_insn) {
-		/* Classic BPF expects A and X to be reset first. These need
-		 * to be guaranteed to be the first two instructions.
-		 */
-		*new_insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
-		*new_insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_X, BPF_REG_X);
-
-		/* All programs must keep CTX in callee saved BPF_REG_CTX.
-		 * In eBPF case it's done by the compiler, here we need to
-		 * do this ourself. Initial CTX is present in BPF_REG_ARG1.
-		 */
-		*new_insn++ = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
-	} else {
-		new_insn += 3;
-	}
+	if (new_insn)
+		*new_insn = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
+	new_insn++;
 
 	for (i = 0; i < len; fp++, i++) {
 		struct bpf_insn tmp_insns[6] = { };
@@ -543,14 +526,12 @@ do_pass:
 			*insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_TMP);
 			break;
 
-		/* RET_K is remaped into 2 insns. RET_A case doesn't need an
-		 * extra mov as BPF_REG_0 is already mapped into BPF_REG_A.
-		 */
+		/* RET_K, RET_A are remaped into 2 insns. */
 		case BPF_RET | BPF_A:
 		case BPF_RET | BPF_K:
-			if (BPF_RVAL(fp->code) == BPF_K)
-				*insn++ = BPF_MOV32_RAW(BPF_K, BPF_REG_0,
-							0, fp->k);
+			*insn++ = BPF_MOV32_RAW(BPF_RVAL(fp->code) == BPF_K ?
+						BPF_K : BPF_X, BPF_REG_0,
+						BPF_REG_A, fp->k);
 			*insn = BPF_EXIT_INSN();
 			break;
 
@@ -1015,7 +996,7 @@ static struct bpf_prog *bpf_migrate_filter(struct bpf_prog *fp)
 		 */
 		goto out_err_free;
 
-	fp = bpf_prog_select_runtime(fp, &err);
+	err = bpf_prog_select_runtime(fp);
 	if (err)
 		goto out_err_free;
 
@@ -1172,7 +1153,8 @@ void bpf_prog_destroy(struct bpf_prog *fp)
 }
 EXPORT_SYMBOL_GPL(bpf_prog_destroy);
 
-static int __sk_attach_prog(struct bpf_prog *prog, struct sock *sk)
+static int __sk_attach_prog(struct bpf_prog *prog, struct sock *sk,
+			    bool locked)
 {
 	struct sk_filter *fp, *old_fp;
 
@@ -1188,61 +1170,45 @@ static int __sk_attach_prog(struct bpf_prog *prog, struct sock *sk)
 		return -ENOMEM;
 	}
 
-	old_fp = rcu_dereference_protected(sk->sk_filter,
-					   lockdep_sock_is_held(sk));
+	old_fp = rcu_dereference_protected(sk->sk_filter, locked);
 	rcu_assign_pointer(sk->sk_filter, fp);
-
 	if (old_fp)
 		sk_filter_uncharge(sk, old_fp);
 
 	return 0;
 }
 
-static int __reuseport_attach_prog(struct bpf_prog *prog, struct sock *sk)
-{
-	struct bpf_prog *old_prog;
-	int err;
-
-	if (bpf_prog_size(prog->len) > sysctl_optmem_max)
-		return -ENOMEM;
-
-	if (sk_unhashed(sk)) {
-		err = reuseport_alloc(sk);
-		if (err)
-			return err;
-	} else if (!rcu_access_pointer(sk->sk_reuseport_cb)) {
-		/* The socket wasn't bound with SO_REUSEPORT */
-		return -EINVAL;
-	}
-
-	old_prog = reuseport_attach_prog(sk, prog);
-	if (old_prog)
-		bpf_prog_destroy(old_prog);
-
-	return 0;
-}
-
-static
-struct bpf_prog *__get_filter(struct sock_fprog *fprog, struct sock *sk)
+/**
+ *	sk_attach_filter - attach a socket filter
+ *	@fprog: the filter program
+ *	@sk: the socket to use
+ *
+ * Attach the user's filter code. We first run some sanity checks on
+ * it to make sure it does not explode on us later. If an error
+ * occurs or there is insufficient memory for the filter a negative
+ * errno code is returned. On success the return is zero.
+ */
+int __sk_attach_filter(struct sock_fprog *fprog, struct sock *sk,
+		       bool locked)
 {
 	unsigned int fsize = bpf_classic_proglen(fprog);
 	struct bpf_prog *prog;
 	int err;
 
 	if (sock_flag(sk, SOCK_FILTER_LOCKED))
-		return ERR_PTR(-EPERM);
+		return -EPERM;
 
 	/* Make sure new filter is there and in the right amounts. */
-	if (fprog->filter == NULL)
-		return ERR_PTR(-EINVAL);
+	if (!bpf_check_basics_ok(fprog->filter, fprog->len))
+		return -EINVAL;
 
 	prog = bpf_prog_alloc(bpf_prog_size(fprog->len), 0);
 	if (!prog)
-		return ERR_PTR(-ENOMEM);
+		return -ENOMEM;
 
 	if (copy_from_user(prog->insns, fprog->filter, fsize)) {
 		__bpf_prog_free(prog);
-		return ERR_PTR(-EFAULT);
+		return -EFAULT;
 	}
 
 	prog->len = fprog->len;
@@ -1250,52 +1216,17 @@ struct bpf_prog *__get_filter(struct sock_fprog *fprog, struct sock *sk)
 	err = bpf_prog_store_orig_filter(prog, fprog);
 	if (err) {
 		__bpf_prog_free(prog);
-		return ERR_PTR(-ENOMEM);
+		return -ENOMEM;
 	}
 
 	/* bpf_prepare_filter() already takes care of freeing
 	 * memory in case something goes wrong.
 	 */
-	return bpf_prepare_filter(prog, NULL);
-}
-
-/**
- *	sk_attach_filter - attach a socket filter
- *	@fprog: the filter program
- *	@sk: the socket to use
- *
- * Attach the user's filter code. We first run some sanity checks on
- * it to make sure it does not explode on us later. If an error
- * occurs or there is insufficient memory for the filter a negative
- * errno code is returned. On success the return is zero.
- */
-int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
-{
-	struct bpf_prog *prog = __get_filter(fprog, sk);
-	int err;
-
-	if (IS_ERR(prog))
-		return PTR_ERR(prog);
-
-	err = __sk_attach_prog(prog, sk);
-	if (err < 0) {
-		__bpf_prog_release(prog);
-		return err;
-	}
-
-	return 0;
-}
-EXPORT_SYMBOL_GPL(sk_attach_filter);
-
-int sk_reuseport_attach_filter(struct sock_fprog *fprog, struct sock *sk)
-{
-	struct bpf_prog *prog = __get_filter(fprog, sk);
-	int err;
-
+	prog = bpf_prepare_filter(prog, NULL);
 	if (IS_ERR(prog))
 		return PTR_ERR(prog);
 
-	err = __reuseport_attach_prog(prog, sk);
+	err = __sk_attach_prog(prog, sk, locked);
 	if (err < 0) {
 		__bpf_prog_release(prog);
 		return err;
@@ -1303,41 +1234,31 @@ int sk_reuseport_attach_filter(struct sock_fprog *fprog, struct sock *sk)
 
 	return 0;
 }
+EXPORT_SYMBOL_GPL(__sk_attach_filter);
 
-static struct bpf_prog *__get_bpf(u32 ufd, struct sock *sk)
+int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
 {
-	if (sock_flag(sk, SOCK_FILTER_LOCKED))
-		return ERR_PTR(-EPERM);
-
-	return bpf_prog_get_type(ufd, BPF_PROG_TYPE_SOCKET_FILTER);
+	return __sk_attach_filter(fprog, sk, sock_owned_by_user(sk));
 }
 
 int sk_attach_bpf(u32 ufd, struct sock *sk)
 {
-	struct bpf_prog *prog = __get_bpf(ufd, sk);
+	struct bpf_prog *prog;
 	int err;
 
+	if (sock_flag(sk, SOCK_FILTER_LOCKED))
+		return -EPERM;
+
+	prog = bpf_prog_get(ufd);
 	if (IS_ERR(prog))
 		return PTR_ERR(prog);
 
-	err = __sk_attach_prog(prog, sk);
-	if (err < 0) {
+	if (prog->type != BPF_PROG_TYPE_SOCKET_FILTER) {
 		bpf_prog_put(prog);
-		return err;
+		return -EINVAL;
 	}
 
-	return 0;
-}
-
-int sk_reuseport_attach_bpf(u32 ufd, struct sock *sk)
-{
-	struct bpf_prog *prog = __get_bpf(ufd, sk);
-	int err;
-
-	if (IS_ERR(prog))
-		return PTR_ERR(prog);
-
-	err = __reuseport_attach_prog(prog, sk);
+	err = __sk_attach_prog(prog, sk, sock_owned_by_user(sk));
 	if (err < 0) {
 		bpf_prog_put(prog);
 		return err;
@@ -1346,74 +1267,49 @@ int sk_reuseport_attach_bpf(u32 ufd, struct sock *sk)
 	return 0;
 }
 
-struct bpf_scratchpad {
-	union {
-		__be32 diff[MAX_BPF_STACK / sizeof(__be32)];
-		u8     buff[MAX_BPF_STACK];
-	};
-};
-
-static DEFINE_PER_CPU(struct bpf_scratchpad, bpf_sp);
-
-static inline int __bpf_try_make_writable(struct sk_buff *skb,
-					  unsigned int write_len)
-{
-	return skb_ensure_writable(skb, write_len);
-}
-
-static inline int bpf_try_make_writable(struct sk_buff *skb,
-					unsigned int write_len)
-{
-	int err = __bpf_try_make_writable(skb, write_len);
-
-	bpf_compute_data_end(skb);
-	return err;
-}
-
-static int bpf_try_make_head_writable(struct sk_buff *skb)
-{
-	return bpf_try_make_writable(skb, skb_headlen(skb));
-}
-
-static inline void bpf_push_mac_rcsum(struct sk_buff *skb)
-{
-	if (skb_at_tc_ingress(skb))
-		skb_postpush_rcsum(skb, skb_mac_header(skb), skb->mac_len);
-}
-
-static inline void bpf_pull_mac_rcsum(struct sk_buff *skb)
-{
-	if (skb_at_tc_ingress(skb))
-		skb_postpull_rcsum(skb, skb_mac_header(skb), skb->mac_len);
-}
+#define BPF_RECOMPUTE_CSUM(flags)	((flags) & 1)
 
-BPF_CALL_5(bpf_skb_store_bytes, struct sk_buff *, skb, u32, offset,
-	   const void *, from, u32, len, u64, flags)
+static u64 bpf_skb_store_bytes(u64 r1, u64 r2, u64 r3, u64 r4, u64 flags)
 {
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
+	int offset = (int) r2;
+	void *from = (void *) (long) r3;
+	unsigned int len = (unsigned int) r4;
+	char buf[16];
 	void *ptr;
 
-	if (unlikely(flags & ~(BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH)))
-		return -EINVAL;
-	if (unlikely(offset > 0xffff))
+	/* bpf verifier guarantees that:
+	 * 'from' pointer points to bpf program stack
+	 * 'len' bytes of it were initialized
+	 * 'len' > 0
+	 * 'skb' is a valid pointer to 'struct sk_buff'
+	 *
+	 * so check for invalid 'offset' and too large 'len'
+	 */
+	if (unlikely((u32) offset > 0xffff || len > sizeof(buf)))
+		return -EFAULT;
+	if (unlikely(skb_try_make_writable(skb, offset + len)))
 		return -EFAULT;
-	if (unlikely(bpf_try_make_writable(skb, offset + len)))
+
+	ptr = skb_header_pointer(skb, offset, len, buf);
+	if (unlikely(!ptr))
 		return -EFAULT;
 
-	ptr = skb->data + offset;
-	if (flags & BPF_F_RECOMPUTE_CSUM)
-		__skb_postpull_rcsum(skb, ptr, len, offset);
+	if (BPF_RECOMPUTE_CSUM(flags))
+		skb_postpull_rcsum(skb, ptr, len);
 
 	memcpy(ptr, from, len);
 
-	if (flags & BPF_F_RECOMPUTE_CSUM)
-		__skb_postpush_rcsum(skb, ptr, len, offset);
-	if (flags & BPF_F_INVALIDATE_HASH)
-		skb_clear_hash(skb);
+	if (ptr == buf)
+		/* skb_store_bits cannot return -EFAULT here */
+		skb_store_bits(skb, offset, ptr, len);
 
+	if (BPF_RECOMPUTE_CSUM(flags) && skb->ip_summed == CHECKSUM_COMPLETE)
+		skb->csum = csum_add(skb->csum, csum_partial(ptr, len, 0));
 	return 0;
 }
 
-static const struct bpf_func_proto bpf_skb_store_bytes_proto = {
+const struct bpf_func_proto bpf_skb_store_bytes_proto = {
 	.func		= bpf_skb_store_bytes,
 	.gpl_only	= false,
 	.ret_type	= RET_INTEGER,
@@ -1424,78 +1320,26 @@ static const struct bpf_func_proto bpf_skb_store_bytes_proto = {
 	.arg5_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_4(bpf_skb_load_bytes, const struct sk_buff *, skb, u32, offset,
-	   void *, to, u32, len)
-{
-	void *ptr;
-
-	if (unlikely(offset > 0xffff))
-		goto err_clear;
-
-	ptr = skb_header_pointer(skb, offset, len, to);
-	if (unlikely(!ptr))
-		goto err_clear;
-	if (ptr != to)
-		memcpy(to, ptr, len);
-
-	return 0;
-err_clear:
-	memset(to, 0, len);
-	return -EFAULT;
-}
-
-static const struct bpf_func_proto bpf_skb_load_bytes_proto = {
-	.func		= bpf_skb_load_bytes,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_ANYTHING,
-	.arg3_type	= ARG_PTR_TO_RAW_STACK,
-	.arg4_type	= ARG_CONST_STACK_SIZE,
-};
-
-BPF_CALL_2(bpf_skb_pull_data, struct sk_buff *, skb, u32, len)
-{
-	/* Idea is the following: should the needed direct read/write
-	 * test fail during runtime, we can pull in more data and redo
-	 * again, since implicitly, we invalidate previous checks here.
-	 *
-	 * Or, since we know how much we need to make read/writeable,
-	 * this can be done once at the program beginning for direct
-	 * access case. By this we overcome limitations of only current
-	 * headroom being accessible.
-	 */
-	return bpf_try_make_writable(skb, len ? : skb_headlen(skb));
-}
-
-static const struct bpf_func_proto bpf_skb_pull_data_proto = {
-	.func		= bpf_skb_pull_data,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_ANYTHING,
-};
+#define BPF_HEADER_FIELD_SIZE(flags)	((flags) & 0x0f)
+#define BPF_IS_PSEUDO_HEADER(flags)	((flags) & 0x10)
 
-BPF_CALL_5(bpf_l3_csum_replace, struct sk_buff *, skb, u32, offset,
-	   u64, from, u64, to, u64, flags)
+static u64 bpf_l3_csum_replace(u64 r1, u64 r2, u64 from, u64 to, u64 flags)
 {
-	__sum16 *ptr;
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
+	int offset = (int) r2;
+	__sum16 sum, *ptr;
 
-	if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK)))
-		return -EINVAL;
-	if (unlikely(offset > 0xffff || offset & 1))
+	if (unlikely((u32) offset > 0xffff))
 		return -EFAULT;
-	if (unlikely(bpf_try_make_writable(skb, offset + sizeof(*ptr))))
+
+	if (unlikely(skb_try_make_writable(skb, offset + sizeof(sum))))
 		return -EFAULT;
 
-	ptr = (__sum16 *)(skb->data + offset);
-	switch (flags & BPF_F_HDR_FIELD_MASK) {
-	case 0:
-		if (unlikely(from != 0))
-			return -EINVAL;
+	ptr = skb_header_pointer(skb, offset, sizeof(sum), &sum);
+	if (unlikely(!ptr))
+		return -EFAULT;
 
-		csum_replace_by_diff(ptr, to);
-		break;
+	switch (BPF_HEADER_FIELD_SIZE(flags)) {
 	case 2:
 		csum_replace2(ptr, from, to);
 		break;
@@ -1506,10 +1350,14 @@ BPF_CALL_5(bpf_l3_csum_replace, struct sk_buff *, skb, u32, offset,
 		return -EINVAL;
 	}
 
+	if (ptr == &sum)
+		/* skb_store_bits guaranteed to not return -EFAULT here */
+		skb_store_bits(skb, offset, ptr, sizeof(sum));
+
 	return 0;
 }
 
-static const struct bpf_func_proto bpf_l3_csum_replace_proto = {
+const struct bpf_func_proto bpf_l3_csum_replace_proto = {
 	.func		= bpf_l3_csum_replace,
 	.gpl_only	= false,
 	.ret_type	= RET_INTEGER,
@@ -1520,32 +1368,23 @@ static const struct bpf_func_proto bpf_l3_csum_replace_proto = {
 	.arg5_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_5(bpf_l4_csum_replace, struct sk_buff *, skb, u32, offset,
-	   u64, from, u64, to, u64, flags)
+static u64 bpf_l4_csum_replace(u64 r1, u64 r2, u64 from, u64 to, u64 flags)
 {
-	bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
-	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
-	__sum16 *ptr;
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
+	bool is_pseudo = !!BPF_IS_PSEUDO_HEADER(flags);
+	int offset = (int) r2;
+	__sum16 sum, *ptr;
 
-	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
-			       BPF_F_HDR_FIELD_MASK)))
-		return -EINVAL;
-	if (unlikely(offset > 0xffff || offset & 1))
+	if (unlikely((u32) offset > 0xffff))
 		return -EFAULT;
-	if (unlikely(bpf_try_make_writable(skb, offset + sizeof(*ptr))))
+	if (unlikely(skb_try_make_writable(skb, offset + sizeof(sum))))
 		return -EFAULT;
 
-	ptr = (__sum16 *)(skb->data + offset);
-	if (is_mmzero && !*ptr)
-		return 0;
-
-	switch (flags & BPF_F_HDR_FIELD_MASK) {
-	case 0:
-		if (unlikely(from != 0))
-			return -EINVAL;
+	ptr = skb_header_pointer(skb, offset, sizeof(sum), &sum);
+	if (unlikely(!ptr))
+		return -EFAULT;
 
-		inet_proto_csum_replace_by_diff(ptr, skb, to, is_pseudo);
-		break;
+	switch (BPF_HEADER_FIELD_SIZE(flags)) {
 	case 2:
 		inet_proto_csum_replace2(ptr, skb, from, to, is_pseudo);
 		break;
@@ -1556,12 +1395,14 @@ BPF_CALL_5(bpf_l4_csum_replace, struct sk_buff *, skb, u32, offset,
 		return -EINVAL;
 	}
 
-	if (is_mmzero && !*ptr)
-		*ptr = CSUM_MANGLED_0;
+	if (ptr == &sum)
+		/* skb_store_bits guaranteed to not return -EFAULT here */
+		skb_store_bits(skb, offset, ptr, sizeof(sum));
+
 	return 0;
 }
 
-static const struct bpf_func_proto bpf_l4_csum_replace_proto = {
+const struct bpf_func_proto bpf_l4_csum_replace_proto = {
 	.func		= bpf_l4_csum_replace,
 	.gpl_only	= false,
 	.ret_type	= RET_INTEGER,
@@ -1572,124 +1413,30 @@ static const struct bpf_func_proto bpf_l4_csum_replace_proto = {
 	.arg5_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_5(bpf_csum_diff, __be32 *, from, u32, from_size,
-	   __be32 *, to, u32, to_size, __wsum, seed)
-{
-	struct bpf_scratchpad *sp = this_cpu_ptr(&bpf_sp);
-	u32 diff_size = from_size + to_size;
-	int i, j = 0;
-
-	/* This is quite flexible, some examples:
-	 *
-	 * from_size == 0, to_size > 0,  seed := csum --> pushing data
-	 * from_size > 0,  to_size == 0, seed := csum --> pulling data
-	 * from_size > 0,  to_size > 0,  seed := 0    --> diffing data
-	 *
-	 * Even for diffing, from_size and to_size don't need to be equal.
-	 */
-	if (unlikely(((from_size | to_size) & (sizeof(__be32) - 1)) ||
-		     diff_size > sizeof(sp->diff)))
-		return -EINVAL;
-
-	for (i = 0; i < from_size / sizeof(__be32); i++, j++)
-		sp->diff[j] = ~from[i];
-	for (i = 0; i <   to_size / sizeof(__be32); i++, j++)
-		sp->diff[j] = to[i];
-
-	return csum_partial(sp->diff, diff_size, seed);
-}
-
-static const struct bpf_func_proto bpf_csum_diff_proto = {
-	.func		= bpf_csum_diff,
-	.gpl_only	= false,
-	.pkt_access	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_STACK,
-	.arg2_type	= ARG_CONST_STACK_SIZE_OR_ZERO,
-	.arg3_type	= ARG_PTR_TO_STACK,
-	.arg4_type	= ARG_CONST_STACK_SIZE_OR_ZERO,
-	.arg5_type	= ARG_ANYTHING,
-};
-
-BPF_CALL_2(bpf_csum_update, struct sk_buff *, skb, __wsum, csum)
-{
-	/* The interface is to be used in combination with bpf_csum_diff()
-	 * for direct packet writes. csum rotation for alignment as well
-	 * as emulating csum_sub() can be done from the eBPF program.
-	 */
-	if (skb->ip_summed == CHECKSUM_COMPLETE)
-		return (skb->csum = csum_add(skb->csum, csum));
-
-	return -ENOTSUPP;
-}
-
-static const struct bpf_func_proto bpf_csum_update_proto = {
-	.func		= bpf_csum_update,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_ANYTHING,
-};
-
-static inline int __bpf_rx_skb(struct net_device *dev, struct sk_buff *skb)
-{
-	return dev_forward_skb(dev, skb);
-}
-
-static inline int __bpf_tx_skb(struct net_device *dev, struct sk_buff *skb)
-{
-	int ret;
-
-	if (unlikely(__this_cpu_read(xmit_recursion) > XMIT_RECURSION_LIMIT)) {
-		net_crit_ratelimited("bpf: recursion limit reached on datapath, buggy bpf program?\n");
-		kfree_skb(skb);
-		return -ENETDOWN;
-	}
-
-	skb->dev = dev;
-
-	__this_cpu_inc(xmit_recursion);
-	ret = dev_queue_xmit(skb);
-	__this_cpu_dec(xmit_recursion);
-
-	return ret;
-}
+#define BPF_IS_REDIRECT_INGRESS(flags)	((flags) & 1)
 
-BPF_CALL_3(bpf_clone_redirect, struct sk_buff *, skb, u32, ifindex, u64, flags)
+static u64 bpf_clone_redirect(u64 r1, u64 ifindex, u64 flags, u64 r4, u64 r5)
 {
+	struct sk_buff *skb = (struct sk_buff *) (long) r1, *skb2;
 	struct net_device *dev;
-	struct sk_buff *clone;
-	int ret;
-
-	if (unlikely(flags & ~(BPF_F_INGRESS)))
-		return -EINVAL;
 
 	dev = dev_get_by_index_rcu(dev_net(skb->dev), ifindex);
 	if (unlikely(!dev))
 		return -EINVAL;
 
-	clone = skb_clone(skb, GFP_ATOMIC);
-	if (unlikely(!clone))
-		return -ENOMEM;
-
-	/* For direct write, we need to keep the invariant that the skbs
-	 * we're dealing with need to be uncloned. Should uncloning fail
-	 * here, we need to free the just generated clone to unclone once
-	 * again.
-	 */
-	ret = bpf_try_make_head_writable(skb);
-	if (unlikely(ret)) {
-		kfree_skb(clone);
+	skb2 = skb_clone(skb, GFP_ATOMIC);
+	if (unlikely(!skb2))
 		return -ENOMEM;
-	}
 
-	bpf_push_mac_rcsum(clone);
+	if (BPF_IS_REDIRECT_INGRESS(flags))
+		return dev_forward_skb(dev, skb2);
 
-	return flags & BPF_F_INGRESS ?
-	       __bpf_rx_skb(dev, clone) : __bpf_tx_skb(dev, clone);
+	skb2->dev = dev;
+	skb_sender_cpu_clear(skb2);
+	return dev_queue_xmit(skb2);
 }
 
-static const struct bpf_func_proto bpf_clone_redirect_proto = {
+const struct bpf_func_proto bpf_clone_redirect_proto = {
 	.func           = bpf_clone_redirect,
 	.gpl_only       = false,
 	.ret_type       = RET_INTEGER,
@@ -1704,17 +1451,12 @@ struct redirect_info {
 };
 
 static DEFINE_PER_CPU(struct redirect_info, redirect_info);
-
-BPF_CALL_2(bpf_redirect, u32, ifindex, u64, flags)
+static u64 bpf_redirect(u64 ifindex, u64 flags, u64 r3, u64 r4, u64 r5)
 {
 	struct redirect_info *ri = this_cpu_ptr(&redirect_info);
 
-	if (unlikely(flags & ~(BPF_F_INGRESS)))
-		return TC_ACT_SHOT;
-
 	ri->ifindex = ifindex;
 	ri->flags = flags;
-
 	return TC_ACT_REDIRECT;
 }
 
@@ -1730,13 +1472,15 @@ int skb_do_redirect(struct sk_buff *skb)
 		return -EINVAL;
 	}
 
-	bpf_push_mac_rcsum(skb);
+	if (BPF_IS_REDIRECT_INGRESS(ri->flags))
+		return dev_forward_skb(dev, skb);
 
-	return ri->flags & BPF_F_INGRESS ?
-	       __bpf_rx_skb(dev, skb) : __bpf_tx_skb(dev, skb);
+	skb->dev = dev;
+	skb_sender_cpu_clear(skb);
+	return dev_queue_xmit(skb);
 }
 
-static const struct bpf_func_proto bpf_redirect_proto = {
+const struct bpf_func_proto bpf_redirect_proto = {
 	.func           = bpf_redirect,
 	.gpl_only       = false,
 	.ret_type       = RET_INTEGER,
@@ -1744,9 +1488,9 @@ static const struct bpf_func_proto bpf_redirect_proto = {
 	.arg2_type      = ARG_ANYTHING,
 };
 
-BPF_CALL_1(bpf_get_cgroup_classid, const struct sk_buff *, skb)
+static u64 bpf_get_cgroup_classid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
-	return task_get_classid(skb);
+	return task_get_classid((struct sk_buff *) (unsigned long) r1);
 }
 
 static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
@@ -1756,9 +1500,16 @@ static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
 	.arg1_type      = ARG_PTR_TO_CTX,
 };
 
-BPF_CALL_1(bpf_get_route_realm, const struct sk_buff *, skb)
+static u64 bpf_get_route_realm(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
-	return dst_tclassid(skb);
+#ifdef CONFIG_IP_ROUTE_CLASSID
+	const struct dst_entry *dst;
+
+	dst = skb_dst((struct sk_buff *) (unsigned long) r1);
+	if (dst)
+		return dst->tclassid;
+#endif
+	return 0;
 }
 
 static const struct bpf_func_proto bpf_get_route_realm_proto = {
@@ -1768,54 +1519,16 @@ static const struct bpf_func_proto bpf_get_route_realm_proto = {
 	.arg1_type      = ARG_PTR_TO_CTX,
 };
 
-BPF_CALL_1(bpf_get_hash_recalc, struct sk_buff *, skb)
-{
-	/* If skb_clear_hash() was called due to mangling, we can
-	 * trigger SW recalculation here. Later access to hash
-	 * can then use the inline skb->hash via context directly
-	 * instead of calling this helper again.
-	 */
-	return skb_get_hash(skb);
-}
-
-static const struct bpf_func_proto bpf_get_hash_recalc_proto = {
-	.func		= bpf_get_hash_recalc,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-};
-
-BPF_CALL_1(bpf_set_hash_invalid, struct sk_buff *, skb)
-{
-	/* After all direct packet write, this can be used once for
-	 * triggering a lazy recalc on next skb_get_hash() invocation.
-	 */
-	skb_clear_hash(skb);
-	return 0;
-}
-
-static const struct bpf_func_proto bpf_set_hash_invalid_proto = {
-	.func		= bpf_set_hash_invalid,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-};
-
-BPF_CALL_3(bpf_skb_vlan_push, struct sk_buff *, skb, __be16, vlan_proto,
-	   u16, vlan_tci)
+static u64 bpf_skb_vlan_push(u64 r1, u64 r2, u64 vlan_tci, u64 r4, u64 r5)
 {
-	int ret;
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
+	__be16 vlan_proto = (__force __be16) r2;
 
 	if (unlikely(vlan_proto != htons(ETH_P_8021Q) &&
 		     vlan_proto != htons(ETH_P_8021AD)))
 		vlan_proto = htons(ETH_P_8021Q);
 
-	bpf_push_mac_rcsum(skb);
-	ret = skb_vlan_push(skb, vlan_proto, vlan_tci);
-	bpf_pull_mac_rcsum(skb);
-
-	bpf_compute_data_end(skb);
-	return ret;
+	return skb_vlan_push(skb, vlan_proto, vlan_tci);
 }
 
 const struct bpf_func_proto bpf_skb_vlan_push_proto = {
@@ -1828,16 +1541,11 @@ const struct bpf_func_proto bpf_skb_vlan_push_proto = {
 };
 EXPORT_SYMBOL_GPL(bpf_skb_vlan_push_proto);
 
-BPF_CALL_1(bpf_skb_vlan_pop, struct sk_buff *, skb)
+static u64 bpf_skb_vlan_pop(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 {
-	int ret;
-
-	bpf_push_mac_rcsum(skb);
-	ret = skb_vlan_pop(skb);
-	bpf_pull_mac_rcsum(skb);
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
 
-	bpf_compute_data_end(skb);
-	return ret;
+	return skb_vlan_pop(skb);
 }
 
 const struct bpf_func_proto bpf_skb_vlan_pop_proto = {
@@ -1848,493 +1556,59 @@ const struct bpf_func_proto bpf_skb_vlan_pop_proto = {
 };
 EXPORT_SYMBOL_GPL(bpf_skb_vlan_pop_proto);
 
-static int bpf_skb_generic_push(struct sk_buff *skb, u32 off, u32 len)
+bool bpf_helper_changes_skb_data(void *func)
 {
-	/* Caller already did skb_cow() with len as headroom,
-	 * so no need to do it here.
-	 */
-	skb_push(skb, len);
-	memmove(skb->data, skb->data + len, off);
-	memset(skb->data + off, 0, len);
-
-	/* No skb_postpush_rcsum(skb, skb->data + off, len)
-	 * needed here as it does not change the skb->csum
-	 * result for checksum complete when summing over
-	 * zeroed blocks.
-	 */
-	return 0;
+	if (func == bpf_skb_vlan_push)
+		return true;
+	if (func == bpf_skb_vlan_pop)
+		return true;
+	if (func == bpf_skb_store_bytes)
+		return true;
+	if (func == bpf_l3_csum_replace)
+		return true;
+	if (func == bpf_l4_csum_replace)
+		return true;
+
+	return false;
 }
 
-static int bpf_skb_generic_pop(struct sk_buff *skb, u32 off, u32 len)
+static u64 bpf_skb_get_tunnel_key(u64 r1, u64 r2, u64 size, u64 flags, u64 r5)
 {
-	/* skb_ensure_writable() is not needed here, as we're
-	 * already working on an uncloned skb.
-	 */
-	if (unlikely(!pskb_may_pull(skb, off + len)))
-		return -ENOMEM;
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
+	struct bpf_tunnel_key *to = (struct bpf_tunnel_key *) (long) r2;
+	struct ip_tunnel_info *info = skb_tunnel_info(skb);
+
+	if (unlikely(size != sizeof(struct bpf_tunnel_key) || flags || !info))
+		return -EINVAL;
+	if (ip_tunnel_info_af(info) != AF_INET)
+		return -EINVAL;
 
-	skb_postpull_rcsum(skb, skb->data + off, len);
-	memmove(skb->data + len, skb->data, off);
-	__skb_pull(skb, len);
+	to->tunnel_id = be64_to_cpu(info->key.tun_id);
+	to->remote_ipv4 = be32_to_cpu(info->key.u.ipv4.src);
 
 	return 0;
 }
 
-static int bpf_skb_net_hdr_push(struct sk_buff *skb, u32 off, u32 len)
-{
-	bool trans_same = skb->transport_header == skb->network_header;
-	int ret;
-
-	/* There's no need for __skb_push()/__skb_pull() pair to
-	 * get to the start of the mac header as we're guaranteed
-	 * to always start from here under eBPF.
-	 */
-	ret = bpf_skb_generic_push(skb, off, len);
-	if (likely(!ret)) {
-		skb->mac_header -= len;
-		skb->network_header -= len;
-		if (trans_same)
-			skb->transport_header = skb->network_header;
-	}
-
-	return ret;
-}
-
-static int bpf_skb_net_hdr_pop(struct sk_buff *skb, u32 off, u32 len)
-{
-	bool trans_same = skb->transport_header == skb->network_header;
-	int ret;
-
-	/* Same here, __skb_push()/__skb_pull() pair not needed. */
-	ret = bpf_skb_generic_pop(skb, off, len);
-	if (likely(!ret)) {
-		skb->mac_header += len;
-		skb->network_header += len;
-		if (trans_same)
-			skb->transport_header = skb->network_header;
-	}
-
-	return ret;
-}
-
-static int bpf_skb_proto_4_to_6(struct sk_buff *skb)
-{
-	const u32 len_diff = sizeof(struct ipv6hdr) - sizeof(struct iphdr);
-	u32 off = skb->network_header - skb->mac_header;
-	int ret;
-
-	ret = skb_cow(skb, len_diff);
-	if (unlikely(ret < 0))
-		return ret;
-
-	ret = bpf_skb_net_hdr_push(skb, off, len_diff);
-	if (unlikely(ret < 0))
-		return ret;
-
-	if (skb_is_gso(skb)) {
-		/* SKB_GSO_UDP stays as is. SKB_GSO_TCPV4 needs to
-		 * be changed into SKB_GSO_TCPV6.
-		 */
-		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
-			skb_shinfo(skb)->gso_type &= ~SKB_GSO_TCPV4;
-			skb_shinfo(skb)->gso_type |=  SKB_GSO_TCPV6;
-		}
-
-		/* Due to IPv6 header, MSS needs to be downgraded. */
-		skb_shinfo(skb)->gso_size -= len_diff;
-		/* Header must be checked, and gso_segs recomputed. */
-		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
-		skb_shinfo(skb)->gso_segs = 0;
-	}
-
-	skb->protocol = htons(ETH_P_IPV6);
-	skb_clear_hash(skb);
-
-	return 0;
-}
-
-static int bpf_skb_proto_6_to_4(struct sk_buff *skb)
-{
-	const u32 len_diff = sizeof(struct ipv6hdr) - sizeof(struct iphdr);
-	u32 off = skb->network_header - skb->mac_header;
-	int ret;
-
-	ret = skb_unclone(skb, GFP_ATOMIC);
-	if (unlikely(ret < 0))
-		return ret;
-
-	ret = bpf_skb_net_hdr_pop(skb, off, len_diff);
-	if (unlikely(ret < 0))
-		return ret;
-
-	if (skb_is_gso(skb)) {
-		/* SKB_GSO_UDP stays as is. SKB_GSO_TCPV6 needs to
-		 * be changed into SKB_GSO_TCPV4.
-		 */
-		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6) {
-			skb_shinfo(skb)->gso_type &= ~SKB_GSO_TCPV6;
-			skb_shinfo(skb)->gso_type |=  SKB_GSO_TCPV4;
-		}
-
-		/* Due to IPv4 header, MSS can be upgraded. */
-		skb_shinfo(skb)->gso_size += len_diff;
-		/* Header must be checked, and gso_segs recomputed. */
-		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
-		skb_shinfo(skb)->gso_segs = 0;
-	}
-
-	skb->protocol = htons(ETH_P_IP);
-	skb_clear_hash(skb);
-
-	return 0;
-}
-
-static int bpf_skb_proto_xlat(struct sk_buff *skb, __be16 to_proto)
-{
-	__be16 from_proto = skb->protocol;
-
-	if (from_proto == htons(ETH_P_IP) &&
-	      to_proto == htons(ETH_P_IPV6))
-		return bpf_skb_proto_4_to_6(skb);
-
-	if (from_proto == htons(ETH_P_IPV6) &&
-	      to_proto == htons(ETH_P_IP))
-		return bpf_skb_proto_6_to_4(skb);
-
-	return -ENOTSUPP;
-}
-
-BPF_CALL_3(bpf_skb_change_proto, struct sk_buff *, skb, __be16, proto,
-	   u64, flags)
-{
-	int ret;
-
-	if (unlikely(flags))
-		return -EINVAL;
-
-	/* General idea is that this helper does the basic groundwork
-	 * needed for changing the protocol, and eBPF program fills the
-	 * rest through bpf_skb_store_bytes(), bpf_lX_csum_replace()
-	 * and other helpers, rather than passing a raw buffer here.
-	 *
-	 * The rationale is to keep this minimal and without a need to
-	 * deal with raw packet data. F.e. even if we would pass buffers
-	 * here, the program still needs to call the bpf_lX_csum_replace()
-	 * helpers anyway. Plus, this way we keep also separation of
-	 * concerns, since f.e. bpf_skb_store_bytes() should only take
-	 * care of stores.
-	 *
-	 * Currently, additional options and extension header space are
-	 * not supported, but flags register is reserved so we can adapt
-	 * that. For offloads, we mark packet as dodgy, so that headers
-	 * need to be verified first.
-	 */
-	ret = bpf_skb_proto_xlat(skb, proto);
-	bpf_compute_data_end(skb);
-	return ret;
-}
-
-static const struct bpf_func_proto bpf_skb_change_proto_proto = {
-	.func		= bpf_skb_change_proto,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_ANYTHING,
-	.arg3_type	= ARG_ANYTHING,
-};
-
-BPF_CALL_2(bpf_skb_change_type, struct sk_buff *, skb, u32, pkt_type)
-{
-	/* We only allow a restricted subset to be changed for now. */
-	if (unlikely(!skb_pkt_type_ok(skb->pkt_type) ||
-		     !skb_pkt_type_ok(pkt_type)))
-		return -EINVAL;
-
-	skb->pkt_type = pkt_type;
-	return 0;
-}
-
-static const struct bpf_func_proto bpf_skb_change_type_proto = {
-	.func		= bpf_skb_change_type,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_ANYTHING,
-};
-
-static u32 __bpf_skb_min_len(const struct sk_buff *skb)
-{
-	u32 min_len = skb_network_offset(skb);
-
-	if (skb_transport_header_was_set(skb))
-		min_len = skb_transport_offset(skb);
-	if (skb->ip_summed == CHECKSUM_PARTIAL)
-		min_len = skb_checksum_start_offset(skb) +
-			  skb->csum_offset + sizeof(__sum16);
-	return min_len;
-}
-
-static u32 __bpf_skb_max_len(const struct sk_buff *skb)
-{
-	return skb->dev->mtu + skb->dev->hard_header_len;
-}
-
-static int bpf_skb_grow_rcsum(struct sk_buff *skb, unsigned int new_len)
-{
-	unsigned int old_len = skb->len;
-	int ret;
-
-	ret = __skb_grow_rcsum(skb, new_len);
-	if (!ret)
-		memset(skb->data + old_len, 0, new_len - old_len);
-	return ret;
-}
-
-static int bpf_skb_trim_rcsum(struct sk_buff *skb, unsigned int new_len)
-{
-	return __skb_trim_rcsum(skb, new_len);
-}
-
-BPF_CALL_3(bpf_skb_change_tail, struct sk_buff *, skb, u32, new_len,
-	   u64, flags)
-{
-	u32 max_len = __bpf_skb_max_len(skb);
-	u32 min_len = __bpf_skb_min_len(skb);
-	int ret;
-
-	if (unlikely(flags || new_len > max_len || new_len < min_len))
-		return -EINVAL;
-	if (skb->encapsulation)
-		return -ENOTSUPP;
-
-	/* The basic idea of this helper is that it's performing the
-	 * needed work to either grow or trim an skb, and eBPF program
-	 * rewrites the rest via helpers like bpf_skb_store_bytes(),
-	 * bpf_lX_csum_replace() and others rather than passing a raw
-	 * buffer here. This one is a slow path helper and intended
-	 * for replies with control messages.
-	 *
-	 * Like in bpf_skb_change_proto(), we want to keep this rather
-	 * minimal and without protocol specifics so that we are able
-	 * to separate concerns as in bpf_skb_store_bytes() should only
-	 * be the one responsible for writing buffers.
-	 *
-	 * It's really expected to be a slow path operation here for
-	 * control message replies, so we're implicitly linearizing,
-	 * uncloning and drop offloads from the skb by this.
-	 */
-	ret = __bpf_try_make_writable(skb, skb->len);
-	if (!ret) {
-		if (new_len > skb->len)
-			ret = bpf_skb_grow_rcsum(skb, new_len);
-		else if (new_len < skb->len)
-			ret = bpf_skb_trim_rcsum(skb, new_len);
-		if (!ret && skb_is_gso(skb))
-			skb_gso_reset(skb);
-	}
-
-	bpf_compute_data_end(skb);
-	return ret;
-}
-
-static const struct bpf_func_proto bpf_skb_change_tail_proto = {
-	.func		= bpf_skb_change_tail,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_ANYTHING,
-	.arg3_type	= ARG_ANYTHING,
-};
-
-bool bpf_helper_changes_skb_data(void *func)
-{
-	if (func == bpf_skb_vlan_push ||
-	    func == bpf_skb_vlan_pop ||
-	    func == bpf_skb_store_bytes ||
-	    func == bpf_skb_change_proto ||
-	    func == bpf_skb_change_tail ||
-	    func == bpf_skb_pull_data ||
-	    func == bpf_l3_csum_replace ||
-	    func == bpf_l4_csum_replace)
-		return true;
-
-	return false;
-}
-
-static unsigned long bpf_skb_copy(void *dst_buff, const void *skb,
-				  unsigned long len)
-{
-	void *ptr = skb_header_pointer(skb, 0, len, dst_buff);
-
-	if (unlikely(!ptr))
-		return len;
-	if (ptr != dst_buff)
-		memcpy(dst_buff, ptr, len);
-
-	return 0;
-}
-
-BPF_CALL_5(bpf_skb_event_output, struct sk_buff *, skb, struct bpf_map *, map,
-	   u64, flags, void *, meta, u64, meta_size)
-{
-	u64 skb_size = (flags & BPF_F_CTXLEN_MASK) >> 32;
-
-	if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
-		return -EINVAL;
-	if (unlikely(skb_size > skb->len))
-		return -EFAULT;
-
-	return bpf_event_output(map, flags, meta, meta_size, skb, skb_size,
-				bpf_skb_copy);
-}
-
-static const struct bpf_func_proto bpf_skb_event_output_proto = {
-	.func		= bpf_skb_event_output,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_CONST_MAP_PTR,
-	.arg3_type	= ARG_ANYTHING,
-	.arg4_type	= ARG_PTR_TO_STACK,
-	.arg5_type	= ARG_CONST_STACK_SIZE,
-};
-
-static unsigned short bpf_tunnel_key_af(u64 flags)
-{
-	return flags & BPF_F_TUNINFO_IPV6 ? AF_INET6 : AF_INET;
-}
-
-BPF_CALL_4(bpf_skb_get_tunnel_key, struct sk_buff *, skb, struct bpf_tunnel_key *, to,
-	   u32, size, u64, flags)
-{
-	const struct ip_tunnel_info *info = skb_tunnel_info(skb);
-	u8 compat[sizeof(struct bpf_tunnel_key)];
-	void *to_orig = to;
-	int err;
-
-	if (unlikely(!info || (flags & ~(BPF_F_TUNINFO_IPV6)))) {
-		err = -EINVAL;
-		goto err_clear;
-	}
-	if (ip_tunnel_info_af(info) != bpf_tunnel_key_af(flags)) {
-		err = -EPROTO;
-		goto err_clear;
-	}
-	if (unlikely(size != sizeof(struct bpf_tunnel_key))) {
-		err = -EINVAL;
-		switch (size) {
-		case offsetof(struct bpf_tunnel_key, tunnel_label):
-		case offsetof(struct bpf_tunnel_key, tunnel_ext):
-			goto set_compat;
-		case offsetof(struct bpf_tunnel_key, remote_ipv6[1]):
-			/* Fixup deprecated structure layouts here, so we have
-			 * a common path later on.
-			 */
-			if (ip_tunnel_info_af(info) != AF_INET)
-				goto err_clear;
-set_compat:
-			to = (struct bpf_tunnel_key *)compat;
-			break;
-		default:
-			goto err_clear;
-		}
-	}
-
-	to->tunnel_id = be64_to_cpu(info->key.tun_id);
-	to->tunnel_tos = info->key.tos;
-	to->tunnel_ttl = info->key.ttl;
-
-	if (flags & BPF_F_TUNINFO_IPV6) {
-		memcpy(to->remote_ipv6, &info->key.u.ipv6.src,
-		       sizeof(to->remote_ipv6));
-		to->tunnel_label = be32_to_cpu(info->key.label);
-	} else {
-		to->remote_ipv4 = be32_to_cpu(info->key.u.ipv4.src);
-	}
-
-	if (unlikely(size != sizeof(struct bpf_tunnel_key)))
-		memcpy(to_orig, to, size);
-
-	return 0;
-err_clear:
-	memset(to_orig, 0, size);
-	return err;
-}
-
-static const struct bpf_func_proto bpf_skb_get_tunnel_key_proto = {
+const struct bpf_func_proto bpf_skb_get_tunnel_key_proto = {
 	.func		= bpf_skb_get_tunnel_key,
 	.gpl_only	= false,
 	.ret_type	= RET_INTEGER,
 	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_PTR_TO_RAW_STACK,
+	.arg2_type	= ARG_PTR_TO_STACK,
 	.arg3_type	= ARG_CONST_STACK_SIZE,
 	.arg4_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_3(bpf_skb_get_tunnel_opt, struct sk_buff *, skb, u8 *, to, u32, size)
-{
-	const struct ip_tunnel_info *info = skb_tunnel_info(skb);
-	int err;
-
-	if (unlikely(!info ||
-		     !(info->key.tun_flags & TUNNEL_OPTIONS_PRESENT))) {
-		err = -ENOENT;
-		goto err_clear;
-	}
-	if (unlikely(size < info->options_len)) {
-		err = -ENOMEM;
-		goto err_clear;
-	}
-
-	ip_tunnel_info_opts_get(to, info);
-	if (size > info->options_len)
-		memset(to + info->options_len, 0, size - info->options_len);
-
-	return info->options_len;
-err_clear:
-	memset(to, 0, size);
-	return err;
-}
-
-static const struct bpf_func_proto bpf_skb_get_tunnel_opt_proto = {
-	.func		= bpf_skb_get_tunnel_opt,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_PTR_TO_RAW_STACK,
-	.arg3_type	= ARG_CONST_STACK_SIZE,
-};
-
 static struct metadata_dst __percpu *md_dst;
 
-BPF_CALL_4(bpf_skb_set_tunnel_key, struct sk_buff *, skb,
-	   const struct bpf_tunnel_key *, from, u32, size, u64, flags)
+static u64 bpf_skb_set_tunnel_key(u64 r1, u64 r2, u64 size, u64 flags, u64 r5)
 {
+	struct sk_buff *skb = (struct sk_buff *) (long) r1;
+	struct bpf_tunnel_key *from = (struct bpf_tunnel_key *) (long) r2;
 	struct metadata_dst *md = this_cpu_ptr(md_dst);
-	u8 compat[sizeof(struct bpf_tunnel_key)];
 	struct ip_tunnel_info *info;
 
-	if (unlikely(flags & ~(BPF_F_TUNINFO_IPV6 | BPF_F_ZERO_CSUM_TX |
-			       BPF_F_DONT_FRAGMENT)))
-		return -EINVAL;
-	if (unlikely(size != sizeof(struct bpf_tunnel_key))) {
-		switch (size) {
-		case offsetof(struct bpf_tunnel_key, tunnel_label):
-		case offsetof(struct bpf_tunnel_key, tunnel_ext):
-		case offsetof(struct bpf_tunnel_key, remote_ipv6[1]):
-			/* Fixup deprecated structure layouts here, so we have
-			 * a common path later on.
-			 */
-			memcpy(compat, from, size);
-			memset(compat + size, 0, sizeof(compat) - size);
-			from = (const struct bpf_tunnel_key *) compat;
-			break;
-		default:
-			return -EINVAL;
-		}
-	}
-	if (unlikely((!(flags & BPF_F_TUNINFO_IPV6) && from->tunnel_label) ||
-		     from->tunnel_ext))
+	if (unlikely(size != sizeof(struct bpf_tunnel_key) || flags))
 		return -EINVAL;
 
 	skb_dst_drop(skb);
@@ -2343,31 +1617,14 @@ BPF_CALL_4(bpf_skb_set_tunnel_key, struct sk_buff *, skb,
 
 	info = &md->u.tun_info;
 	info->mode = IP_TUNNEL_INFO_TX;
-
-	info->key.tun_flags = TUNNEL_KEY | TUNNEL_CSUM;
-	if (flags & BPF_F_DONT_FRAGMENT)
-		info->key.tun_flags |= TUNNEL_DONT_FRAGMENT;
-
+	info->key.tun_flags = TUNNEL_KEY;
 	info->key.tun_id = cpu_to_be64(from->tunnel_id);
-	info->key.tos = from->tunnel_tos;
-	info->key.ttl = from->tunnel_ttl;
-
-	if (flags & BPF_F_TUNINFO_IPV6) {
-		info->mode |= IP_TUNNEL_INFO_IPV6;
-		memcpy(&info->key.u.ipv6.dst, from->remote_ipv6,
-		       sizeof(from->remote_ipv6));
-		info->key.label = cpu_to_be32(from->tunnel_label) &
-				  IPV6_FLOWLABEL_MASK;
-	} else {
-		info->key.u.ipv4.dst = cpu_to_be32(from->remote_ipv4);
-		if (flags & BPF_F_ZERO_CSUM_TX)
-			info->key.tun_flags &= ~TUNNEL_CSUM;
-	}
+	info->key.u.ipv4.dst = cpu_to_be32(from->remote_ipv4);
 
 	return 0;
 }
 
-static const struct bpf_func_proto bpf_skb_set_tunnel_key_proto = {
+const struct bpf_func_proto bpf_skb_set_tunnel_key_proto = {
 	.func		= bpf_skb_set_tunnel_key,
 	.gpl_only	= false,
 	.ret_type	= RET_INTEGER,
@@ -2377,145 +1634,19 @@ static const struct bpf_func_proto bpf_skb_set_tunnel_key_proto = {
 	.arg4_type	= ARG_ANYTHING,
 };
 
-BPF_CALL_3(bpf_skb_set_tunnel_opt, struct sk_buff *, skb,
-	   const u8 *, from, u32, size)
-{
-	struct ip_tunnel_info *info = skb_tunnel_info(skb);
-	const struct metadata_dst *md = this_cpu_ptr(md_dst);
-
-	if (unlikely(info != &md->u.tun_info || (size & (sizeof(u32) - 1))))
-		return -EINVAL;
-	if (unlikely(size > IP_TUNNEL_OPTS_MAX))
-		return -ENOMEM;
-
-	ip_tunnel_info_opts_set(info, from, size);
-
-	return 0;
-}
-
-static const struct bpf_func_proto bpf_skb_set_tunnel_opt_proto = {
-	.func		= bpf_skb_set_tunnel_opt,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_PTR_TO_STACK,
-	.arg3_type	= ARG_CONST_STACK_SIZE,
-};
-
-static const struct bpf_func_proto *
-bpf_get_skb_set_tunnel_proto(enum bpf_func_id which)
+static const struct bpf_func_proto *bpf_get_skb_set_tunnel_key_proto(void)
 {
 	if (!md_dst) {
-		/* Race is not possible, since it's called from verifier
-		 * that is holding verifier mutex.
+		/* race is not possible, since it's called from
+		 * verifier that is holding verifier mutex
 		 */
-		md_dst = metadata_dst_alloc_percpu(IP_TUNNEL_OPTS_MAX,
-						   GFP_KERNEL);
+		md_dst = metadata_dst_alloc_percpu(0, GFP_KERNEL);
 		if (!md_dst)
 			return NULL;
 	}
-
-	switch (which) {
-	case BPF_FUNC_skb_set_tunnel_key:
-		return &bpf_skb_set_tunnel_key_proto;
-	case BPF_FUNC_skb_set_tunnel_opt:
-		return &bpf_skb_set_tunnel_opt_proto;
-	default:
-		return NULL;
-	}
-}
-
-BPF_CALL_3(bpf_skb_under_cgroup, struct sk_buff *, skb, struct bpf_map *, map,
-	   u32, idx)
-{
-	struct bpf_array *array = container_of(map, struct bpf_array, map);
-	struct cgroup *cgrp;
-	struct sock *sk;
-
-	sk = skb->sk;
-	if (!sk || !sk_fullsock(sk))
-		return -ENOENT;
-	if (unlikely(idx >= array->map.max_entries))
-		return -E2BIG;
-
-	cgrp = READ_ONCE(array->ptrs[idx]);
-	if (unlikely(!cgrp))
-		return -EAGAIN;
-
-	return sk_under_cgroup_hierarchy(sk, cgrp);
+	return &bpf_skb_set_tunnel_key_proto;
 }
 
-static const struct bpf_func_proto bpf_skb_under_cgroup_proto = {
-	.func		= bpf_skb_under_cgroup,
-	.gpl_only	= false,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_CONST_MAP_PTR,
-	.arg3_type	= ARG_ANYTHING,
-};
-
-static unsigned long bpf_xdp_copy(void *dst_buff, const void *src_buff,
-				  unsigned long off, unsigned long len)
-{
-	memcpy(dst_buff, src_buff + off, len);
-	return 0;
-}
-
-BPF_CALL_5(bpf_xdp_event_output, struct xdp_buff *, xdp, struct bpf_map *, map,
-	   u64, flags, void *, meta, u64, meta_size)
-{
-	u64 xdp_size = (flags & BPF_F_CTXLEN_MASK) >> 32;
-
-	if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
-		return -EINVAL;
-	if (unlikely(xdp_size > (unsigned long)(xdp->data_end - xdp->data)))
-		return -EFAULT;
-
-	return bpf_event_output(map, flags, meta, meta_size, xdp, xdp_size,
-				bpf_xdp_copy);
-}
-
-static const struct bpf_func_proto bpf_xdp_event_output_proto = {
-	.func		= bpf_xdp_event_output,
-	.gpl_only	= true,
-	.ret_type	= RET_INTEGER,
-	.arg1_type	= ARG_PTR_TO_CTX,
-	.arg2_type	= ARG_CONST_MAP_PTR,
-	.arg3_type	= ARG_ANYTHING,
-	.arg4_type	= ARG_PTR_TO_STACK,
-	.arg5_type	= ARG_CONST_STACK_SIZE,
-};
-
-BPF_CALL_1(bpf_get_socket_cookie, struct sk_buff *, skb)
-{
-	return skb->sk ? sock_gen_cookie(skb->sk) : 0;
-}
-
-static const struct bpf_func_proto bpf_get_socket_cookie_proto = {
-	.func           = bpf_get_socket_cookie,
-	.gpl_only       = false,
-	.ret_type       = RET_INTEGER,
-	.arg1_type      = ARG_PTR_TO_CTX,
-};
-
-BPF_CALL_1(bpf_get_socket_uid, struct sk_buff *, skb)
-{
-	struct sock *sk = sk_to_full_sk(skb->sk);
-	kuid_t kuid;
-
-	if (!sk || !sk_fullsock(sk))
-		return overflowuid;
-	kuid = sock_net_uid(sock_net(sk), sk);
-	return from_kuid_munged(sock_net(sk)->user_ns, kuid);
-}
-
-static const struct bpf_func_proto bpf_get_socket_uid_proto = {
-	.func           = bpf_get_socket_uid,
-	.gpl_only       = false,
-	.ret_type       = RET_INTEGER,
-	.arg1_type      = ARG_PTR_TO_CTX,
-};
-
 static const struct bpf_func_proto *
 sk_filter_func_proto(enum bpf_func_id func_id)
 {
@@ -2529,7 +1660,7 @@ sk_filter_func_proto(enum bpf_func_id func_id)
 	case BPF_FUNC_get_prandom_u32:
 		return &bpf_get_prandom_u32_proto;
 	case BPF_FUNC_get_smp_processor_id:
-		return &bpf_get_raw_smp_processor_id_proto;
+		return &bpf_get_smp_processor_id_proto;
 	case BPF_FUNC_tail_call:
 		return &bpf_tail_call_proto;
 	case BPF_FUNC_ktime_get_ns:
@@ -2537,10 +1668,6 @@ sk_filter_func_proto(enum bpf_func_id func_id)
 	case BPF_FUNC_trace_printk:
 		if (capable(CAP_SYS_ADMIN))
 			return bpf_get_trace_printk_proto();
-	case BPF_FUNC_get_socket_cookie:
-		return &bpf_get_socket_cookie_proto;
-	case BPF_FUNC_get_socket_uid:
-		return &bpf_get_socket_uid_proto;
 	default:
 		return NULL;
 	}
@@ -2552,14 +1679,6 @@ tc_cls_act_func_proto(enum bpf_func_id func_id)
 	switch (func_id) {
 	case BPF_FUNC_skb_store_bytes:
 		return &bpf_skb_store_bytes_proto;
-	case BPF_FUNC_skb_load_bytes:
-		return &bpf_skb_load_bytes_proto;
-	case BPF_FUNC_skb_pull_data:
-		return &bpf_skb_pull_data_proto;
-	case BPF_FUNC_csum_diff:
-		return &bpf_csum_diff_proto;
-	case BPF_FUNC_csum_update:
-		return &bpf_csum_update_proto;
 	case BPF_FUNC_l3_csum_replace:
 		return &bpf_l3_csum_replace_proto;
 	case BPF_FUNC_l4_csum_replace:
@@ -2572,56 +1691,14 @@ tc_cls_act_func_proto(enum bpf_func_id func_id)
 		return &bpf_skb_vlan_push_proto;
 	case BPF_FUNC_skb_vlan_pop:
 		return &bpf_skb_vlan_pop_proto;
-	case BPF_FUNC_skb_change_proto:
-		return &bpf_skb_change_proto_proto;
-	case BPF_FUNC_skb_change_type:
-		return &bpf_skb_change_type_proto;
-	case BPF_FUNC_skb_change_tail:
-		return &bpf_skb_change_tail_proto;
 	case BPF_FUNC_skb_get_tunnel_key:
 		return &bpf_skb_get_tunnel_key_proto;
 	case BPF_FUNC_skb_set_tunnel_key:
-		return bpf_get_skb_set_tunnel_proto(func_id);
-	case BPF_FUNC_skb_get_tunnel_opt:
-		return &bpf_skb_get_tunnel_opt_proto;
-	case BPF_FUNC_skb_set_tunnel_opt:
-		return bpf_get_skb_set_tunnel_proto(func_id);
+		return bpf_get_skb_set_tunnel_key_proto();
 	case BPF_FUNC_redirect:
 		return &bpf_redirect_proto;
 	case BPF_FUNC_get_route_realm:
 		return &bpf_get_route_realm_proto;
-	case BPF_FUNC_get_hash_recalc:
-		return &bpf_get_hash_recalc_proto;
-	case BPF_FUNC_set_hash_invalid:
-		return &bpf_set_hash_invalid_proto;
-	case BPF_FUNC_perf_event_output:
-		return &bpf_skb_event_output_proto;
-	case BPF_FUNC_get_smp_processor_id:
-		return &bpf_get_smp_processor_id_proto;
-	case BPF_FUNC_skb_under_cgroup:
-		return &bpf_skb_under_cgroup_proto;
-	default:
-		return sk_filter_func_proto(func_id);
-	}
-}
-
-static const struct bpf_func_proto *
-xdp_func_proto(enum bpf_func_id func_id)
-{
-	switch (func_id) {
-	case BPF_FUNC_perf_event_output:
-		return &bpf_xdp_event_output_proto;
-	default:
-		return sk_filter_func_proto(func_id);
-	}
-}
-
-static const struct bpf_func_proto *
-cg_skb_func_proto(enum bpf_func_id func_id)
-{
-	switch (func_id) {
-	case BPF_FUNC_skb_load_bytes:
-		return &bpf_skb_load_bytes_proto;
 	default:
 		return sk_filter_func_proto(func_id);
 	}
@@ -2629,32 +1706,31 @@ cg_skb_func_proto(enum bpf_func_id func_id)
 
 static bool __is_valid_access(int off, int size, enum bpf_access_type type)
 {
+	/* check bounds */
 	if (off < 0 || off >= sizeof(struct __sk_buff))
 		return false;
-	/* The verifier guarantees that size > 0. */
+
+	/* disallow misaligned access */
 	if (off % size != 0)
 		return false;
-	if (size != sizeof(__u32))
+
+	/* all __sk_buff fields are __u32 */
+	if (size != 4)
 		return false;
 
 	return true;
 }
 
 static bool sk_filter_is_valid_access(int off, int size,
-				      enum bpf_access_type type,
-				      enum bpf_reg_type *reg_type)
+				      enum bpf_access_type type)
 {
-	switch (off) {
-	case offsetof(struct __sk_buff, tc_classid):
-	case offsetof(struct __sk_buff, data):
-	case offsetof(struct __sk_buff, data_end):
+	if (off == offsetof(struct __sk_buff, tc_classid))
 		return false;
-	}
 
 	if (type == BPF_WRITE) {
 		switch (off) {
 		case offsetof(struct __sk_buff, cb[0]) ...
-		     offsetof(struct __sk_buff, cb[4]):
+			offsetof(struct __sk_buff, cb[4]):
 			break;
 		default:
 			return false;
@@ -2664,117 +1740,31 @@ static bool sk_filter_is_valid_access(int off, int size,
 	return __is_valid_access(off, size, type);
 }
 
-static int tc_cls_act_prologue(struct bpf_insn *insn_buf, bool direct_write,
-			       const struct bpf_prog *prog)
-{
-	struct bpf_insn *insn = insn_buf;
-
-	if (!direct_write)
-		return 0;
-
-	/* if (!skb->cloned)
-	 *       goto start;
-	 *
-	 * (Fast-path, otherwise approximation that we might be
-	 *  a clone, do the rest in helper.)
-	 */
-	*insn++ = BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_1, CLONED_OFFSET());
-	*insn++ = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, CLONED_MASK);
-	*insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 7);
-
-	/* ret = bpf_skb_pull_data(skb, 0); */
-	*insn++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
-	*insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_2, BPF_REG_2);
-	*insn++ = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
-			       BPF_FUNC_skb_pull_data);
-	/* if (!ret)
-	 *      goto restore;
-	 * return TC_ACT_SHOT;
-	 */
-	*insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2);
-	*insn++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, TC_ACT_SHOT);
-	*insn++ = BPF_EXIT_INSN();
-
-	/* restore: */
-	*insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
-	/* start: */
-	*insn++ = prog->insnsi[0];
-
-	return insn - insn_buf;
-}
-
 static bool tc_cls_act_is_valid_access(int off, int size,
-				       enum bpf_access_type type,
-				       enum bpf_reg_type *reg_type)
+				       enum bpf_access_type type)
 {
+	if (off == offsetof(struct __sk_buff, tc_classid))
+		return type == BPF_WRITE ? true : false;
+
 	if (type == BPF_WRITE) {
 		switch (off) {
 		case offsetof(struct __sk_buff, mark):
 		case offsetof(struct __sk_buff, tc_index):
 		case offsetof(struct __sk_buff, priority):
 		case offsetof(struct __sk_buff, cb[0]) ...
-		     offsetof(struct __sk_buff, cb[4]):
-		case offsetof(struct __sk_buff, tc_classid):
+			offsetof(struct __sk_buff, cb[4]):
 			break;
 		default:
 			return false;
 		}
 	}
-
-	switch (off) {
-	case offsetof(struct __sk_buff, data):
-		*reg_type = PTR_TO_PACKET;
-		break;
-	case offsetof(struct __sk_buff, data_end):
-		*reg_type = PTR_TO_PACKET_END;
-		break;
-	}
-
 	return __is_valid_access(off, size, type);
 }
 
-static bool __is_valid_xdp_access(int off, int size,
-				  enum bpf_access_type type)
-{
-	if (off < 0 || off >= sizeof(struct xdp_md))
-		return false;
-	if (off % size != 0)
-		return false;
-	if (size != sizeof(__u32))
-		return false;
-
-	return true;
-}
-
-static bool xdp_is_valid_access(int off, int size,
-				enum bpf_access_type type,
-				enum bpf_reg_type *reg_type)
-{
-	if (type == BPF_WRITE)
-		return false;
-
-	switch (off) {
-	case offsetof(struct xdp_md, data):
-		*reg_type = PTR_TO_PACKET;
-		break;
-	case offsetof(struct xdp_md, data_end):
-		*reg_type = PTR_TO_PACKET_END;
-		break;
-	}
-
-	return __is_valid_xdp_access(off, size, type);
-}
-
-void bpf_warn_invalid_xdp_action(u32 act)
-{
-	WARN_ONCE(1, "Illegal XDP return value %u, expect packet loss\n", act);
-}
-EXPORT_SYMBOL_GPL(bpf_warn_invalid_xdp_action);
-
-static u32 sk_filter_convert_ctx_access(enum bpf_access_type type, int dst_reg,
-					int src_reg, int ctx_off,
-					struct bpf_insn *insn_buf,
-					struct bpf_prog *prog)
+static u32 bpf_net_convert_ctx_access(enum bpf_access_type type, int dst_reg,
+				      int src_reg, int ctx_off,
+				      struct bpf_insn *insn_buf,
+				      struct bpf_prog *prog)
 {
 	struct bpf_insn *insn = insn_buf;
 
@@ -2821,7 +1811,7 @@ static u32 sk_filter_convert_ctx_access(enum bpf_access_type type, int dst_reg,
 	case offsetof(struct __sk_buff, ifindex):
 		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);
 
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
+		*insn++ = BPF_LDX_MEM(bytes_to_bpf_size(FIELD_SIZEOF(struct sk_buff, dev)),
 				      dst_reg, src_reg,
 				      offsetof(struct sk_buff, dev));
 		*insn++ = BPF_JMP_IMM(BPF_JEQ, dst_reg, 0, 1);
@@ -2862,7 +1852,7 @@ static u32 sk_filter_convert_ctx_access(enum bpf_access_type type, int dst_reg,
 					  dst_reg, src_reg, insn);
 
 	case offsetof(struct __sk_buff, cb[0]) ...
-	     offsetof(struct __sk_buff, cb[4]):
+		offsetof(struct __sk_buff, cb[4]):
 		BUILD_BUG_ON(FIELD_SIZEOF(struct qdisc_skb_cb, data) < 20);
 
 		prog->cb_access = 1;
@@ -2879,24 +1869,8 @@ static u32 sk_filter_convert_ctx_access(enum bpf_access_type type, int dst_reg,
 		ctx_off -= offsetof(struct __sk_buff, tc_classid);
 		ctx_off += offsetof(struct sk_buff, cb);
 		ctx_off += offsetof(struct qdisc_skb_cb, tc_classid);
-		if (type == BPF_WRITE)
-			*insn++ = BPF_STX_MEM(BPF_H, dst_reg, src_reg, ctx_off);
-		else
-			*insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg, ctx_off);
-		break;
-
-	case offsetof(struct __sk_buff, data):
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, data),
-				      dst_reg, src_reg,
-				      offsetof(struct sk_buff, data));
-		break;
-
-	case offsetof(struct __sk_buff, data_end):
-		ctx_off -= offsetof(struct __sk_buff, data_end);
-		ctx_off += offsetof(struct sk_buff, cb);
-		ctx_off += offsetof(struct bpf_skb_data_end, data_end);
-		*insn++ = BPF_LDX_MEM(BPF_SIZEOF(void *), dst_reg, src_reg,
-				      ctx_off);
+		WARN_ON(type != BPF_WRITE);
+		*insn++ = BPF_STX_MEM(BPF_H, dst_reg, src_reg, ctx_off);
 		break;
 
 	case offsetof(struct __sk_buff, tc_index):
@@ -2922,102 +1896,31 @@ static u32 sk_filter_convert_ctx_access(enum bpf_access_type type, int dst_reg,
 	return insn - insn_buf;
 }
 
-static u32 tc_cls_act_convert_ctx_access(enum bpf_access_type type, int dst_reg,
-					 int src_reg, int ctx_off,
-					 struct bpf_insn *insn_buf,
-					 struct bpf_prog *prog)
-{
-	struct bpf_insn *insn = insn_buf;
-
-	switch (ctx_off) {
-	case offsetof(struct __sk_buff, ifindex):
-		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);
-
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
-				      dst_reg, src_reg,
-				      offsetof(struct sk_buff, dev));
-		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, dst_reg,
-				      offsetof(struct net_device, ifindex));
-		break;
-	default:
-		return sk_filter_convert_ctx_access(type, dst_reg, src_reg,
-						    ctx_off, insn_buf, prog);
-	}
-
-	return insn - insn_buf;
-}
-
-static u32 xdp_convert_ctx_access(enum bpf_access_type type, int dst_reg,
-				  int src_reg, int ctx_off,
-				  struct bpf_insn *insn_buf,
-				  struct bpf_prog *prog)
-{
-	struct bpf_insn *insn = insn_buf;
-
-	switch (ctx_off) {
-	case offsetof(struct xdp_md, data):
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data),
-				      dst_reg, src_reg,
-				      offsetof(struct xdp_buff, data));
-		break;
-	case offsetof(struct xdp_md, data_end):
-		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data_end),
-				      dst_reg, src_reg,
-				      offsetof(struct xdp_buff, data_end));
-		break;
-	}
-
-	return insn - insn_buf;
-}
-
 static const struct bpf_verifier_ops sk_filter_ops = {
-	.get_func_proto		= sk_filter_func_proto,
-	.is_valid_access	= sk_filter_is_valid_access,
-	.convert_ctx_access	= sk_filter_convert_ctx_access,
+	.get_func_proto = sk_filter_func_proto,
+	.is_valid_access = sk_filter_is_valid_access,
+	.convert_ctx_access = bpf_net_convert_ctx_access,
 };
 
 static const struct bpf_verifier_ops tc_cls_act_ops = {
-	.get_func_proto		= tc_cls_act_func_proto,
-	.is_valid_access	= tc_cls_act_is_valid_access,
-	.convert_ctx_access	= tc_cls_act_convert_ctx_access,
-	.gen_prologue		= tc_cls_act_prologue,
-};
-
-static const struct bpf_verifier_ops xdp_ops = {
-	.get_func_proto		= xdp_func_proto,
-	.is_valid_access	= xdp_is_valid_access,
-	.convert_ctx_access	= xdp_convert_ctx_access,
-};
-
-static const struct bpf_verifier_ops cg_skb_ops = {
-	.get_func_proto		= cg_skb_func_proto,
-	.is_valid_access	= sk_filter_is_valid_access,
-	.convert_ctx_access	= sk_filter_convert_ctx_access,
+	.get_func_proto = tc_cls_act_func_proto,
+	.is_valid_access = tc_cls_act_is_valid_access,
+	.convert_ctx_access = bpf_net_convert_ctx_access,
 };
 
 static struct bpf_prog_type_list sk_filter_type __read_mostly = {
-	.ops	= &sk_filter_ops,
-	.type	= BPF_PROG_TYPE_SOCKET_FILTER,
+	.ops = &sk_filter_ops,
+	.type = BPF_PROG_TYPE_SOCKET_FILTER,
 };
 
 static struct bpf_prog_type_list sched_cls_type __read_mostly = {
-	.ops	= &tc_cls_act_ops,
-	.type	= BPF_PROG_TYPE_SCHED_CLS,
+	.ops = &tc_cls_act_ops,
+	.type = BPF_PROG_TYPE_SCHED_CLS,
 };
 
 static struct bpf_prog_type_list sched_act_type __read_mostly = {
-	.ops	= &tc_cls_act_ops,
-	.type	= BPF_PROG_TYPE_SCHED_ACT,
-};
-
-static struct bpf_prog_type_list xdp_type __read_mostly = {
-	.ops	= &xdp_ops,
-	.type	= BPF_PROG_TYPE_XDP,
-};
-
-static struct bpf_prog_type_list cg_skb_type __read_mostly = {
-	.ops	= &cg_skb_ops,
-	.type	= BPF_PROG_TYPE_CGROUP_SKB,
+	.ops = &tc_cls_act_ops,
+	.type = BPF_PROG_TYPE_SCHED_ACT,
 };
 
 static int __init register_sk_filter_ops(void)
@@ -3025,14 +1928,12 @@ static int __init register_sk_filter_ops(void)
 	bpf_register_prog_type(&sk_filter_type);
 	bpf_register_prog_type(&sched_cls_type);
 	bpf_register_prog_type(&sched_act_type);
-	bpf_register_prog_type(&xdp_type);
-	bpf_register_prog_type(&cg_skb_type);
 
 	return 0;
 }
 late_initcall(register_sk_filter_ops);
 
-int sk_detach_filter(struct sock *sk)
+int __sk_detach_filter(struct sock *sk, bool locked)
 {
 	int ret = -ENOENT;
 	struct sk_filter *filter;
@@ -3040,8 +1941,7 @@ int sk_detach_filter(struct sock *sk)
 	if (sock_flag(sk, SOCK_FILTER_LOCKED))
 		return -EPERM;
 
-	filter = rcu_dereference_protected(sk->sk_filter,
-					   lockdep_sock_is_held(sk));
+	filter = rcu_dereference_protected(sk->sk_filter, locked);
 	if (filter) {
 		RCU_INIT_POINTER(sk->sk_filter, NULL);
 		sk_filter_uncharge(sk, filter);
@@ -3050,7 +1950,12 @@ int sk_detach_filter(struct sock *sk)
 
 	return ret;
 }
-EXPORT_SYMBOL_GPL(sk_detach_filter);
+EXPORT_SYMBOL_GPL(__sk_detach_filter);
+
+int sk_detach_filter(struct sock *sk)
+{
+	return __sk_detach_filter(sk, sock_owned_by_user(sk));
+}
 
 int sk_get_filter(struct sock *sk, struct sock_filter __user *ubuf,
 		  unsigned int len)
@@ -3061,7 +1966,7 @@ int sk_get_filter(struct sock *sk, struct sock_filter __user *ubuf,
 
 	lock_sock(sk);
 	filter = rcu_dereference_protected(sk->sk_filter,
-					   lockdep_sock_is_held(sk));
+					   sock_owned_by_user(sk));
 	if (!filter)
 		goto out;
 
diff --git a/net/core/net_namespace.c b/net/core/net_namespace.c
index 02fa8699f0c4..01bfe28b20a1 100644
--- a/net/core/net_namespace.c
+++ b/net/core/net_namespace.c
@@ -1019,17 +1019,11 @@ static int netns_install(struct nsproxy *nsproxy, struct ns_common *ns)
 	return 0;
 }
 
-static struct user_namespace *netns_owner(struct ns_common *ns)
-{
-	return to_net_ns(ns)->user_ns;
-}
-
 const struct proc_ns_operations netns_operations = {
 	.name		= "net",
 	.type		= CLONE_NEWNET,
 	.get		= netns_get,
 	.put		= netns_put,
 	.install	= netns_install,
-	.owner		= netns_owner,
 };
 #endif
diff --git a/net/core/netclassid_cgroup.c b/net/core/netclassid_cgroup.c
index 0260c84ed83c..d9ee8d08a3a6 100644
--- a/net/core/netclassid_cgroup.c
+++ b/net/core/netclassid_cgroup.c
@@ -61,12 +61,9 @@ static int update_classid_sock(const void *v, struct file *file, unsigned n)
 	int err;
 	struct socket *sock = sock_from_file(file, &err);
 
-	if (sock) {
-		spin_lock(&cgroup_sk_update_lock);
-		sock_cgroup_set_classid(&sock->sk->sk_cgrp_data,
-					(unsigned long)v);
-		spin_unlock(&cgroup_sk_update_lock);
-	}
+	if (sock)
+		sock->sk->sk_classid = (u32)(unsigned long)v;
+
 	return 0;
 }
 
@@ -103,8 +100,6 @@ static int write_classid(struct cgroup_subsys_state *css, struct cftype *cft,
 {
 	struct cgroup_cls_state *cs = css_cls_state(css);
 
-	cgroup_sk_alloc_disable();
-
 	cs->classid = (u32)value;
 
 	update_classid(css, (void *)(unsigned long)cs->classid);
diff --git a/net/core/netprio_cgroup.c b/net/core/netprio_cgroup.c
index 3c1d9a1a5f7d..40fd09fe06ae 100644
--- a/net/core/netprio_cgroup.c
+++ b/net/core/netprio_cgroup.c
@@ -27,12 +27,6 @@
 
 #include <linux/fdtable.h>
 
-/*
- * netprio allocates per-net_device priomap array which is indexed by
- * css->id.  Limiting css ID to 16bits doesn't lose anything.
- */
-#define NETPRIO_ID_MAX		USHRT_MAX
-
 #define PRIOMAP_MIN_SZ		128
 
 /*
@@ -150,9 +144,6 @@ static int cgrp_css_online(struct cgroup_subsys_state *css)
 	struct net_device *dev;
 	int ret = 0;
 
-	if (css->id > NETPRIO_ID_MAX)
-		return -ENOSPC;
-
 	if (!parent_css)
 		return 0;
 
@@ -209,8 +200,6 @@ static ssize_t write_priomap(struct kernfs_open_file *of,
 	if (!dev)
 		return -ENODEV;
 
-	cgroup_sk_alloc_disable();
-
 	rtnl_lock();
 
 	ret = netprio_set_prio(of_css(of), dev, prio);
@@ -224,12 +213,8 @@ static int update_netprio(const void *v, struct file *file, unsigned n)
 {
 	int err;
 	struct socket *sock = sock_from_file(file, &err);
-	if (sock) {
-		spin_lock(&cgroup_sk_update_lock);
-		sock_cgroup_set_prioidx(&sock->sk->sk_cgrp_data,
-					(unsigned long)v);
-		spin_unlock(&cgroup_sk_update_lock);
-	}
+	if (sock)
+		sock->sk->sk_cgrp_prioidx = (u32)(unsigned long)v;
 	return 0;
 }
 
@@ -238,8 +223,6 @@ static void net_prio_attach(struct cgroup_taskset *tset)
 	struct task_struct *p;
 	struct cgroup_subsys_state *css;
 
-	cgroup_sk_alloc_disable();
-
 	cgroup_taskset_for_each(p, css, tset) {
 		void *v = (void *)(unsigned long)css->cgroup->id;
 
diff --git a/net/core/scm.c b/net/core/scm.c
index 2696aefdc148..dce0acb929f1 100644
--- a/net/core/scm.c
+++ b/net/core/scm.c
@@ -295,8 +295,8 @@ void scm_detach_fds(struct msghdr *msg, struct scm_cookie *scm)
 		/* Bump the usage count and install the file. */
 		sock = sock_from_file(fp[i], &err);
 		if (sock) {
-			sock_update_netprioidx(&sock->sk->sk_cgrp_data);
-			sock_update_classid(&sock->sk->sk_cgrp_data);
+			sock_update_netprioidx(sock->sk);
+			sock_update_classid(sock->sk);
 		}
 		fd_install(new_fd, get_file(fp[i]));
 	}
diff --git a/net/core/sock.c b/net/core/sock.c
index 7011e60e4a4c..ffa103957631 100644
--- a/net/core/sock.c
+++ b/net/core/sock.c
@@ -134,7 +134,6 @@
 #include <linux/sock_diag.h>
 
 #include <linux/filter.h>
-#include <net/sock_reuseport.h>
 
 #include <trace/events/sock.h>
 
@@ -935,32 +934,6 @@ set_rcvbuf:
 		}
 		break;
 
-	case SO_ATTACH_REUSEPORT_CBPF:
-		ret = -EINVAL;
-		if (optlen == sizeof(struct sock_fprog)) {
-			struct sock_fprog fprog;
-
-			ret = -EFAULT;
-			if (copy_from_user(&fprog, optval, sizeof(fprog)))
-				break;
-
-			ret = sk_reuseport_attach_filter(&fprog, sk);
-		}
-		break;
-
-	case SO_ATTACH_REUSEPORT_EBPF:
-		ret = -EINVAL;
-		if (optlen == sizeof(u32)) {
-			u32 ufd;
-
-			ret = -EFAULT;
-			if (copy_from_user(&ufd, optval, sizeof(ufd)))
-				break;
-
-			ret = sk_reuseport_attach_bpf(ufd, sk);
-		}
-		break;
-
 	case SO_DETACH_FILTER:
 		ret = sk_detach_filter(sk);
 		break;
@@ -1416,7 +1389,6 @@ static void sk_prot_free(struct proto *prot, struct sock *sk)
 	owner = prot->owner;
 	slab = prot->slab;
 
-	cgroup_sk_free(&sk->sk_cgrp_data);
 	security_sk_free(sk);
 	if (slab != NULL)
 		kmem_cache_free(slab, sk);
@@ -1425,6 +1397,17 @@ static void sk_prot_free(struct proto *prot, struct sock *sk)
 	module_put(owner);
 }
 
+#if IS_ENABLED(CONFIG_CGROUP_NET_PRIO)
+void sock_update_netprioidx(struct sock *sk)
+{
+	if (in_interrupt())
+		return;
+
+	sk->sk_cgrp_prioidx = task_netprioidx(current);
+}
+EXPORT_SYMBOL_GPL(sock_update_netprioidx);
+#endif
+
 /**
  *	sk_alloc - All socket objects are allocated here
  *	@net: the applicable net namespace
@@ -1453,9 +1436,8 @@ struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
 		sock_net_set(sk, net);
 		atomic_set(&sk->sk_wmem_alloc, 1);
 
-		cgroup_sk_alloc(&sk->sk_cgrp_data);
-		sock_update_classid(&sk->sk_cgrp_data);
-		sock_update_netprioidx(&sk->sk_cgrp_data);
+		sock_update_classid(sk);
+		sock_update_netprioidx(sk);
 		sk_tx_queue_clear(sk);
 	}
 
@@ -1480,8 +1462,6 @@ static void __sk_destruct(struct rcu_head *head)
 		sk_filter_uncharge(sk, filter);
 		RCU_INIT_POINTER(sk->sk_filter, NULL);
 	}
-	if (rcu_access_pointer(sk->sk_reuseport_cb))
-		reuseport_detach_sock(sk);
 
 	sock_disable_timestamp(sk, SK_FLAGS_TIMESTAMP);
 
@@ -1587,7 +1567,6 @@ struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority)
 		newsk->sk_userlocks	= sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;
 
 		sock_reset_flag(newsk, SOCK_DONE);
-		cgroup_sk_clone(&newsk->sk_cgrp_data);
 		skb_queue_head_init(&newsk->sk_error_queue);
 
 		filter = rcu_dereference_protected(newsk->sk_filter, 1);
@@ -1619,9 +1598,6 @@ struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority)
 		newsk->sk_priority = 0;
 		newsk->sk_incoming_cpu = raw_smp_processor_id();
 		atomic64_set(&newsk->sk_cookie, 0);
-
-		cgroup_sk_alloc(&newsk->sk_cgrp_data);
-
 		/*
 		 * Before updating sk_refcnt, we must commit prior changes to memory
 		 * (Documentation/RCU/rculist_nulls.txt for details)
diff --git a/net/core/sock_diag.c b/net/core/sock_diag.c
index e25c72918b96..9653798da293 100644
--- a/net/core/sock_diag.c
+++ b/net/core/sock_diag.c
@@ -19,7 +19,7 @@ static int (*inet_rcv_compat)(struct sk_buff *skb, struct nlmsghdr *nlh);
 static DEFINE_MUTEX(sock_diag_table_mutex);
 static struct workqueue_struct *broadcast_wq;
 
-u64 sock_gen_cookie(struct sock *sk)
+static u64 sock_gen_cookie(struct sock *sk)
 {
 	while (1) {
 		u64 res = atomic64_read(&sk->sk_cookie);
diff --git a/net/core/sock_reuseport.c b/net/core/sock_reuseport.c
deleted file mode 100644
index ae0969c0fc2e..000000000000
--- a/net/core/sock_reuseport.c
+++ /dev/null
@@ -1,251 +0,0 @@
-/*
- * To speed up listener socket lookup, create an array to store all sockets
- * listening on the same port.  This allows a decision to be made after finding
- * the first socket.  An optional BPF program can also be configured for
- * selecting the socket index from the array of available sockets.
- */
-
-#include <net/sock_reuseport.h>
-#include <linux/bpf.h>
-#include <linux/rcupdate.h>
-
-#define INIT_SOCKS 128
-
-static DEFINE_SPINLOCK(reuseport_lock);
-
-static struct sock_reuseport *__reuseport_alloc(u16 max_socks)
-{
-	size_t size = sizeof(struct sock_reuseport) +
-		      sizeof(struct sock *) * max_socks;
-	struct sock_reuseport *reuse = kzalloc(size, GFP_ATOMIC);
-
-	if (!reuse)
-		return NULL;
-
-	reuse->max_socks = max_socks;
-
-	RCU_INIT_POINTER(reuse->prog, NULL);
-	return reuse;
-}
-
-int reuseport_alloc(struct sock *sk)
-{
-	struct sock_reuseport *reuse;
-
-	/* bh lock used since this function call may precede hlist lock in
-	 * soft irq of receive path or setsockopt from process context
-	 */
-	spin_lock_bh(&reuseport_lock);
-	WARN_ONCE(rcu_dereference_protected(sk->sk_reuseport_cb,
-					    lockdep_is_held(&reuseport_lock)),
-		  "multiple allocations for the same socket");
-	reuse = __reuseport_alloc(INIT_SOCKS);
-	if (!reuse) {
-		spin_unlock_bh(&reuseport_lock);
-		return -ENOMEM;
-	}
-
-	reuse->socks[0] = sk;
-	reuse->num_socks = 1;
-	rcu_assign_pointer(sk->sk_reuseport_cb, reuse);
-
-	spin_unlock_bh(&reuseport_lock);
-
-	return 0;
-}
-EXPORT_SYMBOL(reuseport_alloc);
-
-static struct sock_reuseport *reuseport_grow(struct sock_reuseport *reuse)
-{
-	struct sock_reuseport *more_reuse;
-	u32 more_socks_size, i;
-
-	more_socks_size = reuse->max_socks * 2U;
-	if (more_socks_size > U16_MAX)
-		return NULL;
-
-	more_reuse = __reuseport_alloc(more_socks_size);
-	if (!more_reuse)
-		return NULL;
-
-	more_reuse->max_socks = more_socks_size;
-	more_reuse->num_socks = reuse->num_socks;
-	more_reuse->prog = reuse->prog;
-
-	memcpy(more_reuse->socks, reuse->socks,
-	       reuse->num_socks * sizeof(struct sock *));
-
-	for (i = 0; i < reuse->num_socks; ++i)
-		rcu_assign_pointer(reuse->socks[i]->sk_reuseport_cb,
-				   more_reuse);
-
-	/* Note: we use kfree_rcu here instead of reuseport_free_rcu so
-	 * that reuse and more_reuse can temporarily share a reference
-	 * to prog.
-	 */
-	kfree_rcu(reuse, rcu);
-	return more_reuse;
-}
-
-/**
- *  reuseport_add_sock - Add a socket to the reuseport group of another.
- *  @sk:  New socket to add to the group.
- *  @sk2: Socket belonging to the existing reuseport group.
- *  May return ENOMEM and not add socket to group under memory pressure.
- */
-int reuseport_add_sock(struct sock *sk, const struct sock *sk2)
-{
-	struct sock_reuseport *reuse;
-
-	spin_lock_bh(&reuseport_lock);
-	reuse = rcu_dereference_protected(sk2->sk_reuseport_cb,
-					  lockdep_is_held(&reuseport_lock)),
-	WARN_ONCE(rcu_dereference_protected(sk->sk_reuseport_cb,
-					    lockdep_is_held(&reuseport_lock)),
-		  "socket already in reuseport group");
-
-	if (reuse->num_socks == reuse->max_socks) {
-		reuse = reuseport_grow(reuse);
-		if (!reuse) {
-			spin_unlock_bh(&reuseport_lock);
-			return -ENOMEM;
-		}
-	}
-
-	reuse->socks[reuse->num_socks] = sk;
-	/* paired with smp_rmb() in reuseport_select_sock() */
-	smp_wmb();
-	reuse->num_socks++;
-	rcu_assign_pointer(sk->sk_reuseport_cb, reuse);
-
-	spin_unlock_bh(&reuseport_lock);
-
-	return 0;
-}
-EXPORT_SYMBOL(reuseport_add_sock);
-
-static void reuseport_free_rcu(struct rcu_head *head)
-{
-	struct sock_reuseport *reuse;
-
-	reuse = container_of(head, struct sock_reuseport, rcu);
-	if (reuse->prog)
-		bpf_prog_destroy(reuse->prog);
-	kfree(reuse);
-}
-
-void reuseport_detach_sock(struct sock *sk)
-{
-	struct sock_reuseport *reuse;
-	int i;
-
-	spin_lock_bh(&reuseport_lock);
-	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
-					  lockdep_is_held(&reuseport_lock));
-	rcu_assign_pointer(sk->sk_reuseport_cb, NULL);
-
-	for (i = 0; i < reuse->num_socks; i++) {
-		if (reuse->socks[i] == sk) {
-			reuse->socks[i] = reuse->socks[reuse->num_socks - 1];
-			reuse->num_socks--;
-			if (reuse->num_socks == 0)
-				call_rcu(&reuse->rcu, reuseport_free_rcu);
-			break;
-		}
-	}
-	spin_unlock_bh(&reuseport_lock);
-}
-EXPORT_SYMBOL(reuseport_detach_sock);
-
-static struct sock *run_bpf(struct sock_reuseport *reuse, u16 socks,
-			    struct bpf_prog *prog, struct sk_buff *skb,
-			    int hdr_len)
-{
-	struct sk_buff *nskb = NULL;
-	u32 index;
-
-	if (skb_shared(skb)) {
-		nskb = skb_clone(skb, GFP_ATOMIC);
-		if (!nskb)
-			return NULL;
-		skb = nskb;
-	}
-
-	/* temporarily advance data past protocol header */
-	if (!pskb_pull(skb, hdr_len)) {
-		consume_skb(nskb);
-		return NULL;
-	}
-	index = bpf_prog_run_save_cb(prog, skb);
-	__skb_push(skb, hdr_len);
-
-	consume_skb(nskb);
-
-	if (index >= socks)
-		return NULL;
-
-	return reuse->socks[index];
-}
-
-/**
- *  reuseport_select_sock - Select a socket from an SO_REUSEPORT group.
- *  @sk: First socket in the group.
- *  @hash: When no BPF filter is available, use this hash to select.
- *  @skb: skb to run through BPF filter.
- *  @hdr_len: BPF filter expects skb data pointer at payload data.  If
- *    the skb does not yet point at the payload, this parameter represents
- *    how far the pointer needs to advance to reach the payload.
- *  Returns a socket that should receive the packet (or NULL on error).
- */
-struct sock *reuseport_select_sock(struct sock *sk,
-				   u32 hash,
-				   struct sk_buff *skb,
-				   int hdr_len)
-{
-	struct sock_reuseport *reuse;
-	struct bpf_prog *prog;
-	struct sock *sk2 = NULL;
-	u16 socks;
-
-	rcu_read_lock();
-	reuse = rcu_dereference(sk->sk_reuseport_cb);
-
-	/* if memory allocation failed or add call is not yet complete */
-	if (!reuse)
-		goto out;
-
-	prog = rcu_dereference(reuse->prog);
-	socks = READ_ONCE(reuse->num_socks);
-	if (likely(socks)) {
-		/* paired with smp_wmb() in reuseport_add_sock() */
-		smp_rmb();
-
-		if (prog && skb)
-			sk2 = run_bpf(reuse, socks, prog, skb, hdr_len);
-		else
-			sk2 = reuse->socks[reciprocal_scale(hash, socks)];
-	}
-
-out:
-	rcu_read_unlock();
-	return sk2;
-}
-EXPORT_SYMBOL(reuseport_select_sock);
-
-struct bpf_prog *
-reuseport_attach_prog(struct sock *sk, struct bpf_prog *prog)
-{
-	struct sock_reuseport *reuse;
-	struct bpf_prog *old_prog;
-
-	spin_lock_bh(&reuseport_lock);
-	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
-					  lockdep_is_held(&reuseport_lock));
-	old_prog = rcu_dereference_protected(reuse->prog,
-					     lockdep_is_held(&reuseport_lock));
-	rcu_assign_pointer(reuse->prog, prog);
-	spin_unlock_bh(&reuseport_lock);
-
-	return old_prog;
-}
-EXPORT_SYMBOL(reuseport_attach_prog);
diff --git a/net/core/sysctl_net_core.c b/net/core/sysctl_net_core.c
index a6fc82704f0c..32898247d8bf 100644
--- a/net/core/sysctl_net_core.c
+++ b/net/core/sysctl_net_core.c
@@ -24,12 +24,9 @@
 
 static int zero = 0;
 static int one = 1;
-static int two __maybe_unused = 2;
 static int min_sndbuf = SOCK_MIN_SNDBUF;
 static int min_rcvbuf = SOCK_MIN_RCVBUF;
 static int max_skb_frags = MAX_SKB_FRAGS;
-static long long_one __maybe_unused = 1;
-static long long_max __maybe_unused = LONG_MAX;
 
 static int net_msg_warn;	/* Unused, but still a sysctl */
 
@@ -234,50 +231,6 @@ static int proc_do_rss_key(struct ctl_table *table, int write,
 	return proc_dostring(&fake_table, write, buffer, lenp, ppos);
 }
 
-#ifdef CONFIG_BPF_JIT
-static int proc_dointvec_minmax_bpf_enable(struct ctl_table *table, int write,
-					   void __user *buffer, size_t *lenp,
-					   loff_t *ppos)
-{
-	int ret, jit_enable = *(int *)table->data;
-	struct ctl_table tmp = *table;
-
-	if (write && !capable(CAP_SYS_ADMIN))
-		return -EPERM;
-
-	tmp.data = &jit_enable;
-	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
-	if (write && !ret) {
-		*(int *)table->data = jit_enable;
-		if (jit_enable == 2)
-			pr_warn("bpf_jit_enable = 2 was set! NEVER use this in production, only for JIT debugging!\n");
-	}
-	return ret;
-}
-
-static int
-proc_dointvec_minmax_bpf_restricted(struct ctl_table *table, int write,
-				    void __user *buffer, size_t *lenp,
-				    loff_t *ppos)
-{
-	if (!capable(CAP_SYS_ADMIN))
-		return -EPERM;
-
-	return proc_dointvec_minmax(table, write, buffer, lenp, ppos);
-}
-
-static int
-proc_dolongvec_minmax_bpf_restricted(struct ctl_table *table, int write,
-				     void __user *buffer, size_t *lenp,
-				     loff_t *ppos)
-{
-	if (!capable(CAP_SYS_ADMIN))
-		return -EPERM;
-
-	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
-}
-#endif
-
 static struct ctl_table net_core_table[] = {
 #ifdef CONFIG_NET
 	{
@@ -339,34 +292,13 @@ static struct ctl_table net_core_table[] = {
 		.data		= &bpf_jit_enable,
 		.maxlen		= sizeof(int),
 		.mode		= 0644,
-		.proc_handler	= proc_dointvec_minmax_bpf_enable,
-# ifdef CONFIG_BPF_JIT_ALWAYS_ON
+#ifndef CONFIG_BPF_JIT_ALWAYS_ON
+		.proc_handler	= proc_dointvec
+#else
+		.proc_handler	= proc_dointvec_minmax,
 		.extra1		= &one,
 		.extra2		= &one,
-# else
-		.extra1		= &zero,
-		.extra2		= &two,
-# endif
-	},
-# ifdef CONFIG_HAVE_EBPF_JIT
-	{
-		.procname	= "bpf_jit_harden",
-		.data		= &bpf_jit_harden,
-		.maxlen		= sizeof(int),
-		.mode		= 0600,
-		.proc_handler	= proc_dointvec_minmax_bpf_restricted,
-		.extra1		= &zero,
-		.extra2		= &two,
-	},
-# endif
-	{
-		.procname	= "bpf_jit_limit",
-		.data		= &bpf_jit_limit,
-		.maxlen		= sizeof(long),
-		.mode		= 0600,
-		.proc_handler	= proc_dolongvec_minmax_bpf_restricted,
-		.extra1		= &long_one,
-		.extra2		= &long_max,
+#endif
 	},
 #endif
 	{
diff --git a/net/ipv4/ip_tunnel_core.c b/net/ipv4/ip_tunnel_core.c
index 4d64aa76d285..4916d1857b75 100644
--- a/net/ipv4/ip_tunnel_core.c
+++ b/net/ipv4/ip_tunnel_core.c
@@ -407,12 +407,6 @@ static const struct lwtunnel_encap_ops ip6_tun_lwt_ops = {
 
 void __init ip_tunnel_core_init(void)
 {
-	/* If you land here, make sure whether increasing ip_tunnel_info's
-	 * options_len is a reasonable choice with its usage in front ends
-	 * (f.e., it's part of flow keys, etc).
-	 */
-	BUILD_BUG_ON(IP_TUNNEL_OPTS_MAX != 255);
-
 	lwtunnel_encap_add_ops(&ip_tun_lwt_ops, LWTUNNEL_ENCAP_IP);
 	lwtunnel_encap_add_ops(&ip6_tun_lwt_ops, LWTUNNEL_ENCAP_IP6);
 }
diff --git a/net/ipv4/udp.c b/net/ipv4/udp.c
index 0a0d44c53373..3f805e0b0561 100644
--- a/net/ipv4/udp.c
+++ b/net/ipv4/udp.c
@@ -113,7 +113,6 @@
 #include <trace/events/skb.h>
 #include <net/busy_poll.h>
 #include "udp_impl.h"
-#include <net/sock_reuseport.h>
 
 struct udp_table udp_table __read_mostly;
 EXPORT_SYMBOL(udp_table);
@@ -138,8 +137,7 @@ static int udp_lib_lport_inuse(struct net *net, __u16 num,
 			       unsigned long *bitmap,
 			       struct sock *sk,
 			       int (*saddr_comp)(const struct sock *sk1,
-						 const struct sock *sk2,
-						 bool match_wildcard),
+						 const struct sock *sk2),
 			       unsigned int log)
 {
 	struct sock *sk2;
@@ -154,9 +152,8 @@ static int udp_lib_lport_inuse(struct net *net, __u16 num,
 		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
 		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
 		    (!sk2->sk_reuseport || !sk->sk_reuseport ||
-		     rcu_access_pointer(sk->sk_reuseport_cb) ||
 		     !uid_eq(uid, sock_i_uid(sk2))) &&
-		    saddr_comp(sk, sk2, true)) {
+		    saddr_comp(sk, sk2)) {
 			if (!bitmap)
 				return 1;
 			__set_bit(udp_sk(sk2)->udp_port_hash >> log, bitmap);
@@ -173,8 +170,7 @@ static int udp_lib_lport_inuse2(struct net *net, __u16 num,
 				struct udp_hslot *hslot2,
 				struct sock *sk,
 				int (*saddr_comp)(const struct sock *sk1,
-						  const struct sock *sk2,
-						  bool match_wildcard))
+						  const struct sock *sk2))
 {
 	struct sock *sk2;
 	struct hlist_nulls_node *node;
@@ -190,9 +186,8 @@ static int udp_lib_lport_inuse2(struct net *net, __u16 num,
 		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
 		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
 		    (!sk2->sk_reuseport || !sk->sk_reuseport ||
-		     rcu_access_pointer(sk->sk_reuseport_cb) ||
 		     !uid_eq(uid, sock_i_uid(sk2))) &&
-		    saddr_comp(sk, sk2, true)) {
+		    saddr_comp(sk, sk2)) {
 			res = 1;
 			break;
 		}
@@ -201,35 +196,6 @@ static int udp_lib_lport_inuse2(struct net *net, __u16 num,
 	return res;
 }
 
-static int udp_reuseport_add_sock(struct sock *sk, struct udp_hslot *hslot,
-				  int (*saddr_same)(const struct sock *sk1,
-						    const struct sock *sk2,
-						    bool match_wildcard))
-{
-	struct net *net = sock_net(sk);
-	struct hlist_nulls_node *node;
-	kuid_t uid = sock_i_uid(sk);
-	struct sock *sk2;
-
-	sk_nulls_for_each(sk2, node, &hslot->head) {
-		if (net_eq(sock_net(sk2), net) &&
-		    sk2 != sk &&
-		    sk2->sk_family == sk->sk_family &&
-		    ipv6_only_sock(sk2) == ipv6_only_sock(sk) &&
-		    (udp_sk(sk2)->udp_port_hash == udp_sk(sk)->udp_port_hash) &&
-		    (sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
-		    sk2->sk_reuseport && uid_eq(uid, sock_i_uid(sk2)) &&
-		    (*saddr_same)(sk, sk2, false)) {
-			return reuseport_add_sock(sk, sk2);
-		}
-	}
-
-	/* Initial allocation may have already happened via setsockopt */
-	if (!rcu_access_pointer(sk->sk_reuseport_cb))
-		return reuseport_alloc(sk);
-	return 0;
-}
-
 /**
  *  udp_lib_get_port  -  UDP/-Lite port lookup for IPv4 and IPv6
  *
@@ -241,8 +207,7 @@ static int udp_reuseport_add_sock(struct sock *sk, struct udp_hslot *hslot,
  */
 int udp_lib_get_port(struct sock *sk, unsigned short snum,
 		     int (*saddr_comp)(const struct sock *sk1,
-				       const struct sock *sk2,
-				       bool match_wildcard),
+				       const struct sock *sk2),
 		     unsigned int hash2_nulladdr)
 {
 	struct udp_hslot *hslot, *hslot2;
@@ -330,14 +295,6 @@ found:
 	udp_sk(sk)->udp_port_hash = snum;
 	udp_sk(sk)->udp_portaddr_hash ^= snum;
 	if (sk_unhashed(sk)) {
-		if (sk->sk_reuseport &&
-		    udp_reuseport_add_sock(sk, hslot, saddr_comp)) {
-			inet_sk(sk)->inet_num = 0;
-			udp_sk(sk)->udp_port_hash = 0;
-			udp_sk(sk)->udp_portaddr_hash ^= snum;
-			goto fail_unlock;
-		}
-
 		sk_nulls_add_node_rcu(sk, &hslot->head);
 		hslot->count++;
 		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
@@ -357,22 +314,13 @@ fail:
 }
 EXPORT_SYMBOL(udp_lib_get_port);
 
-/* match_wildcard == true:  0.0.0.0 equals to any IPv4 addresses
- * match_wildcard == false: addresses must be exactly the same, i.e.
- *                          0.0.0.0 only equals to 0.0.0.0
- */
-static int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2,
-				bool match_wildcard)
+static int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
 {
 	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);
 
-	if (!ipv6_only_sock(sk2)) {
-		if (inet1->inet_rcv_saddr == inet2->inet_rcv_saddr)
-			return 1;
-		if (!inet1->inet_rcv_saddr || !inet2->inet_rcv_saddr)
-			return match_wildcard;
-	}
-	return 0;
+	return 	(!ipv6_only_sock(sk2)  &&
+		 (!inet1->inet_rcv_saddr || !inet2->inet_rcv_saddr ||
+		   inet1->inet_rcv_saddr == inet2->inet_rcv_saddr));
 }
 
 static u32 udp4_portaddr_hash(const struct net *net, __be32 saddr,
@@ -516,14 +464,8 @@ begin:
 			badness = score;
 			reuseport = sk->sk_reuseport;
 			if (reuseport) {
-				struct sock *sk2;
 				hash = udp_ehashfn(net, daddr, hnum,
 						   saddr, sport);
-				sk2 = reuseport_select_sock(sk, hash, NULL, 0);
-				if (sk2) {
-					result = sk2;
-					goto found;
-				}
 				matches = 1;
 			}
 		} else if (score == badness && reuseport) {
@@ -541,7 +483,6 @@ begin:
 	if (get_nulls_value(node) != slot2)
 		goto begin;
 	if (result) {
-found:
 		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
 			result = NULL;
 		else if (unlikely(compute_score2(result, net, saddr, sport,
@@ -558,7 +499,7 @@ found:
  */
 struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr,
 		__be16 sport, __be32 daddr, __be16 dport,
-		int dif, struct udp_table *udptable, struct sk_buff *skb)
+		int dif, struct udp_table *udptable)
 {
 	struct sock *sk, *result;
 	struct hlist_nulls_node *node;
@@ -604,15 +545,8 @@ begin:
 			badness = score;
 			reuseport = sk->sk_reuseport;
 			if (reuseport) {
-				struct sock *sk2;
 				hash = udp_ehashfn(net, daddr, hnum,
 						   saddr, sport);
-				sk2 = reuseport_select_sock(sk, hash, skb,
-							sizeof(struct udphdr));
-				if (sk2) {
-					result = sk2;
-					goto found;
-				}
 				matches = 1;
 			}
 		} else if (score == badness && reuseport) {
@@ -631,7 +565,6 @@ begin:
 		goto begin;
 
 	if (result) {
-found:
 		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
 			result = NULL;
 		else if (unlikely(compute_score(result, net, saddr, hnum, sport,
@@ -653,14 +586,13 @@ static inline struct sock *__udp4_lib_lookup_skb(struct sk_buff *skb,
 
 	return __udp4_lib_lookup(dev_net(skb_dst(skb)->dev), iph->saddr, sport,
 				 iph->daddr, dport, inet_iif(skb),
-				 udptable, skb);
+				 udptable);
 }
 
 struct sock *udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
 			     __be32 daddr, __be16 dport, int dif)
 {
-	return __udp4_lib_lookup(net, saddr, sport, daddr, dport, dif,
-				 &udp_table, NULL);
+	return __udp4_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table);
 }
 EXPORT_SYMBOL_GPL(udp4_lib_lookup);
 
@@ -708,8 +640,7 @@ void __udp4_lib_err(struct sk_buff *skb, u32 info, struct udp_table *udptable)
 	struct net *net = dev_net(skb->dev);
 
 	sk = __udp4_lib_lookup(net, iph->daddr, uh->dest,
-			iph->saddr, uh->source, skb->dev->ifindex, udptable,
-			NULL);
+			iph->saddr, uh->source, skb->dev->ifindex, udptable);
 	if (!sk) {
 		ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
 		return;	/* No socket for error */
@@ -1480,8 +1411,6 @@ void udp_lib_unhash(struct sock *sk)
 		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
 
 		spin_lock_bh(&hslot->lock);
-		if (rcu_access_pointer(sk->sk_reuseport_cb))
-			reuseport_detach_sock(sk);
 		if (sk_nulls_del_node_init_rcu(sk)) {
 			hslot->count--;
 			inet_sk(sk)->inet_num = 0;
@@ -1509,28 +1438,22 @@ void udp_lib_rehash(struct sock *sk, u16 newhash)
 		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
 		nhslot2 = udp_hashslot2(udptable, newhash);
 		udp_sk(sk)->udp_portaddr_hash = newhash;
-
-		if (hslot2 != nhslot2 ||
-		    rcu_access_pointer(sk->sk_reuseport_cb)) {
+		if (hslot2 != nhslot2) {
 			hslot = udp_hashslot(udptable, sock_net(sk),
 					     udp_sk(sk)->udp_port_hash);
 			/* we must lock primary chain too */
 			spin_lock_bh(&hslot->lock);
-			if (rcu_access_pointer(sk->sk_reuseport_cb))
-				reuseport_detach_sock(sk);
-
-			if (hslot2 != nhslot2) {
-				spin_lock(&hslot2->lock);
-				hlist_nulls_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
-				hslot2->count--;
-				spin_unlock(&hslot2->lock);
-
-				spin_lock(&nhslot2->lock);
-				hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
-							 &nhslot2->head);
-				nhslot2->count++;
-				spin_unlock(&nhslot2->lock);
-			}
+
+			spin_lock(&hslot2->lock);
+			hlist_nulls_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
+			hslot2->count--;
+			spin_unlock(&hslot2->lock);
+
+			spin_lock(&nhslot2->lock);
+			hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
+						 &nhslot2->head);
+			nhslot2->count++;
+			spin_unlock(&nhslot2->lock);
 
 			spin_unlock_bh(&hslot->lock);
 		}
diff --git a/net/ipv4/udp_diag.c b/net/ipv4/udp_diag.c
index 6510e961aaa6..092aa60e8b92 100644
--- a/net/ipv4/udp_diag.c
+++ b/net/ipv4/udp_diag.c
@@ -44,7 +44,7 @@ static int udp_dump_one(struct udp_table *tbl, struct sk_buff *in_skb,
 		sk = __udp4_lib_lookup(net,
 				req->id.idiag_src[0], req->id.idiag_sport,
 				req->id.idiag_dst[0], req->id.idiag_dport,
-				req->id.idiag_if, tbl, NULL);
+				req->id.idiag_if, tbl);
 #if IS_ENABLED(CONFIG_IPV6)
 	else if (req->sdiag_family == AF_INET6)
 		sk = __udp6_lib_lookup(net,
@@ -52,7 +52,7 @@ static int udp_dump_one(struct udp_table *tbl, struct sk_buff *in_skb,
 				req->id.idiag_sport,
 				(struct in6_addr *)req->id.idiag_dst,
 				req->id.idiag_dport,
-				req->id.idiag_if, tbl, NULL);
+				req->id.idiag_if, tbl);
 #endif
 	else
 		goto out_nosk;
@@ -182,7 +182,7 @@ static int __udp_diag_destroy(struct sk_buff *in_skb,
 		sk = __udp4_lib_lookup(net,
 				req->id.idiag_dst[0], req->id.idiag_dport,
 				req->id.idiag_src[0], req->id.idiag_sport,
-				req->id.idiag_if, tbl, NULL);
+				req->id.idiag_if, tbl);
 #if IS_ENABLED(CONFIG_IPV6)
 	else if (req->sdiag_family == AF_INET6) {
 		if (ipv6_addr_v4mapped((struct in6_addr *)req->id.idiag_dst) &&
@@ -190,7 +190,7 @@ static int __udp_diag_destroy(struct sk_buff *in_skb,
 			sk = __udp4_lib_lookup(net,
 					req->id.idiag_dst[3], req->id.idiag_dport,
 					req->id.idiag_src[3], req->id.idiag_sport,
-					req->id.idiag_if, tbl, NULL);
+					req->id.idiag_if, tbl);
 
 		else
 			sk = __udp6_lib_lookup(net,
@@ -198,7 +198,7 @@ static int __udp_diag_destroy(struct sk_buff *in_skb,
 					req->id.idiag_dport,
 					(struct in6_addr *)req->id.idiag_src,
 					req->id.idiag_sport,
-					req->id.idiag_if, tbl, NULL);
+					req->id.idiag_if, tbl);
 	}
 #endif
 	else {
diff --git a/net/ipv6/inet6_connection_sock.c b/net/ipv6/inet6_connection_sock.c
index 908525ae5d19..ab9eda00dde5 100644
--- a/net/ipv6/inet6_connection_sock.c
+++ b/net/ipv6/inet6_connection_sock.c
@@ -51,12 +51,12 @@ int inet6_csk_bind_conflict(const struct sock *sk,
 			     (sk2->sk_state != TCP_TIME_WAIT &&
 			      !uid_eq(uid,
 				      sock_i_uid((struct sock *)sk2))))) {
-				if (ipv6_rcv_saddr_equal(sk, sk2, true))
+				if (ipv6_rcv_saddr_equal(sk, sk2))
 					break;
 			}
 			if (!relax && reuse && sk2->sk_reuse &&
 			    sk2->sk_state != TCP_LISTEN &&
-			    ipv6_rcv_saddr_equal(sk, sk2, true))
+			    ipv6_rcv_saddr_equal(sk, sk2))
 				break;
 		}
 	}
diff --git a/net/ipv6/ip6_udp_tunnel.c b/net/ipv6/ip6_udp_tunnel.c
index 7ec737d85ccf..30b03d8e321a 100644
--- a/net/ipv6/ip6_udp_tunnel.c
+++ b/net/ipv6/ip6_udp_tunnel.c
@@ -74,8 +74,8 @@ int udp_tunnel6_xmit_skb(struct dst_entry *dst, struct sock *sk,
 			 struct sk_buff *skb,
 			 struct net_device *dev, struct in6_addr *saddr,
 			 struct in6_addr *daddr,
-			 __u8 prio, __u8 ttl, __be32 label,
-			 __be16 src_port, __be16 dst_port, bool nocheck)
+			 __u8 prio, __u8 ttl, __be16 src_port,
+			 __be16 dst_port, bool nocheck)
 {
 	struct udphdr *uh;
 	struct ipv6hdr *ip6h;
@@ -99,7 +99,7 @@ int udp_tunnel6_xmit_skb(struct dst_entry *dst, struct sock *sk,
 	__skb_push(skb, sizeof(*ip6h));
 	skb_reset_network_header(skb);
 	ip6h		  = ipv6_hdr(skb);
-	ip6_flow_hdr(ip6h, prio, label);
+	ip6_flow_hdr(ip6h, prio, htonl(0));
 	ip6h->payload_len = htons(skb->len);
 	ip6h->nexthdr     = IPPROTO_UDP;
 	ip6h->hop_limit   = ttl;
diff --git a/net/ipv6/udp.c b/net/ipv6/udp.c
index b345b37edd4f..9e2b553b76c4 100644
--- a/net/ipv6/udp.c
+++ b/net/ipv6/udp.c
@@ -48,7 +48,6 @@
 #include <net/inet_hashtables.h>
 #include <net/inet6_hashtables.h>
 #include <net/busy_poll.h>
-#include <net/sock_reuseport.h>
 
 #include <linux/proc_fs.h>
 #include <linux/seq_file.h>
@@ -78,14 +77,7 @@ static u32 udp6_ehashfn(const struct net *net,
 			       udp_ipv6_hash_secret + net_hash_mix(net));
 }
 
-/* match_wildcard == true:  IPV6_ADDR_ANY equals to any IPv6 addresses if IPv6
- *                          only, and any IPv4 addresses if not IPv6 only
- * match_wildcard == false: addresses must be exactly the same, i.e.
- *                          IPV6_ADDR_ANY only equals to IPV6_ADDR_ANY,
- *                          and 0.0.0.0 equals to 0.0.0.0 only
- */
-int ipv6_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2,
-			 bool match_wildcard)
+int ipv6_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2)
 {
 	const struct in6_addr *sk2_rcv_saddr6 = inet6_rcv_saddr(sk2);
 	int sk2_ipv6only = inet_v6_ipv6only(sk2);
@@ -93,24 +85,16 @@ int ipv6_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2,
 	int addr_type2 = sk2_rcv_saddr6 ? ipv6_addr_type(sk2_rcv_saddr6) : IPV6_ADDR_MAPPED;
 
 	/* if both are mapped, treat as IPv4 */
-	if (addr_type == IPV6_ADDR_MAPPED && addr_type2 == IPV6_ADDR_MAPPED) {
-		if (!sk2_ipv6only) {
-			if (sk->sk_rcv_saddr == sk2->sk_rcv_saddr)
-				return 1;
-			if (!sk->sk_rcv_saddr || !sk2->sk_rcv_saddr)
-				return match_wildcard;
-		}
-		return 0;
-	}
-
-	if (addr_type == IPV6_ADDR_ANY && addr_type2 == IPV6_ADDR_ANY)
-		return 1;
+	if (addr_type == IPV6_ADDR_MAPPED && addr_type2 == IPV6_ADDR_MAPPED)
+		return (!sk2_ipv6only &&
+			(!sk->sk_rcv_saddr || !sk2->sk_rcv_saddr ||
+			  sk->sk_rcv_saddr == sk2->sk_rcv_saddr));
 
-	if (addr_type2 == IPV6_ADDR_ANY && match_wildcard &&
+	if (addr_type2 == IPV6_ADDR_ANY &&
 	    !(sk2_ipv6only && addr_type == IPV6_ADDR_MAPPED))
 		return 1;
 
-	if (addr_type == IPV6_ADDR_ANY && match_wildcard &&
+	if (addr_type == IPV6_ADDR_ANY &&
 	    !(ipv6_only_sock(sk) && addr_type2 == IPV6_ADDR_MAPPED))
 		return 1;
 
@@ -270,14 +254,8 @@ begin:
 			badness = score;
 			reuseport = sk->sk_reuseport;
 			if (reuseport) {
-				struct sock *sk2;
 				hash = udp6_ehashfn(net, daddr, hnum,
 						    saddr, sport);
-				sk2 = reuseport_select_sock(sk, hash, NULL, 0);
-				if (sk2) {
-					result = sk2;
-					goto found;
-				}
 				matches = 1;
 			}
 		} else if (score == badness && reuseport) {
@@ -296,7 +274,6 @@ begin:
 		goto begin;
 
 	if (result) {
-found:
 		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
 			result = NULL;
 		else if (unlikely(compute_score2(result, net, saddr, sport,
@@ -311,8 +288,7 @@ found:
 struct sock *__udp6_lib_lookup(struct net *net,
 				      const struct in6_addr *saddr, __be16 sport,
 				      const struct in6_addr *daddr, __be16 dport,
-				      int dif, struct udp_table *udptable,
-				      struct sk_buff *skb)
+				      int dif, struct udp_table *udptable)
 {
 	struct sock *sk, *result;
 	struct hlist_nulls_node *node;
@@ -357,15 +333,8 @@ begin:
 			badness = score;
 			reuseport = sk->sk_reuseport;
 			if (reuseport) {
-				struct sock *sk2;
 				hash = udp6_ehashfn(net, daddr, hnum,
 						    saddr, sport);
-				sk2 = reuseport_select_sock(sk, hash, skb,
-							sizeof(struct udphdr));
-				if (sk2) {
-					result = sk2;
-					goto found;
-				}
 				matches = 1;
 			}
 		} else if (score == badness && reuseport) {
@@ -384,7 +353,6 @@ begin:
 		goto begin;
 
 	if (result) {
-found:
 		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
 			result = NULL;
 		else if (unlikely(compute_score(result, net, hnum, saddr, sport,
@@ -410,13 +378,13 @@ static struct sock *__udp6_lib_lookup_skb(struct sk_buff *skb,
 		return sk;
 	return __udp6_lib_lookup(dev_net(skb_dst(skb)->dev), &iph->saddr, sport,
 				 &iph->daddr, dport, inet6_iif(skb),
-				 udptable, skb);
+				 udptable);
 }
 
 struct sock *udp6_lib_lookup(struct net *net, const struct in6_addr *saddr, __be16 sport,
 			     const struct in6_addr *daddr, __be16 dport, int dif)
 {
-	return __udp6_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table, NULL);
+	return __udp6_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table);
 }
 EXPORT_SYMBOL_GPL(udp6_lib_lookup);
 
@@ -583,8 +551,8 @@ void __udp6_lib_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
 	int err;
 	struct net *net = dev_net(skb->dev);
 
-	sk = __udp6_lib_lookup(net, daddr, uh->dest, saddr, uh->source,
-			       inet6_iif(skb), udptable, skb);
+	sk = __udp6_lib_lookup(net, daddr, uh->dest,
+			       saddr, uh->source, inet6_iif(skb), udptable);
 	if (!sk) {
 		ICMP6_INC_STATS_BH(net, __in6_dev_get(skb->dev),
 				   ICMP6_MIB_INERRORS);
diff --git a/net/netfilter/nft_meta.c b/net/netfilter/nft_meta.c
index 8a69c6fdced5..a97a5bf716be 100644
--- a/net/netfilter/nft_meta.c
+++ b/net/netfilter/nft_meta.c
@@ -200,7 +200,7 @@ void nft_meta_get_eval(const struct nft_expr *expr,
 		sk = skb_to_full_sk(skb);
 		if (!sk || !sk_fullsock(sk))
 			goto err;
-		*dest = sock_cgroup_classid(&sk->sk_cgrp_data);
+		*dest = sk->sk_classid;
 		break;
 #endif
 	default:
diff --git a/net/netfilter/xt_bpf.c b/net/netfilter/xt_bpf.c
index a8df0a9d68e6..7b993f25aab9 100644
--- a/net/netfilter/xt_bpf.c
+++ b/net/netfilter/xt_bpf.c
@@ -8,10 +8,8 @@
  */
 
 #include <linux/module.h>
-#include <linux/syscalls.h>
 #include <linux/skbuff.h>
 #include <linux/filter.h>
-#include <linux/bpf.h>
 
 #include <linux/netfilter/xt_bpf.h>
 #include <linux/netfilter/x_tables.h>
@@ -22,18 +20,18 @@ MODULE_LICENSE("GPL");
 MODULE_ALIAS("ipt_bpf");
 MODULE_ALIAS("ip6t_bpf");
 
-static int __bpf_mt_check_bytecode(struct sock_filter *insns, __u16 len,
-				   struct bpf_prog **ret)
+static int bpf_mt_check(const struct xt_mtchk_param *par)
 {
+	struct xt_bpf_info *info = par->matchinfo;
 	struct sock_fprog_kern program;
 
-	if (len > XT_BPF_MAX_NUM_INSTR)
+	if (info->bpf_program_num_elem > XT_BPF_MAX_NUM_INSTR)
 		return -EINVAL;
 
-	program.len = len;
-	program.filter = insns;
+	program.len = info->bpf_program_num_elem;
+	program.filter = info->bpf_program;
 
-	if (bpf_prog_create(ret, &program)) {
+	if (bpf_prog_create(&info->filter, &program)) {
 		pr_info("bpf: check failed: parse error\n");
 		return -EINVAL;
 	}
@@ -41,53 +39,6 @@ static int __bpf_mt_check_bytecode(struct sock_filter *insns, __u16 len,
 	return 0;
 }
 
-static int __bpf_mt_check_fd(int fd, struct bpf_prog **ret)
-{
-	struct bpf_prog *prog;
-
-	prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_SOCKET_FILTER);
-	if (IS_ERR(prog))
-		return PTR_ERR(prog);
-
-	*ret = prog;
-	return 0;
-}
-
-static int __bpf_mt_check_path(const char *path, struct bpf_prog **ret)
-{
-	if (strnlen(path, XT_BPF_PATH_MAX) == XT_BPF_PATH_MAX)
-		return -EINVAL;
-
-	*ret = bpf_prog_get_type_path(path, BPF_PROG_TYPE_SOCKET_FILTER);
-	return PTR_ERR_OR_ZERO(*ret);
-
-}
-
-static int bpf_mt_check(const struct xt_mtchk_param *par)
-{
-	struct xt_bpf_info *info = par->matchinfo;
-
-	return __bpf_mt_check_bytecode(info->bpf_program,
-				       info->bpf_program_num_elem,
-				       &info->filter);
-}
-
-static int bpf_mt_check_v1(const struct xt_mtchk_param *par)
-{
-	struct xt_bpf_info_v1 *info = par->matchinfo;
-
-	if (info->mode == XT_BPF_MODE_BYTECODE)
-		return __bpf_mt_check_bytecode(info->bpf_program,
-					       info->bpf_program_num_elem,
-					       &info->filter);
-	else if (info->mode == XT_BPF_MODE_FD_ELF)
-		return __bpf_mt_check_fd(info->fd, &info->filter);
-	else if (info->mode == XT_BPF_MODE_PATH_PINNED)
-		return __bpf_mt_check_path(info->path, &info->filter);
-	else
-		return -EINVAL;
-}
-
 static bool bpf_mt(const struct sk_buff *skb, struct xt_action_param *par)
 {
 	const struct xt_bpf_info *info = par->matchinfo;
@@ -95,58 +46,31 @@ static bool bpf_mt(const struct sk_buff *skb, struct xt_action_param *par)
 	return BPF_PROG_RUN(info->filter, skb);
 }
 
-static bool bpf_mt_v1(const struct sk_buff *skb, struct xt_action_param *par)
-{
-	const struct xt_bpf_info_v1 *info = par->matchinfo;
-
-	return !!bpf_prog_run_save_cb(info->filter, (struct sk_buff *) skb);
-}
-
 static void bpf_mt_destroy(const struct xt_mtdtor_param *par)
 {
 	const struct xt_bpf_info *info = par->matchinfo;
-
-	bpf_prog_destroy(info->filter);
-}
-
-static void bpf_mt_destroy_v1(const struct xt_mtdtor_param *par)
-{
-	const struct xt_bpf_info_v1 *info = par->matchinfo;
-
 	bpf_prog_destroy(info->filter);
 }
 
-static struct xt_match bpf_mt_reg[] __read_mostly = {
-	{
-		.name		= "bpf",
-		.revision	= 0,
-		.family		= NFPROTO_UNSPEC,
-		.checkentry	= bpf_mt_check,
-		.match		= bpf_mt,
-		.destroy	= bpf_mt_destroy,
-		.matchsize	= sizeof(struct xt_bpf_info),
-		.me		= THIS_MODULE,
-	},
-	{
-		.name		= "bpf",
-		.revision	= 1,
-		.family		= NFPROTO_UNSPEC,
-		.checkentry	= bpf_mt_check_v1,
-		.match		= bpf_mt_v1,
-		.destroy	= bpf_mt_destroy_v1,
-		.matchsize	= sizeof(struct xt_bpf_info_v1),
-		.me		= THIS_MODULE,
-	},
+static struct xt_match bpf_mt_reg __read_mostly = {
+	.name		= "bpf",
+	.revision	= 0,
+	.family		= NFPROTO_UNSPEC,
+	.checkentry	= bpf_mt_check,
+	.match		= bpf_mt,
+	.destroy	= bpf_mt_destroy,
+	.matchsize	= sizeof(struct xt_bpf_info),
+	.me		= THIS_MODULE,
 };
 
 static int __init bpf_mt_init(void)
 {
-	return xt_register_matches(bpf_mt_reg, ARRAY_SIZE(bpf_mt_reg));
+	return xt_register_match(&bpf_mt_reg);
 }
 
 static void __exit bpf_mt_exit(void)
 {
-	xt_unregister_matches(bpf_mt_reg, ARRAY_SIZE(bpf_mt_reg));
+	xt_unregister_match(&bpf_mt_reg);
 }
 
 module_init(bpf_mt_init);
diff --git a/net/netfilter/xt_cgroup.c b/net/netfilter/xt_cgroup.c
index 54eaeb45ce99..a1d126f29463 100644
--- a/net/netfilter/xt_cgroup.c
+++ b/net/netfilter/xt_cgroup.c
@@ -42,8 +42,7 @@ cgroup_mt(const struct sk_buff *skb, struct xt_action_param *par)
 	if (skb->sk == NULL || !sk_fullsock(skb->sk))
 		return false;
 
-	return (info->id == sock_cgroup_classid(&skb->sk->sk_cgrp_data)) ^
-		info->invert;
+	return (info->id == skb->sk->sk_classid) ^ info->invert;
 }
 
 static struct xt_match cgroup_mt_reg __read_mostly = {
diff --git a/net/openvswitch/flow.h b/net/openvswitch/flow.h
index 03378e75a67c..1d055c559eaf 100644
--- a/net/openvswitch/flow.h
+++ b/net/openvswitch/flow.h
@@ -55,7 +55,7 @@ struct ovs_tunnel_info {
 	FIELD_SIZEOF(struct sw_flow_key, recirc_id))
 
 struct sw_flow_key {
-	u8 tun_opts[IP_TUNNEL_OPTS_MAX];
+	u8 tun_opts[255];
 	u8 tun_opts_len;
 	struct ip_tunnel_key tun_key;	/* Encapsulating tunnel key. */
 	struct {
diff --git a/net/packet/af_packet.c b/net/packet/af_packet.c
index 1da248df5cf8..eac6f7eea7b5 100644
--- a/net/packet/af_packet.c
+++ b/net/packet/af_packet.c
@@ -1605,9 +1605,13 @@ static int fanout_set_data_ebpf(struct packet_sock *po, char __user *data,
 	if (copy_from_user(&fd, data, len))
 		return -EFAULT;
 
-	new = bpf_prog_get_type(fd, BPF_PROG_TYPE_SOCKET_FILTER);
+	new = bpf_prog_get(fd);
 	if (IS_ERR(new))
 		return PTR_ERR(new);
+	if (new->type != BPF_PROG_TYPE_SOCKET_FILTER) {
+		bpf_prog_put(new);
+		return -EINVAL;
+	}
 
 	__fanout_set_data_bpf(po->fanout, new);
 	return 0;
diff --git a/net/sched/act_bpf.c b/net/sched/act_bpf.c
index 143093b95bc3..bd155e59be1c 100644
--- a/net/sched/act_bpf.c
+++ b/net/sched/act_bpf.c
@@ -51,11 +51,9 @@ static int tcf_bpf(struct sk_buff *skb, const struct tc_action *act,
 	filter = rcu_dereference(prog->filter);
 	if (at_ingress) {
 		__skb_push(skb, skb->mac_len);
-		bpf_compute_data_end(skb);
 		filter_res = BPF_PROG_RUN(filter, skb);
 		__skb_pull(skb, skb->mac_len);
 	} else {
-		bpf_compute_data_end(skb);
 		filter_res = BPF_PROG_RUN(filter, skb);
 	}
 	rcu_read_unlock();
@@ -222,10 +220,15 @@ static int tcf_bpf_init_from_efd(struct nlattr **tb, struct tcf_bpf_cfg *cfg)
 
 	bpf_fd = nla_get_u32(tb[TCA_ACT_BPF_FD]);
 
-	fp = bpf_prog_get_type(bpf_fd, BPF_PROG_TYPE_SCHED_ACT);
+	fp = bpf_prog_get(bpf_fd);
 	if (IS_ERR(fp))
 		return PTR_ERR(fp);
 
+	if (fp->type != BPF_PROG_TYPE_SCHED_ACT) {
+		bpf_prog_put(fp);
+		return -EINVAL;
+	}
+
 	if (tb[TCA_ACT_BPF_NAME]) {
 		name = kmemdup(nla_data(tb[TCA_ACT_BPF_NAME]),
 			       nla_len(tb[TCA_ACT_BPF_NAME]),
diff --git a/net/sched/cls_bpf.c b/net/sched/cls_bpf.c
index f674d330ebd1..cdfb8d33bcba 100644
--- a/net/sched/cls_bpf.c
+++ b/net/sched/cls_bpf.c
@@ -100,11 +100,9 @@ static int cls_bpf_classify(struct sk_buff *skb, const struct tcf_proto *tp,
 		if (at_ingress) {
 			/* It is safe to push/pull even if skb_shared() */
 			__skb_push(skb, skb->mac_len);
-			bpf_compute_data_end(skb);
 			filter_res = BPF_PROG_RUN(prog->filter, skb);
 			__skb_pull(skb, skb->mac_len);
 		} else {
-			bpf_compute_data_end(skb);
 			filter_res = BPF_PROG_RUN(prog->filter, skb);
 		}
 
@@ -272,10 +270,15 @@ static int cls_bpf_prog_from_efd(struct nlattr **tb, struct cls_bpf_prog *prog,
 
 	bpf_fd = nla_get_u32(tb[TCA_BPF_FD]);
 
-	fp = bpf_prog_get_type(bpf_fd, BPF_PROG_TYPE_SCHED_CLS);
+	fp = bpf_prog_get(bpf_fd);
 	if (IS_ERR(fp))
 		return PTR_ERR(fp);
 
+	if (fp->type != BPF_PROG_TYPE_SCHED_CLS) {
+		bpf_prog_put(fp);
+		return -EINVAL;
+	}
+
 	if (tb[TCA_BPF_NAME]) {
 		name = kmemdup(nla_data(tb[TCA_BPF_NAME]),
 			       nla_len(tb[TCA_BPF_NAME]),
diff --git a/net/socket.c b/net/socket.c
index b6c46a5fa1fc..453adaf032a8 100644
--- a/net/socket.c
+++ b/net/socket.c
@@ -2597,6 +2597,15 @@ out_fs:
 
 core_initcall(sock_init);	/* early initcall */
 
+static int __init jit_init(void)
+{
+#ifdef CONFIG_BPF_JIT_ALWAYS_ON
+	bpf_jit_enable = 1;
+#endif
+	return 0;
+}
+pure_initcall(jit_init);
+
 #ifdef CONFIG_PROC_FS
 void socket_seq_show(struct seq_file *seq)
 {
diff --git a/net/sunrpc/rpc_pipe.c b/net/sunrpc/rpc_pipe.c
index 831a8cf231a1..12dd5cc499c1 100644
--- a/net/sunrpc/rpc_pipe.c
+++ b/net/sunrpc/rpc_pipe.c
@@ -1388,7 +1388,7 @@ rpc_fill_super(struct super_block *sb, void *data, int silent)
 {
 	struct inode *inode;
 	struct dentry *root, *gssd_dentry;
-	struct net *net = get_net(sb->s_fs_info);
+	struct net *net = data;
 	struct sunrpc_net *sn = net_generic(net, sunrpc_net_id);
 	int err;
 
@@ -1421,6 +1421,7 @@ rpc_fill_super(struct super_block *sb, void *data, int silent)
 					   sb);
 	if (err)
 		goto err_depopulate;
+	sb->s_fs_info = get_net(net);
 	mutex_unlock(&sn->pipefs_sb_lock);
 	return 0;
 
@@ -1449,8 +1450,7 @@ static struct dentry *
 rpc_mount(struct file_system_type *fs_type,
 		int flags, const char *dev_name, void *data)
 {
-	struct net *net = current->nsproxy->net_ns;
-	return mount_ns(fs_type, flags, data, net, net->user_ns, rpc_fill_super);
+	return mount_ns(fs_type, flags, current->nsproxy->net_ns, rpc_fill_super);
 }
 
 static void rpc_kill_sb(struct super_block *sb)
@@ -1470,9 +1470,9 @@ static void rpc_kill_sb(struct super_block *sb)
 					   RPC_PIPEFS_UMOUNT,
 					   sb);
 	mutex_unlock(&sn->pipefs_sb_lock);
+	put_net(net);
 out:
 	kill_litter_super(sb);
-	put_net(net);
 }
 
 static struct file_system_type rpc_pipe_fs_type = {
diff --git a/net/tipc/udp_media.c b/net/tipc/udp_media.c
index 90d54ad86e4e..ac2079439242 100644
--- a/net/tipc/udp_media.c
+++ b/net/tipc/udp_media.c
@@ -210,7 +210,7 @@ static int tipc_udp_send_msg(struct net *net, struct sk_buff *skb,
 		ttl = ip6_dst_hoplimit(ndst);
 		err = udp_tunnel6_xmit_skb(ndst, ub->ubsock->sk, skb,
 					   ndst->dev, &src->ipv6,
-					   &dst->ipv6, 0, ttl, 0, src->udp_port,
+					   &dst->ipv6, 0, ttl, src->udp_port,
 					   dst->udp_port, false);
 #endif
 	}
diff --git a/net/wireguard/compat/udp_tunnel/udp_tunnel_partial_compat.h b/net/wireguard/compat/udp_tunnel/udp_tunnel_partial_compat.h
index 7e25a1419884..0605896e902f 100644
--- a/net/wireguard/compat/udp_tunnel/udp_tunnel_partial_compat.h
+++ b/net/wireguard/compat/udp_tunnel/udp_tunnel_partial_compat.h
@@ -147,6 +147,7 @@ static inline void __compat_fake_destructor(struct sk_buff *skb)
 #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0) && IS_ENABLED(CONFIG_IPV6) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
 #include <linux/if.h>
 #include <net/udp_tunnel.h>
+#define udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, j, k, l)
 #endif
 
 #endif
diff --git a/samples/bpf/Makefile b/samples/bpf/Makefile
index a7ea3889443f..edd638b5825f 100644
--- a/samples/bpf/Makefile
+++ b/samples/bpf/Makefile
@@ -16,12 +16,6 @@ hostprogs-y += tracex5
 hostprogs-y += tracex6
 hostprogs-y += trace_output
 hostprogs-y += lathist
-hostprogs-y += offwaketime
-hostprogs-y += spintest
-hostprogs-y += map_perf_test
-hostprogs-y += test_overhead
-hostprogs-y += test_cgrp2_array_pin
-hostprogs-y += test_cgrp2_attach
 
 test_verifier-objs := test_verifier.o libbpf.o
 test_maps-objs := test_maps.o libbpf.o
@@ -38,12 +32,6 @@ tracex5-objs := bpf_load.o libbpf.o tracex5_user.o
 tracex6-objs := bpf_load.o libbpf.o tracex6_user.o
 trace_output-objs := bpf_load.o libbpf.o trace_output_user.o
 lathist-objs := bpf_load.o libbpf.o lathist_user.o
-offwaketime-objs := bpf_load.o libbpf.o offwaketime_user.o
-spintest-objs := bpf_load.o libbpf.o spintest_user.o
-map_perf_test-objs := bpf_load.o libbpf.o map_perf_test_user.o
-test_overhead-objs := bpf_load.o libbpf.o test_overhead_user.o
-test_cgrp2_array_pin-objs := libbpf.o test_cgrp2_array_pin.o
-test_cgrp2_attach-objs := libbpf.o test_cgrp2_attach.o
 
 # Tell kbuild to always build the programs
 always := $(hostprogs-y)
@@ -59,13 +47,6 @@ always += tracex6_kern.o
 always += trace_output_kern.o
 always += tcbpf1_kern.o
 always += lathist_kern.o
-always += offwaketime_kern.o
-always += spintest_kern.o
-always += map_perf_test_kern.o
-always += test_overhead_tp_kern.o
-always += test_overhead_kprobe_kern.o
-always += parse_varlen.o parse_simple.o parse_ldabs.o
-always += test_cgrp2_tc_kern.o
 
 HOSTCFLAGS += -I$(objtree)/usr/include
 
@@ -82,10 +63,6 @@ HOSTLOADLIBES_tracex5 += -lelf
 HOSTLOADLIBES_tracex6 += -lelf
 HOSTLOADLIBES_trace_output += -lelf -lrt
 HOSTLOADLIBES_lathist += -lelf
-HOSTLOADLIBES_offwaketime += -lelf
-HOSTLOADLIBES_spintest += -lelf
-HOSTLOADLIBES_map_perf_test += -lelf -lrt
-HOSTLOADLIBES_test_overhead += -lelf -lrt
 
 # point this to your LLVM backend with bpf support
 LLC=$(srctree)/tools/bpf/llvm/bld/Debug+Asserts/bin/llc
@@ -96,7 +73,6 @@ LLC=$(srctree)/tools/bpf/llvm/bld/Debug+Asserts/bin/llc
 $(obj)/%.o: $(src)/%.c
 	clang $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
 		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
-		-Wno-compare-distinct-pointer-types \
 		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
 	clang $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
 		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
diff --git a/samples/bpf/bpf_helpers.h b/samples/bpf/bpf_helpers.h
index 2e69bf6da207..7ad19e1dbaf4 100644
--- a/samples/bpf/bpf_helpers.h
+++ b/samples/bpf/bpf_helpers.h
@@ -39,10 +39,6 @@ static int (*bpf_redirect)(int ifindex, int flags) =
 	(void *) BPF_FUNC_redirect;
 static int (*bpf_perf_event_output)(void *ctx, void *map, int index, void *data, int size) =
 	(void *) BPF_FUNC_perf_event_output;
-static int (*bpf_get_stackid)(void *ctx, void *map, int flags) =
-	(void *) BPF_FUNC_get_stackid;
-static int (*bpf_probe_write_user)(void *dst, void *src, int size) =
-	(void *) BPF_FUNC_probe_write_user;
 
 /* llvm builtin functions that eBPF C program may use to
  * emit BPF_LD_ABS and BPF_LD_IND instructions
@@ -63,7 +59,6 @@ struct bpf_map_def {
 	unsigned int key_size;
 	unsigned int value_size;
 	unsigned int max_entries;
-	unsigned int map_flags;
 };
 
 static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
@@ -72,8 +67,6 @@ static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flag
 	(void *) BPF_FUNC_l3_csum_replace;
 static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
 	(void *) BPF_FUNC_l4_csum_replace;
-static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
-	(void *) BPF_FUNC_skb_under_cgroup;
 
 #if defined(__x86_64__)
 
diff --git a/samples/bpf/bpf_load.c b/samples/bpf/bpf_load.c
index 625de05dea83..e836b5ff2060 100644
--- a/samples/bpf/bpf_load.c
+++ b/samples/bpf/bpf_load.c
@@ -157,13 +157,9 @@ static int load_maps(struct bpf_map_def *maps, int len)
 		map_fd[i] = bpf_create_map(maps[i].type,
 					   maps[i].key_size,
 					   maps[i].value_size,
-					   maps[i].max_entries,
-					   maps[i].map_flags);
-		if (map_fd[i] < 0) {
-			printf("failed to create a map: %d %s\n",
-			       errno, strerror(errno));
+					   maps[i].max_entries);
+		if (map_fd[i] < 0)
 			return 1;
-		}
 
 		if (maps[i].type == BPF_MAP_TYPE_PROG_ARRAY)
 			prog_array_fd = map_fd[i];
diff --git a/samples/bpf/fds_example.c b/samples/bpf/fds_example.c
index 625e797be6ef..e2fd16c3d0f0 100644
--- a/samples/bpf/fds_example.c
+++ b/samples/bpf/fds_example.c
@@ -44,7 +44,7 @@ static void usage(void)
 static int bpf_map_create(void)
 {
 	return bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
-			      sizeof(uint32_t), 1024, 0);
+			      sizeof(uint32_t), 1024);
 }
 
 static int bpf_prog_create(const char *object)
diff --git a/samples/bpf/libbpf.c b/samples/bpf/libbpf.c
index 9cbc786e48e5..65a8d48d2799 100644
--- a/samples/bpf/libbpf.c
+++ b/samples/bpf/libbpf.c
@@ -19,14 +19,13 @@ static __u64 ptr_to_u64(void *ptr)
 }
 
 int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
-		   int max_entries, int map_flags)
+		   int max_entries)
 {
 	union bpf_attr attr = {
 		.map_type = map_type,
 		.key_size = key_size,
 		.value_size = value_size,
-		.max_entries = max_entries,
-		.map_flags = map_flags,
+		.max_entries = max_entries
 	};
 
 	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
@@ -104,29 +103,6 @@ int bpf_prog_load(enum bpf_prog_type prog_type,
 	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
 }
 
-int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type,
-		    unsigned int flags)
-{
-	union bpf_attr attr = {
-		.target_fd = target_fd,
-		.attach_bpf_fd = prog_fd,
-		.attach_type = type,
-		.attach_flags  = flags;
-	};
-
-	return syscall(__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
-}
-
-int bpf_prog_detach(int target_fd, enum bpf_attach_type type)
-{
-	union bpf_attr attr = {
-		.target_fd = target_fd,
-		.attach_type = type,
-	};
-
-	return syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
-}
-
 int bpf_obj_pin(int fd, const char *pathname)
 {
 	union bpf_attr attr = {
diff --git a/samples/bpf/libbpf.h b/samples/bpf/libbpf.h
index b06cf5aea097..014aacf916e4 100644
--- a/samples/bpf/libbpf.h
+++ b/samples/bpf/libbpf.h
@@ -5,7 +5,7 @@
 struct bpf_insn;
 
 int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
-		   int max_entries, int map_flags);
+		   int max_entries);
 int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags);
 int bpf_lookup_elem(int fd, void *key, void *value);
 int bpf_delete_elem(int fd, void *key);
@@ -15,10 +15,6 @@ int bpf_prog_load(enum bpf_prog_type prog_type,
 		  const struct bpf_insn *insns, int insn_len,
 		  const char *license, int kern_version);
 
-int bpf_prog_attach(int prog_fd, int attachable_fd, enum bpf_attach_type type,
-		    unsigned int flags);
-int bpf_prog_detach(int attachable_fd, enum bpf_attach_type type);
-
 int bpf_obj_pin(int fd, const char *pathname);
 int bpf_obj_get(const char *pathname);
 
@@ -89,14 +85,6 @@ extern char bpf_log_buf[LOG_BUF_SIZE];
 		.off   = 0,					\
 		.imm   = IMM })
 
-#define BPF_MOV32_IMM(DST, IMM)					\
-	((struct bpf_insn) {					\
-		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
-		.dst_reg = DST,					\
-		.src_reg = 0,					\
-		.off   = 0,					\
-		.imm   = IMM })
-
 /* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
 #define BPF_LD_IMM64(DST, IMM)					\
 	BPF_LD_IMM64_RAW(DST, 0, IMM)
diff --git a/samples/bpf/map_perf_test_kern.c b/samples/bpf/map_perf_test_kern.c
deleted file mode 100644
index 311538e5a701..000000000000
--- a/samples/bpf/map_perf_test_kern.c
+++ /dev/null
@@ -1,100 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/skbuff.h>
-#include <linux/netdevice.h>
-#include <linux/version.h>
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-
-#define MAX_ENTRIES 1000
-
-struct bpf_map_def SEC("maps") hash_map = {
-	.type = BPF_MAP_TYPE_HASH,
-	.key_size = sizeof(u32),
-	.value_size = sizeof(long),
-	.max_entries = MAX_ENTRIES,
-};
-
-struct bpf_map_def SEC("maps") percpu_hash_map = {
-	.type = BPF_MAP_TYPE_PERCPU_HASH,
-	.key_size = sizeof(u32),
-	.value_size = sizeof(long),
-	.max_entries = MAX_ENTRIES,
-};
-
-struct bpf_map_def SEC("maps") hash_map_alloc = {
-	.type = BPF_MAP_TYPE_HASH,
-	.key_size = sizeof(u32),
-	.value_size = sizeof(long),
-	.max_entries = MAX_ENTRIES,
-	.map_flags = BPF_F_NO_PREALLOC,
-};
-
-struct bpf_map_def SEC("maps") percpu_hash_map_alloc = {
-	.type = BPF_MAP_TYPE_PERCPU_HASH,
-	.key_size = sizeof(u32),
-	.value_size = sizeof(long),
-	.max_entries = MAX_ENTRIES,
-	.map_flags = BPF_F_NO_PREALLOC,
-};
-
-SEC("kprobe/sys_getuid")
-int stress_hmap(struct pt_regs *ctx)
-{
-	u32 key = bpf_get_current_pid_tgid();
-	long init_val = 1;
-	long *value;
-
-	bpf_map_update_elem(&hash_map, &key, &init_val, BPF_ANY);
-	value = bpf_map_lookup_elem(&hash_map, &key);
-	if (value)
-		bpf_map_delete_elem(&hash_map, &key);
-	return 0;
-}
-
-SEC("kprobe/sys_geteuid")
-int stress_percpu_hmap(struct pt_regs *ctx)
-{
-	u32 key = bpf_get_current_pid_tgid();
-	long init_val = 1;
-	long *value;
-
-	bpf_map_update_elem(&percpu_hash_map, &key, &init_val, BPF_ANY);
-	value = bpf_map_lookup_elem(&percpu_hash_map, &key);
-	if (value)
-		bpf_map_delete_elem(&percpu_hash_map, &key);
-	return 0;
-}
-SEC("kprobe/sys_getgid")
-int stress_hmap_alloc(struct pt_regs *ctx)
-{
-	u32 key = bpf_get_current_pid_tgid();
-	long init_val = 1;
-	long *value;
-
-	bpf_map_update_elem(&hash_map_alloc, &key, &init_val, BPF_ANY);
-	value = bpf_map_lookup_elem(&hash_map_alloc, &key);
-	if (value)
-		bpf_map_delete_elem(&hash_map_alloc, &key);
-	return 0;
-}
-
-SEC("kprobe/sys_getegid")
-int stress_percpu_hmap_alloc(struct pt_regs *ctx)
-{
-	u32 key = bpf_get_current_pid_tgid();
-	long init_val = 1;
-	long *value;
-
-	bpf_map_update_elem(&percpu_hash_map_alloc, &key, &init_val, BPF_ANY);
-	value = bpf_map_lookup_elem(&percpu_hash_map_alloc, &key);
-	if (value)
-		bpf_map_delete_elem(&percpu_hash_map_alloc, &key);
-	return 0;
-}
-char _license[] SEC("license") = "GPL";
-u32 _version SEC("version") = LINUX_VERSION_CODE;
diff --git a/samples/bpf/map_perf_test_user.c b/samples/bpf/map_perf_test_user.c
deleted file mode 100644
index 95af56ec5739..000000000000
--- a/samples/bpf/map_perf_test_user.c
+++ /dev/null
@@ -1,155 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#define _GNU_SOURCE
-#include <sched.h>
-#include <stdio.h>
-#include <sys/types.h>
-#include <asm/unistd.h>
-#include <unistd.h>
-#include <assert.h>
-#include <sys/wait.h>
-#include <stdlib.h>
-#include <signal.h>
-#include <linux/bpf.h>
-#include <string.h>
-#include <time.h>
-#include "libbpf.h"
-#include "bpf_load.h"
-
-#define MAX_CNT 1000000
-
-static __u64 time_get_ns(void)
-{
-	struct timespec ts;
-
-	clock_gettime(CLOCK_MONOTONIC, &ts);
-	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
-}
-
-#define HASH_PREALLOC		(1 << 0)
-#define PERCPU_HASH_PREALLOC	(1 << 1)
-#define HASH_KMALLOC		(1 << 2)
-#define PERCPU_HASH_KMALLOC	(1 << 3)
-
-static int test_flags = ~0;
-
-static void test_hash_prealloc(int cpu)
-{
-	__u64 start_time;
-	int i;
-
-	start_time = time_get_ns();
-	for (i = 0; i < MAX_CNT; i++)
-		syscall(__NR_getuid);
-	printf("%d:hash_map_perf pre-alloc %lld events per sec\n",
-	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
-}
-
-static void test_percpu_hash_prealloc(int cpu)
-{
-	__u64 start_time;
-	int i;
-
-	start_time = time_get_ns();
-	for (i = 0; i < MAX_CNT; i++)
-		syscall(__NR_geteuid);
-	printf("%d:percpu_hash_map_perf pre-alloc %lld events per sec\n",
-	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
-}
-
-static void test_hash_kmalloc(int cpu)
-{
-	__u64 start_time;
-	int i;
-
-	start_time = time_get_ns();
-	for (i = 0; i < MAX_CNT; i++)
-		syscall(__NR_getgid);
-	printf("%d:hash_map_perf kmalloc %lld events per sec\n",
-	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
-}
-
-static void test_percpu_hash_kmalloc(int cpu)
-{
-	__u64 start_time;
-	int i;
-
-	start_time = time_get_ns();
-	for (i = 0; i < MAX_CNT; i++)
-		syscall(__NR_getegid);
-	printf("%d:percpu_hash_map_perf kmalloc %lld events per sec\n",
-	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
-}
-
-static void loop(int cpu)
-{
-	cpu_set_t cpuset;
-
-	CPU_ZERO(&cpuset);
-	CPU_SET(cpu, &cpuset);
-	sched_setaffinity(0, sizeof(cpuset), &cpuset);
-
-	if (test_flags & HASH_PREALLOC)
-		test_hash_prealloc(cpu);
-
-	if (test_flags & PERCPU_HASH_PREALLOC)
-		test_percpu_hash_prealloc(cpu);
-
-	if (test_flags & HASH_KMALLOC)
-		test_hash_kmalloc(cpu);
-
-	if (test_flags & PERCPU_HASH_KMALLOC)
-		test_percpu_hash_kmalloc(cpu);
-}
-
-static void run_perf_test(int tasks)
-{
-	pid_t pid[tasks];
-	int i;
-
-	for (i = 0; i < tasks; i++) {
-		pid[i] = fork();
-		if (pid[i] == 0) {
-			loop(i);
-			exit(0);
-		} else if (pid[i] == -1) {
-			printf("couldn't spawn #%d process\n", i);
-			exit(1);
-		}
-	}
-	for (i = 0; i < tasks; i++) {
-		int status;
-
-		assert(waitpid(pid[i], &status, 0) == pid[i]);
-		assert(status == 0);
-	}
-}
-
-int main(int argc, char **argv)
-{
-	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
-	char filename[256];
-	int num_cpu = 8;
-
-	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
-	setrlimit(RLIMIT_MEMLOCK, &r);
-
-	if (argc > 1)
-		test_flags = atoi(argv[1]) ? : test_flags;
-
-	if (argc > 2)
-		num_cpu = atoi(argv[2]) ? : num_cpu;
-
-	if (load_bpf_file(filename)) {
-		printf("%s", bpf_log_buf);
-		return 1;
-	}
-
-	run_perf_test(num_cpu);
-
-	return 0;
-}
diff --git a/samples/bpf/offwaketime_kern.c b/samples/bpf/offwaketime_kern.c
deleted file mode 100644
index c0aa5a9b9c48..000000000000
--- a/samples/bpf/offwaketime_kern.c
+++ /dev/null
@@ -1,131 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-#include <uapi/linux/ptrace.h>
-#include <uapi/linux/perf_event.h>
-#include <linux/version.h>
-#include <linux/sched.h>
-
-#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
-
-#define MINBLOCK_US	1
-
-struct key_t {
-	char waker[TASK_COMM_LEN];
-	char target[TASK_COMM_LEN];
-	u32 wret;
-	u32 tret;
-};
-
-struct bpf_map_def SEC("maps") counts = {
-	.type = BPF_MAP_TYPE_HASH,
-	.key_size = sizeof(struct key_t),
-	.value_size = sizeof(u64),
-	.max_entries = 10000,
-};
-
-struct bpf_map_def SEC("maps") start = {
-	.type = BPF_MAP_TYPE_HASH,
-	.key_size = sizeof(u32),
-	.value_size = sizeof(u64),
-	.max_entries = 10000,
-};
-
-struct wokeby_t {
-	char name[TASK_COMM_LEN];
-	u32 ret;
-};
-
-struct bpf_map_def SEC("maps") wokeby = {
-	.type = BPF_MAP_TYPE_HASH,
-	.key_size = sizeof(u32),
-	.value_size = sizeof(struct wokeby_t),
-	.max_entries = 10000,
-};
-
-struct bpf_map_def SEC("maps") stackmap = {
-	.type = BPF_MAP_TYPE_STACK_TRACE,
-	.key_size = sizeof(u32),
-	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
-	.max_entries = 10000,
-};
-
-#define STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
-
-SEC("kprobe/try_to_wake_up")
-int waker(struct pt_regs *ctx)
-{
-	struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
-	struct wokeby_t woke = {};
-	u32 pid;
-
-	pid = _(p->pid);
-
-	bpf_get_current_comm(&woke.name, sizeof(woke.name));
-	woke.ret = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);
-
-	bpf_map_update_elem(&wokeby, &pid, &woke, BPF_ANY);
-	return 0;
-}
-
-static inline int update_counts(struct pt_regs *ctx, u32 pid, u64 delta)
-{
-	struct key_t key = {};
-	struct wokeby_t *woke;
-	u64 zero = 0, *val;
-
-	bpf_get_current_comm(&key.target, sizeof(key.target));
-	key.tret = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);
-
-	woke = bpf_map_lookup_elem(&wokeby, &pid);
-	if (woke) {
-		key.wret = woke->ret;
-		__builtin_memcpy(&key.waker, woke->name, TASK_COMM_LEN);
-		bpf_map_delete_elem(&wokeby, &pid);
-	}
-
-	val = bpf_map_lookup_elem(&counts, &key);
-	if (!val) {
-		bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
-		val = bpf_map_lookup_elem(&counts, &key);
-		if (!val)
-			return 0;
-	}
-	(*val) += delta;
-	return 0;
-}
-
-SEC("kprobe/finish_task_switch")
-int oncpu(struct pt_regs *ctx)
-{
-	struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
-	u64 delta, ts, *tsp;
-	u32 pid;
-
-	/* record previous thread sleep time */
-	pid = _(p->pid);
-	ts = bpf_ktime_get_ns();
-	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
-
-	/* calculate current thread's delta time */
-	pid = bpf_get_current_pid_tgid();
-	tsp = bpf_map_lookup_elem(&start, &pid);
-	if (!tsp)
-		/* missed start or filtered */
-		return 0;
-
-	delta = bpf_ktime_get_ns() - *tsp;
-	bpf_map_delete_elem(&start, &pid);
-	delta = delta / 1000;
-	if (delta < MINBLOCK_US)
-		return 0;
-
-	return update_counts(ctx, pid, delta);
-}
-char _license[] SEC("license") = "GPL";
-u32 _version SEC("version") = LINUX_VERSION_CODE;
diff --git a/samples/bpf/offwaketime_user.c b/samples/bpf/offwaketime_user.c
deleted file mode 100644
index 17cf3024e22c..000000000000
--- a/samples/bpf/offwaketime_user.c
+++ /dev/null
@@ -1,185 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <stdio.h>
-#include <unistd.h>
-#include <stdlib.h>
-#include <signal.h>
-#include <linux/bpf.h>
-#include <string.h>
-#include <linux/perf_event.h>
-#include <errno.h>
-#include <assert.h>
-#include <stdbool.h>
-#include <sys/resource.h>
-#include "libbpf.h"
-#include "bpf_load.h"
-
-#define MAX_SYMS 300000
-#define PRINT_RAW_ADDR 0
-
-static struct ksym {
-	long addr;
-	char *name;
-} syms[MAX_SYMS];
-static int sym_cnt;
-
-static int ksym_cmp(const void *p1, const void *p2)
-{
-	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
-}
-
-static int load_kallsyms(void)
-{
-	FILE *f = fopen("/proc/kallsyms", "r");
-	char func[256], buf[256];
-	char symbol;
-	void *addr;
-	int i = 0;
-
-	if (!f)
-		return -ENOENT;
-
-	while (!feof(f)) {
-		if (!fgets(buf, sizeof(buf), f))
-			break;
-		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
-			break;
-		if (!addr)
-			continue;
-		syms[i].addr = (long) addr;
-		syms[i].name = strdup(func);
-		i++;
-	}
-	sym_cnt = i;
-	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
-	return 0;
-}
-
-static void *search(long key)
-{
-	int start = 0, end = sym_cnt;
-	int result;
-
-	while (start < end) {
-		size_t mid = start + (end - start) / 2;
-
-		result = key - syms[mid].addr;
-		if (result < 0)
-			end = mid;
-		else if (result > 0)
-			start = mid + 1;
-		else
-			return &syms[mid];
-	}
-
-	if (start >= 1 && syms[start - 1].addr < key &&
-	    key < syms[start].addr)
-		/* valid ksym */
-		return &syms[start - 1];
-
-	/* out of range. return _stext */
-	return &syms[0];
-}
-
-static void print_ksym(__u64 addr)
-{
-	struct ksym *sym;
-
-	if (!addr)
-		return;
-	sym = search(addr);
-	if (PRINT_RAW_ADDR)
-		printf("%s/%llx;", sym->name, addr);
-	else
-		printf("%s;", sym->name);
-}
-
-#define TASK_COMM_LEN 16
-
-struct key_t {
-	char waker[TASK_COMM_LEN];
-	char target[TASK_COMM_LEN];
-	__u32 wret;
-	__u32 tret;
-};
-
-static void print_stack(struct key_t *key, __u64 count)
-{
-	__u64 ip[PERF_MAX_STACK_DEPTH] = {};
-	static bool warned;
-	int i;
-
-	printf("%s;", key->target);
-	if (bpf_lookup_elem(map_fd[3], &key->tret, ip) != 0) {
-		printf("---;");
-	} else {
-		for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
-			print_ksym(ip[i]);
-	}
-	printf("-;");
-	if (bpf_lookup_elem(map_fd[3], &key->wret, ip) != 0) {
-		printf("---;");
-	} else {
-		for (i = 0; i < PERF_MAX_STACK_DEPTH; i++)
-			print_ksym(ip[i]);
-	}
-	printf(";%s %lld\n", key->waker, count);
-
-	if ((key->tret == -EEXIST || key->wret == -EEXIST) && !warned) {
-		printf("stackmap collisions seen. Consider increasing size\n");
-		warned = true;
-	} else if (((int)(key->tret) < 0 || (int)(key->wret) < 0)) {
-		printf("err stackid %d %d\n", key->tret, key->wret);
-	}
-}
-
-static void print_stacks(int fd)
-{
-	struct key_t key = {}, next_key;
-	__u64 value;
-
-	while (bpf_get_next_key(fd, &key, &next_key) == 0) {
-		bpf_lookup_elem(fd, &next_key, &value);
-		print_stack(&next_key, value);
-		key = next_key;
-	}
-}
-
-static void int_exit(int sig)
-{
-	print_stacks(map_fd[0]);
-	exit(0);
-}
-
-int main(int argc, char **argv)
-{
-	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
-	char filename[256];
-	int delay = 1;
-
-	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
-	setrlimit(RLIMIT_MEMLOCK, &r);
-
-	signal(SIGINT, int_exit);
-
-	if (load_kallsyms()) {
-		printf("failed to process /proc/kallsyms\n");
-		return 2;
-	}
-
-	if (load_bpf_file(filename)) {
-		printf("%s", bpf_log_buf);
-		return 1;
-	}
-
-	if (argc > 1)
-		delay = atoi(argv[1]);
-	sleep(delay);
-	print_stacks(map_fd[0]);
-
-	return 0;
-}
diff --git a/samples/bpf/parse_ldabs.c b/samples/bpf/parse_ldabs.c
deleted file mode 100644
index d17550198d06..000000000000
--- a/samples/bpf/parse_ldabs.c
+++ /dev/null
@@ -1,41 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/ip.h>
-#include <linux/ipv6.h>
-#include <linux/in.h>
-#include <linux/tcp.h>
-#include <linux/udp.h>
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-
-#define DEFAULT_PKTGEN_UDP_PORT	9
-#define IP_MF			0x2000
-#define IP_OFFSET		0x1FFF
-
-static inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
-{
-	return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off))
-		& (IP_MF | IP_OFFSET);
-}
-
-SEC("ldabs")
-int handle_ingress(struct __sk_buff *skb)
-{
-	__u64 troff = ETH_HLEN + sizeof(struct iphdr);
-
-	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
-		return 0;
-	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_UDP ||
-	    load_byte(skb, ETH_HLEN) != 0x45)
-		return 0;
-	if (ip_is_fragment(skb, ETH_HLEN))
-		return 0;
-	if (load_half(skb, troff + offsetof(struct udphdr, dest)) == DEFAULT_PKTGEN_UDP_PORT)
-		return TC_ACT_SHOT;
-	return 0;
-}
-char _license[] SEC("license") = "GPL";
diff --git a/samples/bpf/parse_simple.c b/samples/bpf/parse_simple.c
deleted file mode 100644
index cf2511c33905..000000000000
--- a/samples/bpf/parse_simple.c
+++ /dev/null
@@ -1,48 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/ip.h>
-#include <linux/ipv6.h>
-#include <linux/in.h>
-#include <linux/tcp.h>
-#include <linux/udp.h>
-#include <uapi/linux/bpf.h>
-#include <net/ip.h>
-#include "bpf_helpers.h"
-
-#define DEFAULT_PKTGEN_UDP_PORT 9
-
-/* copy of 'struct ethhdr' without __packed */
-struct eth_hdr {
-	unsigned char   h_dest[ETH_ALEN];
-	unsigned char   h_source[ETH_ALEN];
-	unsigned short  h_proto;
-};
-
-SEC("simple")
-int handle_ingress(struct __sk_buff *skb)
-{
-	void *data = (void *)(long)skb->data;
-	struct eth_hdr *eth = data;
-	struct iphdr *iph = data + sizeof(*eth);
-	struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);
-	void *data_end = (void *)(long)skb->data_end;
-
-	/* single length check */
-	if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end)
-		return 0;
-
-	if (eth->h_proto != htons(ETH_P_IP))
-		return 0;
-	if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
-		return 0;
-	if (ip_is_fragment(iph))
-		return 0;
-	if (udp->dest == htons(DEFAULT_PKTGEN_UDP_PORT))
-		return TC_ACT_SHOT;
-	return 0;
-}
-char _license[] SEC("license") = "GPL";
diff --git a/samples/bpf/parse_varlen.c b/samples/bpf/parse_varlen.c
deleted file mode 100644
index edab34dce79b..000000000000
--- a/samples/bpf/parse_varlen.c
+++ /dev/null
@@ -1,153 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/if_ether.h>
-#include <linux/ip.h>
-#include <linux/ipv6.h>
-#include <linux/in.h>
-#include <linux/tcp.h>
-#include <linux/udp.h>
-#include <uapi/linux/bpf.h>
-#include <net/ip.h>
-#include "bpf_helpers.h"
-
-#define DEFAULT_PKTGEN_UDP_PORT 9
-#define DEBUG 0
-
-static int tcp(void *data, uint64_t tp_off, void *data_end)
-{
-	struct tcphdr *tcp = data + tp_off;
-
-	if (tcp + 1 > data_end)
-		return 0;
-	if (tcp->dest == htons(80) || tcp->source == htons(80))
-		return TC_ACT_SHOT;
-	return 0;
-}
-
-static int udp(void *data, uint64_t tp_off, void *data_end)
-{
-	struct udphdr *udp = data + tp_off;
-
-	if (udp + 1 > data_end)
-		return 0;
-	if (udp->dest == htons(DEFAULT_PKTGEN_UDP_PORT) ||
-	    udp->source == htons(DEFAULT_PKTGEN_UDP_PORT)) {
-		if (DEBUG) {
-			char fmt[] = "udp port 9 indeed\n";
-
-			bpf_trace_printk(fmt, sizeof(fmt));
-		}
-		return TC_ACT_SHOT;
-	}
-	return 0;
-}
-
-static int parse_ipv4(void *data, uint64_t nh_off, void *data_end)
-{
-	struct iphdr *iph;
-	uint64_t ihl_len;
-
-	iph = data + nh_off;
-	if (iph + 1 > data_end)
-		return 0;
-
-	if (ip_is_fragment(iph))
-		return 0;
-	ihl_len = iph->ihl * 4;
-
-	if (iph->protocol == IPPROTO_IPIP) {
-		iph = data + nh_off + ihl_len;
-		if (iph + 1 > data_end)
-			return 0;
-		ihl_len += iph->ihl * 4;
-	}
-
-	if (iph->protocol == IPPROTO_TCP)
-		return tcp(data, nh_off + ihl_len, data_end);
-	else if (iph->protocol == IPPROTO_UDP)
-		return udp(data, nh_off + ihl_len, data_end);
-	return 0;
-}
-
-static int parse_ipv6(void *data, uint64_t nh_off, void *data_end)
-{
-	struct ipv6hdr *ip6h;
-	struct iphdr *iph;
-	uint64_t ihl_len = sizeof(struct ipv6hdr);
-	uint64_t nexthdr;
-
-	ip6h = data + nh_off;
-	if (ip6h + 1 > data_end)
-		return 0;
-
-	nexthdr = ip6h->nexthdr;
-
-	if (nexthdr == IPPROTO_IPIP) {
-		iph = data + nh_off + ihl_len;
-		if (iph + 1 > data_end)
-			return 0;
-		ihl_len += iph->ihl * 4;
-		nexthdr = iph->protocol;
-	} else if (nexthdr == IPPROTO_IPV6) {
-		ip6h = data + nh_off + ihl_len;
-		if (ip6h + 1 > data_end)
-			return 0;
-		ihl_len += sizeof(struct ipv6hdr);
-		nexthdr = ip6h->nexthdr;
-	}
-
-	if (nexthdr == IPPROTO_TCP)
-		return tcp(data, nh_off + ihl_len, data_end);
-	else if (nexthdr == IPPROTO_UDP)
-		return udp(data, nh_off + ihl_len, data_end);
-	return 0;
-}
-
-struct vlan_hdr {
-	uint16_t h_vlan_TCI;
-	uint16_t h_vlan_encapsulated_proto;
-};
-
-SEC("varlen")
-int handle_ingress(struct __sk_buff *skb)
-{
-	void *data = (void *)(long)skb->data;
-	struct ethhdr *eth = data;
-	void *data_end = (void *)(long)skb->data_end;
-	uint64_t h_proto, nh_off;
-
-	nh_off = sizeof(*eth);
-	if (data + nh_off > data_end)
-		return 0;
-
-	h_proto = eth->h_proto;
-
-	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
-		struct vlan_hdr *vhdr;
-
-		vhdr = data + nh_off;
-		nh_off += sizeof(struct vlan_hdr);
-		if (data + nh_off > data_end)
-			return 0;
-		h_proto = vhdr->h_vlan_encapsulated_proto;
-	}
-	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
-		struct vlan_hdr *vhdr;
-
-		vhdr = data + nh_off;
-		nh_off += sizeof(struct vlan_hdr);
-		if (data + nh_off > data_end)
-			return 0;
-		h_proto = vhdr->h_vlan_encapsulated_proto;
-	}
-	if (h_proto == htons(ETH_P_IP))
-		return parse_ipv4(data, nh_off, data_end);
-	else if (h_proto == htons(ETH_P_IPV6))
-		return parse_ipv6(data, nh_off, data_end);
-	return 0;
-}
-char _license[] SEC("license") = "GPL";
diff --git a/samples/bpf/sock_example.c b/samples/bpf/sock_example.c
index 28b60baa9fa8..a0ce251c5390 100644
--- a/samples/bpf/sock_example.c
+++ b/samples/bpf/sock_example.c
@@ -34,7 +34,7 @@ static int test_sock(void)
 	long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;
 
 	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
-				256, 0);
+				256);
 	if (map_fd < 0) {
 		printf("failed to create map '%s'\n", strerror(errno));
 		goto cleanup;
diff --git a/samples/bpf/spintest_kern.c b/samples/bpf/spintest_kern.c
deleted file mode 100644
index ef8ac33bb2e9..000000000000
--- a/samples/bpf/spintest_kern.c
+++ /dev/null
@@ -1,59 +0,0 @@
-/* Copyright (c) 2016, Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/skbuff.h>
-#include <linux/netdevice.h>
-#include <linux/version.h>
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-
-struct bpf_map_def SEC("maps") my_map = {
-	.type = BPF_MAP_TYPE_HASH,
-	.key_size = sizeof(long),
-	.value_size = sizeof(long),
-	.max_entries = 1024,
-};
-struct bpf_map_def SEC("maps") my_map2 = {
-	.type = BPF_MAP_TYPE_PERCPU_HASH,
-	.key_size = sizeof(long),
-	.value_size = sizeof(long),
-	.max_entries = 1024,
-};
-
-#define PROG(foo) \
-int foo(struct pt_regs *ctx) \
-{ \
-	long v = ctx->ip, *val; \
-\
-	val = bpf_map_lookup_elem(&my_map, &v); \
-	bpf_map_update_elem(&my_map, &v, &v, BPF_ANY); \
-	bpf_map_update_elem(&my_map2, &v, &v, BPF_ANY); \
-	bpf_map_delete_elem(&my_map2, &v); \
-	return 0; \
-}
-
-/* add kprobes to all possible *spin* functions */
-SEC("kprobe/spin_unlock")PROG(p1)
-SEC("kprobe/spin_lock")PROG(p2)
-SEC("kprobe/mutex_spin_on_owner")PROG(p3)
-SEC("kprobe/rwsem_spin_on_owner")PROG(p4)
-SEC("kprobe/spin_unlock_irqrestore")PROG(p5)
-SEC("kprobe/_raw_spin_unlock_irqrestore")PROG(p6)
-SEC("kprobe/_raw_spin_unlock_bh")PROG(p7)
-SEC("kprobe/_raw_spin_unlock")PROG(p8)
-SEC("kprobe/_raw_spin_lock_irqsave")PROG(p9)
-SEC("kprobe/_raw_spin_trylock_bh")PROG(p10)
-SEC("kprobe/_raw_spin_lock_irq")PROG(p11)
-SEC("kprobe/_raw_spin_trylock")PROG(p12)
-SEC("kprobe/_raw_spin_lock")PROG(p13)
-SEC("kprobe/_raw_spin_lock_bh")PROG(p14)
-/* and to inner bpf helpers */
-SEC("kprobe/htab_map_update_elem")PROG(p15)
-SEC("kprobe/__htab_percpu_map_update_elem")PROG(p16)
-SEC("kprobe/htab_map_alloc")PROG(p17)
-
-char _license[] SEC("license") = "GPL";
-u32 _version SEC("version") = LINUX_VERSION_CODE;
diff --git a/samples/bpf/spintest_user.c b/samples/bpf/spintest_user.c
deleted file mode 100644
index 311ede532230..000000000000
--- a/samples/bpf/spintest_user.c
+++ /dev/null
@@ -1,50 +0,0 @@
-#include <stdio.h>
-#include <unistd.h>
-#include <linux/bpf.h>
-#include <string.h>
-#include <assert.h>
-#include <sys/resource.h>
-#include "libbpf.h"
-#include "bpf_load.h"
-
-int main(int ac, char **argv)
-{
-	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
-	long key, next_key, value;
-	char filename[256];
-	struct ksym *sym;
-	int i;
-
-	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
-	setrlimit(RLIMIT_MEMLOCK, &r);
-
-	if (load_kallsyms()) {
-		printf("failed to process /proc/kallsyms\n");
-		return 2;
-	}
-
-	if (load_bpf_file(filename)) {
-		printf("%s", bpf_log_buf);
-		return 1;
-	}
-
-	for (i = 0; i < 5; i++) {
-		key = 0;
-		printf("kprobing funcs:");
-		while (bpf_get_next_key(map_fd[0], &key, &next_key) == 0) {
-			bpf_lookup_elem(map_fd[0], &next_key, &value);
-			assert(next_key == value);
-			sym = ksym_search(value);
-			printf(" %s", sym->name);
-			key = next_key;
-		}
-		if (key)
-			printf("\n");
-		key = 0;
-		while (bpf_get_next_key(map_fd[0], &key, &next_key) == 0)
-			bpf_delete_elem(map_fd[0], &next_key);
-		sleep(1);
-	}
-
-	return 0;
-}
diff --git a/samples/bpf/test_cgrp2_array_pin.c b/samples/bpf/test_cgrp2_array_pin.c
deleted file mode 100644
index 70e86f7be69d..000000000000
--- a/samples/bpf/test_cgrp2_array_pin.c
+++ /dev/null
@@ -1,109 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/unistd.h>
-#include <linux/bpf.h>
-
-#include <stdio.h>
-#include <stdint.h>
-#include <unistd.h>
-#include <string.h>
-#include <errno.h>
-#include <fcntl.h>
-
-#include "libbpf.h"
-
-static void usage(void)
-{
-	printf("Usage: test_cgrp2_array_pin [...]\n");
-	printf("       -F <file>   File to pin an BPF cgroup array\n");
-	printf("       -U <file>   Update an already pinned BPF cgroup array\n");
-	printf("       -v <value>  Full path of the cgroup2\n");
-	printf("       -h          Display this help\n");
-}
-
-int main(int argc, char **argv)
-{
-	const char *pinned_file = NULL, *cg2 = NULL;
-	int create_array = 1;
-	int array_key = 0;
-	int array_fd = -1;
-	int cg2_fd = -1;
-	int ret = -1;
-	int opt;
-
-	while ((opt = getopt(argc, argv, "F:U:v:")) != -1) {
-		switch (opt) {
-		/* General args */
-		case 'F':
-			pinned_file = optarg;
-			break;
-		case 'U':
-			pinned_file = optarg;
-			create_array = 0;
-			break;
-		case 'v':
-			cg2 = optarg;
-			break;
-		default:
-			usage();
-			goto out;
-		}
-	}
-
-	if (!cg2 || !pinned_file) {
-		usage();
-		goto out;
-	}
-
-	cg2_fd = open(cg2, O_RDONLY);
-	if (cg2_fd < 0) {
-		fprintf(stderr, "open(%s,...): %s(%d)\n",
-			cg2, strerror(errno), errno);
-		goto out;
-	}
-
-	if (create_array) {
-		array_fd = bpf_create_map(BPF_MAP_TYPE_CGROUP_ARRAY,
-					  sizeof(uint32_t), sizeof(uint32_t),
-					  1, 0);
-		if (array_fd < 0) {
-			fprintf(stderr,
-				"bpf_create_map(BPF_MAP_TYPE_CGROUP_ARRAY,...): %s(%d)\n",
-				strerror(errno), errno);
-			goto out;
-		}
-	} else {
-		array_fd = bpf_obj_get(pinned_file);
-		if (array_fd < 0) {
-			fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
-				pinned_file, strerror(errno), errno);
-			goto out;
-		}
-	}
-
-	ret = bpf_update_elem(array_fd, &array_key, &cg2_fd, 0);
-	if (ret) {
-		perror("bpf_update_elem");
-		goto out;
-	}
-
-	if (create_array) {
-		ret = bpf_obj_pin(array_fd, pinned_file);
-		if (ret) {
-			fprintf(stderr, "bpf_obj_pin(..., %s): %s(%d)\n",
-				pinned_file, strerror(errno), errno);
-			goto out;
-		}
-	}
-
-out:
-	if (array_fd != -1)
-		close(array_fd);
-	if (cg2_fd != -1)
-		close(cg2_fd);
-	return ret;
-}
diff --git a/samples/bpf/test_cgrp2_attach.c b/samples/bpf/test_cgrp2_attach.c
deleted file mode 100644
index 9de4896edeef..000000000000
--- a/samples/bpf/test_cgrp2_attach.c
+++ /dev/null
@@ -1,147 +0,0 @@
-/* eBPF example program:
- *
- * - Creates arraymap in kernel with 4 bytes keys and 8 byte values
- *
- * - Loads eBPF program
- *
- *   The eBPF program accesses the map passed in to store two pieces of
- *   information. The number of invocations of the program, which maps
- *   to the number of packets received, is stored to key 0. Key 1 is
- *   incremented on each iteration by the number of bytes stored in
- *   the skb.
- *
- * - Detaches any eBPF program previously attached to the cgroup
- *
- * - Attaches the new program to a cgroup using BPF_PROG_ATTACH
- *
- * - Every second, reads map[0] and map[1] to see how many bytes and
- *   packets were seen on any socket of tasks in the given cgroup.
- */
-
-#define _GNU_SOURCE
-
-#include <stdio.h>
-#include <stdlib.h>
-#include <stddef.h>
-#include <string.h>
-#include <unistd.h>
-#include <assert.h>
-#include <errno.h>
-#include <fcntl.h>
-
-#include <linux/bpf.h>
-
-#include "libbpf.h"
-
-enum {
-	MAP_KEY_PACKETS,
-	MAP_KEY_BYTES,
-};
-
-static int prog_load(int map_fd, int verdict)
-{
-	struct bpf_insn prog[] = {
-		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1), /* save r6 so it's not clobbered by BPF_CALL */
-
-		/* Count packets */
-		BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_PACKETS), /* r0 = 0 */
-		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
-		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
-		BPF_LD_MAP_FD(BPF_REG_1, map_fd), /* load map fd to r1 */
-		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
-		BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
-		BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
-
-		/* Count bytes */
-		BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_BYTES), /* r0 = 1 */
-		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
-		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
-		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
-		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
-		BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, len)), /* r1 = skb->len */
-		BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
-
-		BPF_MOV64_IMM(BPF_REG_0, verdict), /* r0 = verdict */
-		BPF_EXIT_INSN(),
-	};
-
-	return bpf_prog_load(BPF_PROG_TYPE_CGROUP_SKB,
-			     prog, sizeof(prog), "GPL", 0);
-}
-
-static int usage(const char *argv0)
-{
-	printf("Usage: %s <cg-path> <egress|ingress> [drop]\n", argv0);
-	return EXIT_FAILURE;
-}
-
-int main(int argc, char **argv)
-{
-	int cg_fd, map_fd, prog_fd, key, ret;
-	long long pkt_cnt, byte_cnt;
-	enum bpf_attach_type type;
-	int verdict = 1;
-
-	if (argc < 3)
-		return usage(argv[0]);
-
-	if (strcmp(argv[2], "ingress") == 0)
-		type = BPF_CGROUP_INET_INGRESS;
-	else if (strcmp(argv[2], "egress") == 0)
-		type = BPF_CGROUP_INET_EGRESS;
-	else
-		return usage(argv[0]);
-
-	if (argc > 3 && strcmp(argv[3], "drop") == 0)
-		verdict = 0;
-
-	cg_fd = open(argv[1], O_DIRECTORY | O_RDONLY);
-	if (cg_fd < 0) {
-		printf("Failed to open cgroup path: '%s'\n", strerror(errno));
-		return EXIT_FAILURE;
-	}
-
-	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY,
-				sizeof(key), sizeof(byte_cnt),
-				256, 0);
-	if (map_fd < 0) {
-		printf("Failed to create map: '%s'\n", strerror(errno));
-		return EXIT_FAILURE;
-	}
-
-	prog_fd = prog_load(map_fd, verdict);
-	printf("Output from kernel verifier:\n%s\n-------\n", bpf_log_buf);
-
-	if (prog_fd < 0) {
-		printf("Failed to load prog: '%s'\n", strerror(errno));
-		return EXIT_FAILURE;
-	}
-
-	ret = bpf_prog_detach(cg_fd, type);
-	printf("bpf_prog_detach() returned '%s' (%d)\n", strerror(errno), errno);
-
-	ret = bpf_prog_attach(prog_fd, cg_fd, type, 0);
-	if (ret < 0) {
-		printf("Failed to attach prog to cgroup: '%s'\n",
-		       strerror(errno));
-		return EXIT_FAILURE;
-	}
-
-	while (1) {
-		key = MAP_KEY_PACKETS;
-		assert(bpf_lookup_elem(map_fd, &key, &pkt_cnt) == 0);
-
-		key = MAP_KEY_BYTES;
-		assert(bpf_lookup_elem(map_fd, &key, &byte_cnt) == 0);
-
-		printf("cgroup received %lld packets, %lld bytes\n",
-		       pkt_cnt, byte_cnt);
-		sleep(1);
-	}
-
-	return EXIT_SUCCESS;
-}
diff --git a/samples/bpf/test_cgrp2_tc.sh b/samples/bpf/test_cgrp2_tc.sh
deleted file mode 100755
index 0b119eeaf85c..000000000000
--- a/samples/bpf/test_cgrp2_tc.sh
+++ /dev/null
@@ -1,184 +0,0 @@
-#!/bin/bash
-
-MY_DIR=$(dirname $0)
-# Details on the bpf prog
-BPF_CGRP2_ARRAY_NAME='test_cgrp2_array_pin'
-BPF_PROG="$MY_DIR/test_cgrp2_tc_kern.o"
-BPF_SECTION='filter'
-
-[ -z "$TC" ] && TC='tc'
-[ -z "$IP" ] && IP='ip'
-
-# Names of the veth interface, net namespace...etc.
-HOST_IFC='ve'
-NS_IFC='vens'
-NS='ns'
-
-find_mnt() {
-    cat /proc/mounts | \
-	awk '{ if ($3 == "'$1'" && mnt == "") { mnt = $2 }} END { print mnt }'
-}
-
-# Init cgroup2 vars
-init_cgrp2_vars() {
-    CGRP2_ROOT=$(find_mnt cgroup2)
-    if [ -z "$CGRP2_ROOT" ]
-    then
-	CGRP2_ROOT='/mnt/cgroup2'
-	MOUNT_CGRP2="yes"
-    fi
-    CGRP2_TC="$CGRP2_ROOT/tc"
-    CGRP2_TC_LEAF="$CGRP2_TC/leaf"
-}
-
-# Init bpf fs vars
-init_bpf_fs_vars() {
-    local bpf_fs_root=$(find_mnt bpf)
-    [ -n "$bpf_fs_root" ] || return -1
-    BPF_FS_TC_SHARE="$bpf_fs_root/tc/globals"
-}
-
-setup_cgrp2() {
-    case $1 in
-	start)
-	    if [ "$MOUNT_CGRP2" == 'yes' ]
-	    then
-		[ -d $CGRP2_ROOT ] || mkdir -p $CGRP2_ROOT
-		mount -t cgroup2 none $CGRP2_ROOT || return $?
-	    fi
-	    mkdir -p $CGRP2_TC_LEAF
-	    ;;
-	*)
-	    rmdir $CGRP2_TC_LEAF && rmdir $CGRP2_TC
-	    [ "$MOUNT_CGRP2" == 'yes' ] && umount $CGRP2_ROOT
-	    ;;
-    esac
-}
-
-setup_bpf_cgrp2_array() {
-    local bpf_cgrp2_array="$BPF_FS_TC_SHARE/$BPF_CGRP2_ARRAY_NAME"
-    case $1 in
-	start)
-	    $MY_DIR/test_cgrp2_array_pin -U $bpf_cgrp2_array -v $CGRP2_TC
-	    ;;
-	*)
-	    [ -d "$BPF_FS_TC_SHARE" ] && rm -f $bpf_cgrp2_array
-	    ;;
-    esac
-}
-
-setup_net() {
-    case $1 in
-	start)
-	    $IP link add $HOST_IFC type veth peer name $NS_IFC || return $?
-	    $IP link set dev $HOST_IFC up || return $?
-	    sysctl -q net.ipv6.conf.$HOST_IFC.accept_dad=0
-
-	    $IP netns add ns || return $?
-	    $IP link set dev $NS_IFC netns ns || return $?
-	    $IP -n $NS link set dev $NS_IFC up || return $?
-	    $IP netns exec $NS sysctl -q net.ipv6.conf.$NS_IFC.accept_dad=0
-	    $TC qdisc add dev $HOST_IFC clsact || return $?
-	    $TC filter add dev $HOST_IFC egress bpf da obj $BPF_PROG sec $BPF_SECTION || return $?
-	    ;;
-	*)
-	    $IP netns del $NS
-	    $IP link del $HOST_IFC
-	    ;;
-    esac
-}
-
-run_in_cgrp() {
-    # Fork another bash and move it under the specified cgroup.
-    # It makes the cgroup cleanup easier at the end of the test.
-    cmd='echo $$ > '
-    cmd="$cmd $1/cgroup.procs; exec $2"
-    bash -c "$cmd"
-}
-
-do_test() {
-    run_in_cgrp $CGRP2_TC_LEAF "ping -6 -c3 ff02::1%$HOST_IFC >& /dev/null"
-    local dropped=$($TC -s qdisc show dev $HOST_IFC | tail -3 | \
-			   awk '/drop/{print substr($7, 0, index($7, ",")-1)}')
-    if [[ $dropped -eq 0 ]]
-    then
-	echo "FAIL"
-	return 1
-    else
-	echo "Successfully filtered $dropped packets"
-	return 0
-    fi
-}
-
-do_exit() {
-    if [ "$DEBUG" == "yes" ] && [ "$MODE" != 'cleanuponly' ]
-    then
-	echo "------ DEBUG ------"
-	echo "mount: "; mount | egrep '(cgroup2|bpf)'; echo
-	echo "$CGRP2_TC_LEAF: "; ls -l $CGRP2_TC_LEAF; echo
-	if [ -d "$BPF_FS_TC_SHARE" ]
-	then
-	    echo "$BPF_FS_TC_SHARE: "; ls -l $BPF_FS_TC_SHARE; echo
-	fi
-	echo "Host net:"
-	$IP netns
-	$IP link show dev $HOST_IFC
-	$IP -6 a show dev $HOST_IFC
-	$TC -s qdisc show dev $HOST_IFC
-	echo
-	echo "$NS net:"
-	$IP -n $NS link show dev $NS_IFC
-	$IP -n $NS -6 link show dev $NS_IFC
-	echo "------ DEBUG ------"
-	echo
-    fi
-
-    if [ "$MODE" != 'nocleanup' ]
-    then
-	setup_net stop
-	setup_bpf_cgrp2_array stop
-	setup_cgrp2 stop
-    fi
-}
-
-init_cgrp2_vars
-init_bpf_fs_vars
-
-while [[ $# -ge 1 ]]
-do
-    a="$1"
-    case $a in
-	debug)
-	    DEBUG='yes'
-	    shift 1
-	    ;;
-	cleanup-only)
-	    MODE='cleanuponly'
-	    shift 1
-	    ;;
-	no-cleanup)
-	    MODE='nocleanup'
-	    shift 1
-	    ;;
-	*)
-	    echo "test_cgrp2_tc [debug] [cleanup-only | no-cleanup]"
-	    echo "  debug: Print cgrp and network setup details at the end of the test"
-	    echo "  cleanup-only: Try to cleanup things from last test.  No test will be run"
-	    echo "  no-cleanup: Run the test but don't do cleanup at the end"
-	    echo "[Note: If no arg is given, it will run the test and do cleanup at the end]"
-	    echo
-	    exit -1
-	    ;;
-    esac
-done
-
-trap do_exit 0
-
-[ "$MODE" == 'cleanuponly' ] && exit
-
-setup_cgrp2 start || exit $?
-setup_net start || exit $?
-init_bpf_fs_vars || exit $?
-setup_bpf_cgrp2_array start || exit $?
-do_test
-echo
diff --git a/samples/bpf/test_cgrp2_tc_kern.c b/samples/bpf/test_cgrp2_tc_kern.c
deleted file mode 100644
index 10ff73404e3a..000000000000
--- a/samples/bpf/test_cgrp2_tc_kern.c
+++ /dev/null
@@ -1,69 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <uapi/linux/if_ether.h>
-#include <uapi/linux/in6.h>
-#include <uapi/linux/ipv6.h>
-#include <uapi/linux/pkt_cls.h>
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-
-/* copy of 'struct ethhdr' without __packed */
-struct eth_hdr {
-	unsigned char   h_dest[ETH_ALEN];
-	unsigned char   h_source[ETH_ALEN];
-	unsigned short  h_proto;
-};
-
-#define PIN_GLOBAL_NS		2
-struct bpf_elf_map {
-	__u32 type;
-	__u32 size_key;
-	__u32 size_value;
-	__u32 max_elem;
-	__u32 flags;
-	__u32 id;
-	__u32 pinning;
-};
-
-struct bpf_elf_map SEC("maps") test_cgrp2_array_pin = {
-	.type		= BPF_MAP_TYPE_CGROUP_ARRAY,
-	.size_key	= sizeof(uint32_t),
-	.size_value	= sizeof(uint32_t),
-	.pinning	= PIN_GLOBAL_NS,
-	.max_elem	= 1,
-};
-
-SEC("filter")
-int handle_egress(struct __sk_buff *skb)
-{
-	void *data = (void *)(long)skb->data;
-	struct eth_hdr *eth = data;
-	struct ipv6hdr *ip6h = data + sizeof(*eth);
-	void *data_end = (void *)(long)skb->data_end;
-	char dont_care_msg[] = "dont care %04x %d\n";
-	char pass_msg[] = "pass\n";
-	char reject_msg[] = "reject\n";
-
-	/* single length check */
-	if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
-		return TC_ACT_OK;
-
-	if (eth->h_proto != htons(ETH_P_IPV6) ||
-	    ip6h->nexthdr != IPPROTO_ICMPV6) {
-		bpf_trace_printk(dont_care_msg, sizeof(dont_care_msg),
-				 eth->h_proto, ip6h->nexthdr);
-		return TC_ACT_OK;
-	} else if (bpf_skb_under_cgroup(skb, &test_cgrp2_array_pin, 0) != 1) {
-		bpf_trace_printk(pass_msg, sizeof(pass_msg));
-		return TC_ACT_OK;
-	} else {
-		bpf_trace_printk(reject_msg, sizeof(reject_msg));
-		return TC_ACT_SHOT;
-	}
-}
-
-char _license[] SEC("license") = "GPL";
diff --git a/samples/bpf/test_cls_bpf.sh b/samples/bpf/test_cls_bpf.sh
deleted file mode 100755
index 0365d5ee512c..000000000000
--- a/samples/bpf/test_cls_bpf.sh
+++ /dev/null
@@ -1,37 +0,0 @@
-#!/bin/bash
-
-function pktgen {
-    ../pktgen/pktgen_bench_xmit_mode_netif_receive.sh -i $IFC -s 64 \
-        -m 90:e2:ba:ff:ff:ff -d 192.168.0.1 -t 4
-    local dropped=`tc -s qdisc show dev $IFC | tail -3 | awk '/drop/{print $7}'`
-    if [ "$dropped" == "0," ]; then
-        echo "FAIL"
-    else
-        echo "Successfully filtered " $dropped " packets"
-    fi
-}
-
-function test {
-    echo -n "Loading bpf program '$2'... "
-    tc qdisc add dev $IFC clsact
-    tc filter add dev $IFC ingress bpf da obj $1 sec $2
-    local status=$?
-    if [ $status -ne 0 ]; then
-        echo "FAIL"
-    else
-        echo "ok"
-	pktgen
-    fi
-    tc qdisc del dev $IFC clsact
-}
-
-IFC=test_veth
-
-ip link add name $IFC type veth peer name pair_$IFC
-ip link set $IFC up
-ip link set pair_$IFC up
-
-test ./parse_simple.o simple
-test ./parse_varlen.o varlen
-test ./parse_ldabs.o ldabs
-ip link del dev $IFC
diff --git a/samples/bpf/test_maps.c b/samples/bpf/test_maps.c
index 7bd9edd02d9b..6299ee95cd11 100644
--- a/samples/bpf/test_maps.c
+++ b/samples/bpf/test_maps.c
@@ -2,7 +2,6 @@
  * Testsuite for eBPF maps
  *
  * Copyright (c) 2014 PLUMgrid, http://plumgrid.com
- * Copyright (c) 2016 Facebook
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of version 2 of the GNU General Public
@@ -18,16 +17,13 @@
 #include <stdlib.h>
 #include "libbpf.h"
 
-static int map_flags;
-
 /* sanity tests for map API */
 static void test_hashmap_sanity(int i, void *data)
 {
 	long long key, next_key, value;
 	int map_fd;
 
-	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
-				2, map_flags);
+	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), 2);
 	if (map_fd < 0) {
 		printf("failed to create hashmap '%s'\n", strerror(errno));
 		exit(1);
@@ -93,107 +89,12 @@ static void test_hashmap_sanity(int i, void *data)
 	close(map_fd);
 }
 
-/* sanity tests for percpu map API */
-static void test_percpu_hashmap_sanity(int task, void *data)
-{
-	long long key, next_key;
-	int expected_key_mask = 0;
-	unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
-	long long value[nr_cpus];
-	int map_fd, i;
-
-	map_fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_HASH, sizeof(key),
-				sizeof(value[0]), 2, map_flags);
-	if (map_fd < 0) {
-		printf("failed to create hashmap '%s'\n", strerror(errno));
-		exit(1);
-	}
-
-	for (i = 0; i < nr_cpus; i++)
-		value[i] = i + 100;
-	key = 1;
-	/* insert key=1 element */
-	assert(!(expected_key_mask & key));
-	assert(bpf_update_elem(map_fd, &key, value, BPF_ANY) == 0);
-	expected_key_mask |= key;
-
-	/* BPF_NOEXIST means: add new element if it doesn't exist */
-	assert(bpf_update_elem(map_fd, &key, value, BPF_NOEXIST) == -1 &&
-	       /* key=1 already exists */
-	       errno == EEXIST);
-
-	/* -1 is an invalid flag */
-	assert(bpf_update_elem(map_fd, &key, value, -1) == -1 &&
-	       errno == EINVAL);
-
-	/* check that key=1 can be found. value could be 0 if the lookup
-	 * was run from a different cpu.
-	 */
-	value[0] = 1;
-	assert(bpf_lookup_elem(map_fd, &key, value) == 0 && value[0] == 100);
-
-	key = 2;
-	/* check that key=2 is not found */
-	assert(bpf_lookup_elem(map_fd, &key, value) == -1 && errno == ENOENT);
-
-	/* BPF_EXIST means: update existing element */
-	assert(bpf_update_elem(map_fd, &key, value, BPF_EXIST) == -1 &&
-	       /* key=2 is not there */
-	       errno == ENOENT);
-
-	/* insert key=2 element */
-	assert(!(expected_key_mask & key));
-	assert(bpf_update_elem(map_fd, &key, value, BPF_NOEXIST) == 0);
-	expected_key_mask |= key;
-
-	/* key=1 and key=2 were inserted, check that key=0 cannot be inserted
-	 * due to max_entries limit
-	 */
-	key = 0;
-	assert(bpf_update_elem(map_fd, &key, value, BPF_NOEXIST) == -1 &&
-	       errno == E2BIG);
-
-	/* check that key = 0 doesn't exist */
-	assert(bpf_delete_elem(map_fd, &key) == -1 && errno == ENOENT);
-
-	/* iterate over two elements */
-	while (!bpf_get_next_key(map_fd, &key, &next_key)) {
-		assert((expected_key_mask & next_key) == next_key);
-		expected_key_mask &= ~next_key;
-
-		assert(bpf_lookup_elem(map_fd, &next_key, value) == 0);
-		for (i = 0; i < nr_cpus; i++)
-			assert(value[i] == i + 100);
-
-		key = next_key;
-	}
-	assert(errno == ENOENT);
-
-	/* Update with BPF_EXIST */
-	key = 1;
-	assert(bpf_update_elem(map_fd, &key, value, BPF_EXIST) == 0);
-
-	/* delete both elements */
-	key = 1;
-	assert(bpf_delete_elem(map_fd, &key) == 0);
-	key = 2;
-	assert(bpf_delete_elem(map_fd, &key) == 0);
-	assert(bpf_delete_elem(map_fd, &key) == -1 && errno == ENOENT);
-
-	key = 0;
-	/* check that map is empty */
-	assert(bpf_get_next_key(map_fd, &key, &next_key) == -1 &&
-	       errno == ENOENT);
-	close(map_fd);
-}
-
 static void test_arraymap_sanity(int i, void *data)
 {
 	int key, next_key, map_fd;
 	long long value;
 
-	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
-				2, 0);
+	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 2);
 	if (map_fd < 0) {
 		printf("failed to create arraymap '%s'\n", strerror(errno));
 		exit(1);
@@ -241,94 +142,6 @@ static void test_arraymap_sanity(int i, void *data)
 	close(map_fd);
 }
 
-static void test_percpu_arraymap_many_keys(void)
-{
-	unsigned nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
-	unsigned nr_keys = 20000;
-	long values[nr_cpus];
-	int key, map_fd, i;
-
-	map_fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(key),
-				sizeof(values[0]), nr_keys, 0);
-	if (map_fd < 0) {
-		printf("failed to create per-cpu arraymap '%s'\n",
-		       strerror(errno));
-		exit(1);
-	}
-
-	for (i = 0; i < nr_cpus; i++)
-		values[i] = i + 10;
-
-	for (key = 0; key < nr_keys; key++)
-		assert(bpf_update_elem(map_fd, &key, values, BPF_ANY) == 0);
-
-	for (key = 0; key < nr_keys; key++) {
-		for (i = 0; i < nr_cpus; i++)
-			values[i] = 0;
-		assert(bpf_lookup_elem(map_fd, &key, values) == 0);
-		for (i = 0; i < nr_cpus; i++)
-			assert(values[i] == i + 10);
-	}
-
-	close(map_fd);
-}
-
-static void test_percpu_arraymap_sanity(int i, void *data)
-{
-	unsigned nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
-	long values[nr_cpus];
-	int key, next_key, map_fd;
-
-	map_fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(key),
-				sizeof(values[0]), 2, 0);
-	if (map_fd < 0) {
-		printf("failed to create arraymap '%s'\n", strerror(errno));
-		exit(1);
-	}
-
-	for (i = 0; i < nr_cpus; i++)
-		values[i] = i + 100;
-
-	key = 1;
-	/* insert key=1 element */
-	assert(bpf_update_elem(map_fd, &key, values, BPF_ANY) == 0);
-
-	values[0] = 0;
-	assert(bpf_update_elem(map_fd, &key, values, BPF_NOEXIST) == -1 &&
-	       errno == EEXIST);
-
-	/* check that key=1 can be found */
-	assert(bpf_lookup_elem(map_fd, &key, values) == 0 && values[0] == 100);
-
-	key = 0;
-	/* check that key=0 is also found and zero initialized */
-	assert(bpf_lookup_elem(map_fd, &key, values) == 0 &&
-	       values[0] == 0 && values[nr_cpus - 1] == 0);
-
-
-	/* check that key=2 cannot be inserted due to max_entries limit */
-	key = 2;
-	assert(bpf_update_elem(map_fd, &key, values, BPF_EXIST) == -1 &&
-	       errno == E2BIG);
-
-	/* check that key = 2 doesn't exist */
-	assert(bpf_lookup_elem(map_fd, &key, values) == -1 && errno == ENOENT);
-
-	/* iterate over two elements */
-	assert(bpf_get_next_key(map_fd, &key, &next_key) == 0 &&
-	       next_key == 0);
-	assert(bpf_get_next_key(map_fd, &next_key, &next_key) == 0 &&
-	       next_key == 1);
-	assert(bpf_get_next_key(map_fd, &next_key, &next_key) == -1 &&
-	       errno == ENOENT);
-
-	/* delete shouldn't succeed */
-	key = 1;
-	assert(bpf_delete_elem(map_fd, &key) == -1 && errno == EINVAL);
-
-	close(map_fd);
-}
-
 #define MAP_SIZE (32 * 1024)
 static void test_map_large(void)
 {
@@ -341,7 +154,7 @@ static void test_map_large(void)
 
 	/* allocate 4Mbyte of memory */
 	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
-				MAP_SIZE, map_flags);
+				MAP_SIZE);
 	if (map_fd < 0) {
 		printf("failed to create large map '%s'\n", strerror(errno));
 		exit(1);
@@ -396,9 +209,7 @@ static void run_parallel(int tasks, void (*fn)(int i, void *data), void *data)
 static void test_map_stress(void)
 {
 	run_parallel(100, test_hashmap_sanity, NULL);
-	run_parallel(100, test_percpu_hashmap_sanity, NULL);
 	run_parallel(100, test_arraymap_sanity, NULL);
-	run_parallel(100, test_percpu_arraymap_sanity, NULL);
 }
 
 #define TASKS 1024
@@ -426,7 +237,7 @@ static void test_map_parallel(void)
 	int data[2];
 
 	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
-				MAP_SIZE, map_flags);
+				MAP_SIZE);
 	if (map_fd < 0) {
 		printf("failed to create map for parallel test '%s'\n",
 		       strerror(errno));
@@ -471,11 +282,7 @@ static void test_map_parallel(void)
 int main(void)
 {
 	test_hashmap_sanity(0, NULL);
-	test_percpu_hashmap_sanity(0, NULL);
 	test_arraymap_sanity(0, NULL);
-	test_percpu_arraymap_sanity(0, NULL);
-	test_percpu_arraymap_many_keys();
-
 	test_map_large();
 	test_map_parallel();
 	test_map_stress();
diff --git a/samples/bpf/test_overhead_kprobe_kern.c b/samples/bpf/test_overhead_kprobe_kern.c
deleted file mode 100644
index 468a66a92ef9..000000000000
--- a/samples/bpf/test_overhead_kprobe_kern.c
+++ /dev/null
@@ -1,41 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <linux/version.h>
-#include <linux/ptrace.h>
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-
-#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
-
-SEC("kprobe/__set_task_comm")
-int prog(struct pt_regs *ctx)
-{
-	struct signal_struct *signal;
-	struct task_struct *tsk;
-	char oldcomm[16] = {};
-	char newcomm[16] = {};
-	u16 oom_score_adj;
-	u32 pid;
-
-	tsk = (void *)PT_REGS_PARM1(ctx);
-
-	pid = _(tsk->pid);
-	bpf_probe_read(oldcomm, sizeof(oldcomm), &tsk->comm);
-	bpf_probe_read(newcomm, sizeof(newcomm), (void *)PT_REGS_PARM2(ctx));
-	signal = _(tsk->signal);
-	oom_score_adj = _(signal->oom_score_adj);
-	return 0;
-}
-
-SEC("kprobe/urandom_read")
-int prog2(struct pt_regs *ctx)
-{
-	return 0;
-}
-
-char _license[] SEC("license") = "GPL";
-u32 _version SEC("version") = LINUX_VERSION_CODE;
diff --git a/samples/bpf/test_overhead_tp_kern.c b/samples/bpf/test_overhead_tp_kern.c
deleted file mode 100644
index 38f5c0b9da9f..000000000000
--- a/samples/bpf/test_overhead_tp_kern.c
+++ /dev/null
@@ -1,36 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#include <uapi/linux/bpf.h>
-#include "bpf_helpers.h"
-
-/* from /sys/kernel/debug/tracing/events/task/task_rename/format */
-struct task_rename {
-	__u64 pad;
-	__u32 pid;
-	char oldcomm[16];
-	char newcomm[16];
-	__u16 oom_score_adj;
-};
-SEC("tracepoint/task/task_rename")
-int prog(struct task_rename *ctx)
-{
-	return 0;
-}
-
-/* from /sys/kernel/debug/tracing/events/random/urandom_read/format */
-struct urandom_read {
-	__u64 pad;
-	int got_bits;
-	int pool_left;
-	int input_left;
-};
-SEC("tracepoint/random/urandom_read")
-int prog2(struct urandom_read *ctx)
-{
-	return 0;
-}
-char _license[] SEC("license") = "GPL";
diff --git a/samples/bpf/test_overhead_user.c b/samples/bpf/test_overhead_user.c
deleted file mode 100644
index d291167fd3c7..000000000000
--- a/samples/bpf/test_overhead_user.c
+++ /dev/null
@@ -1,162 +0,0 @@
-/* Copyright (c) 2016 Facebook
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of version 2 of the GNU General Public
- * License as published by the Free Software Foundation.
- */
-#define _GNU_SOURCE
-#include <sched.h>
-#include <stdio.h>
-#include <sys/types.h>
-#include <asm/unistd.h>
-#include <fcntl.h>
-#include <unistd.h>
-#include <assert.h>
-#include <sys/wait.h>
-#include <stdlib.h>
-#include <signal.h>
-#include <linux/bpf.h>
-#include <string.h>
-#include <time.h>
-#include <sys/resource.h>
-#include "libbpf.h"
-#include "bpf_load.h"
-
-#define MAX_CNT 1000000
-
-static __u64 time_get_ns(void)
-{
-	struct timespec ts;
-
-	clock_gettime(CLOCK_MONOTONIC, &ts);
-	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
-}
-
-static void test_task_rename(int cpu)
-{
-	__u64 start_time;
-	char buf[] = "test\n";
-	int i, fd;
-
-	fd = open("/proc/self/comm", O_WRONLY|O_TRUNC);
-	if (fd < 0) {
-		printf("couldn't open /proc\n");
-		exit(1);
-	}
-	start_time = time_get_ns();
-	for (i = 0; i < MAX_CNT; i++)
-		write(fd, buf, sizeof(buf));
-	printf("task_rename:%d: %lld events per sec\n",
-	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
-	close(fd);
-}
-
-static void test_urandom_read(int cpu)
-{
-	__u64 start_time;
-	char buf[4];
-	int i, fd;
-
-	fd = open("/dev/urandom", O_RDONLY);
-	if (fd < 0) {
-		printf("couldn't open /dev/urandom\n");
-		exit(1);
-	}
-	start_time = time_get_ns();
-	for (i = 0; i < MAX_CNT; i++)
-		read(fd, buf, sizeof(buf));
-	printf("urandom_read:%d: %lld events per sec\n",
-	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
-	close(fd);
-}
-
-static void loop(int cpu, int flags)
-{
-	cpu_set_t cpuset;
-
-	CPU_ZERO(&cpuset);
-	CPU_SET(cpu, &cpuset);
-	sched_setaffinity(0, sizeof(cpuset), &cpuset);
-
-	if (flags & 1)
-		test_task_rename(cpu);
-	if (flags & 2)
-		test_urandom_read(cpu);
-}
-
-static void run_perf_test(int tasks, int flags)
-{
-	pid_t pid[tasks];
-	int i;
-
-	for (i = 0; i < tasks; i++) {
-		pid[i] = fork();
-		if (pid[i] == 0) {
-			loop(i, flags);
-			exit(0);
-		} else if (pid[i] == -1) {
-			printf("couldn't spawn #%d process\n", i);
-			exit(1);
-		}
-	}
-	for (i = 0; i < tasks; i++) {
-		int status;
-
-		assert(waitpid(pid[i], &status, 0) == pid[i]);
-		assert(status == 0);
-	}
-}
-
-static void unload_progs(void)
-{
-	close(prog_fd[0]);
-	close(prog_fd[1]);
-	close(event_fd[0]);
-	close(event_fd[1]);
-}
-
-int main(int argc, char **argv)
-{
-	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
-	char filename[256];
-	int num_cpu = 8;
-	int test_flags = ~0;
-
-	setrlimit(RLIMIT_MEMLOCK, &r);
-
-	if (argc > 1)
-		test_flags = atoi(argv[1]) ? : test_flags;
-	if (argc > 2)
-		num_cpu = atoi(argv[2]) ? : num_cpu;
-
-	if (test_flags & 0x3) {
-		printf("BASE\n");
-		run_perf_test(num_cpu, test_flags);
-	}
-
-	if (test_flags & 0xC) {
-		snprintf(filename, sizeof(filename),
-			 "%s_kprobe_kern.o", argv[0]);
-		if (load_bpf_file(filename)) {
-			printf("%s", bpf_log_buf);
-			return 1;
-		}
-		printf("w/KPROBE\n");
-		run_perf_test(num_cpu, test_flags >> 2);
-		unload_progs();
-	}
-
-	if (test_flags & 0x30) {
-		snprintf(filename, sizeof(filename),
-			 "%s_tp_kern.o", argv[0]);
-		if (load_bpf_file(filename)) {
-			printf("%s", bpf_log_buf);
-			return 1;
-		}
-		printf("w/TRACEPOINT\n");
-		run_perf_test(num_cpu, test_flags >> 4);
-		unload_progs();
-	}
-
-	return 0;
-}
diff --git a/samples/bpf/test_verifier.c b/samples/bpf/test_verifier.c
index dc7dec9e64ba..563c507c0a09 100644
--- a/samples/bpf/test_verifier.c
+++ b/samples/bpf/test_verifier.c
@@ -29,7 +29,6 @@ struct bpf_test {
 	struct bpf_insn	insns[MAX_INSNS];
 	int fixup[MAX_FIXUPS];
 	int prog_array_fixup[MAX_FIXUPS];
-	int test_val_map_fixup[MAX_FIXUPS];
 	const char *errstr;
 	const char *errstr_unpriv;
 	enum {
@@ -40,19 +39,6 @@ struct bpf_test {
 	enum bpf_prog_type prog_type;
 };
 
-/* Note we want this to be 64 bit aligned so that the end of our array is
- * actually the end of the structure.
- */
-#define MAX_ENTRIES 11
-struct test_val {
-	unsigned index;
-	int foo[MAX_ENTRIES];
-};
-
-struct other_val {
-	unsigned int action[32];
-};
-
 static struct bpf_test tests[] = {
 	{
 		"add+sub+mul",
@@ -304,29 +290,6 @@ static struct bpf_test tests[] = {
 		.errstr = "invalid read from stack",
 		.result = REJECT,
 	},
-	{
-		"invalid argument register",
-		.insns = {
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_cgroup_classid),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_cgroup_classid),
-			BPF_EXIT_INSN(),
-		},
-		.errstr = "R1 !read_ok",
-		.result = REJECT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"non-invalid argument register",
-		.insns = {
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_cgroup_classid),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_1, BPF_REG_6),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_cgroup_classid),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
 	{
 		"check valid spill/fill",
 		.insns = {
@@ -345,19 +308,6 @@ static struct bpf_test tests[] = {
 		.result = ACCEPT,
 		.result_unpriv = REJECT,
 	},
-	{
-		"check valid spill/fill, skb mark",
-		.insns = {
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
-			BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -8),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),
-			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
-				    offsetof(struct __sk_buff, mark)),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.result_unpriv = ACCEPT,
-	},
 	{
 		"check corrupted spill/fill",
 		.insns = {
@@ -1218,1176 +1168,17 @@ static struct bpf_test tests[] = {
 		.result = ACCEPT,
 	},
 	{
-		"stack pointer arithmetic",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_1, 4),
-			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
-			BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -10),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1),
-			BPF_ST_MEM(0, BPF_REG_2, 4, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8),
-			BPF_ST_MEM(0, BPF_REG_2, 4, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-	},
-	{
-		"raw_stack: no skb_load_bytes",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			/* Call to skb_load_bytes() omitted. */
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid read from stack off -8+0 size 8",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, negative len",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, -8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, negative len 2",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, ~0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, zero len",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, no init",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, init",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_ST_MEM(BPF_DW, BPF_REG_6, 0, 0xcafe),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, spilled regs around bounds",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -16),
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8), /* spill ctx from R1 */
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  8), /* spill ctx from R1 */
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, -8), /* fill ctx into R0 */
-			BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,  8), /* fill ctx into R2 */
-			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
-				    offsetof(struct __sk_buff, mark)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2,
-				    offsetof(struct __sk_buff, priority)),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, spilled regs corruption",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0), /* spill ctx from R1 */
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0), /* fill ctx into R0 */
-			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
-				    offsetof(struct __sk_buff, mark)),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "R0 invalid mem access 'inv'",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, spilled regs corruption 2",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -16),
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8), /* spill ctx from R1 */
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  0), /* spill ctx from R1 */
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  8), /* spill ctx from R1 */
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, -8), /* fill ctx into R0 */
-			BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,  8), /* fill ctx into R2 */
-			BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_6,  0), /* fill ctx into R3 */
-			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
-				    offsetof(struct __sk_buff, mark)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2,
-				    offsetof(struct __sk_buff, priority)),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_3,
-				    offsetof(struct __sk_buff, pkt_type)),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_3),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "R3 invalid mem access 'inv'",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, spilled regs + data",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -16),
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8), /* spill ctx from R1 */
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  0), /* spill ctx from R1 */
-			BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  8), /* spill ctx from R1 */
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, -8), /* fill ctx into R0 */
-			BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,  8), /* fill ctx into R2 */
-			BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_6,  0), /* fill data into R3 */
-			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
-				    offsetof(struct __sk_buff, mark)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2,
-				    offsetof(struct __sk_buff, priority)),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_3),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, invalid access 1",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -513),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3 off=-513 access_size=8",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, invalid access 2",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -1),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 8),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3 off=-1 access_size=8",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, invalid access 3",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 0xffffffff),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 0xffffffff),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3 off=-1 access_size=-1",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, invalid access 4",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -1),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 0x7fffffff),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3 off=-1 access_size=2147483647",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, invalid access 5",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -512),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 0x7fffffff),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3 off=-512 access_size=2147483647",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, invalid access 6",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -512),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid stack type R3 off=-512 access_size=0",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"raw_stack: skb_load_bytes, large access",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -512),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_4, 512),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test1",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test2",
-		.insns = {
-			BPF_MOV64_IMM(BPF_REG_0, 1),
-			BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_MOV64_REG(BPF_REG_5, BPF_REG_3),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 14),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_4, 15),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_3, 7),
-			BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_3, 12),
-			BPF_ALU64_IMM(BPF_MUL, BPF_REG_4, 14),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_4),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
-			BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 48),
-			BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 48),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_2),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_3),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8),
-			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_2, BPF_REG_1, 1),
-			BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_3, 4),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test3",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.errstr = "invalid bpf_context access off=76",
-		.result = REJECT,
-		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
-	},
-	{
-		"direct packet access: test4 (write)",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
-			BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test5 (pkt_end >= reg, good access)",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGE, BPF_REG_3, BPF_REG_0, 2),
-			BPF_MOV64_IMM(BPF_REG_0, 1),
-			BPF_EXIT_INSN(),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test6 (pkt_end >= reg, bad access)",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGE, BPF_REG_3, BPF_REG_0, 3),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 1),
-			BPF_EXIT_INSN(),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.errstr = "invalid access to packet",
-		.result = REJECT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test7 (pkt_end >= reg, both accesses)",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGE, BPF_REG_3, BPF_REG_0, 3),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 1),
-			BPF_EXIT_INSN(),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.errstr = "invalid access to packet",
-		.result = REJECT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test8 (double test, variant 1)",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGE, BPF_REG_3, BPF_REG_0, 4),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 1),
-			BPF_EXIT_INSN(),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test9 (double test, variant 2)",
+		"unpriv: obfuscate stack pointer",
 		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGE, BPF_REG_3, BPF_REG_0, 2),
-			BPF_MOV64_IMM(BPF_REG_0, 1),
-			BPF_EXIT_INSN(),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
-			BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
+			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
+			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
+			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
 			BPF_MOV64_IMM(BPF_REG_0, 0),
 			BPF_EXIT_INSN(),
 		},
+		.errstr_unpriv = "R2 pointer arithmetic",
+		.result_unpriv = REJECT,
 		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"direct packet access: test10 (write invalid)",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 2),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-			BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.errstr = "invalid access to packet",
-		.result = REJECT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test1, valid packet_ptr range",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct xdp_md, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct xdp_md, data_end)),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 5),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_2),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {5},
-		.result_unpriv = ACCEPT,
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_XDP,
-	},
-	{
-		"helper access to packet: test2, unchecked packet_ptr",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct xdp_md, data)),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {1},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_XDP,
-	},
-	{
-		"helper access to packet: test3, variable add",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-					offsetof(struct xdp_md, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-					offsetof(struct xdp_md, data_end)),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 10),
-			BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_2, 0),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_4, BPF_REG_5),
-			BPF_MOV64_REG(BPF_REG_5, BPF_REG_4),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 4),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_4),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {11},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_XDP,
-	},
-	{
-		"helper access to packet: test4, packet_ptr with bad range",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct xdp_md, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct xdp_md, data_end)),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 4),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 2),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {7},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_XDP,
-	},
-	{
-		"helper access to packet: test5, packet_ptr with too short range",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct xdp_md, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct xdp_md, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 3),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {6},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_XDP,
-	},
-	{
-		"helper access to packet: test6, cls valid packet_ptr range",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 5),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_2),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {5},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test7, cls unchecked packet_ptr",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {1},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test8, cls variable add",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-					offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-					offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 10),
-			BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_2, 0),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_4, BPF_REG_5),
-			BPF_MOV64_REG(BPF_REG_5, BPF_REG_4),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 4),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_4),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {11},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test9, cls packet_ptr with bad range",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 4),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 2),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {7},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test10, cls packet_ptr with too short range",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
-			BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 3),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.fixup = {6},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test11, cls unsuitable helper 1",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_3, BPF_REG_7, 4),
-			BPF_MOV64_IMM(BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 42),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_store_bytes),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "helper access to the packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test12, cls unsuitable helper 2",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 8),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 3),
-			BPF_MOV64_IMM(BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 4),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "helper access to the packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test13, cls helper ok",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = ACCEPT,
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test14, cls helper fail sub",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 4),
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "type=inv expected=fp",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test15, cls helper fail range 1",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_2, 8),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test16, cls helper fail range 2",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_2, -9),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test17, cls helper fail range 3",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_2, ~0),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test18, cls helper fail range zero",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_MOV64_IMM(BPF_REG_2, 0),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test19, pkt end as input",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "R1 type=pkt_end expected=fp",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"helper access to packet: test20, wrong reg",
-		.insns = {
-			BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
-				    offsetof(struct __sk_buff, data)),
-			BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1,
-				    offsetof(struct __sk_buff, data_end)),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
-			BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_7, 6),
-			BPF_MOV64_IMM(BPF_REG_2, 4),
-			BPF_MOV64_IMM(BPF_REG_3, 0),
-			BPF_MOV64_IMM(BPF_REG_4, 0),
-			BPF_MOV64_IMM(BPF_REG_5, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_csum_diff),
-			BPF_MOV64_IMM(BPF_REG_0, 0),
-			BPF_EXIT_INSN(),
-		},
-		.result = REJECT,
-		.errstr = "invalid access to packet",
-		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
-	},
-	{
-		"valid map access into an array with a constant",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr_unpriv = "R0 leaks addr",
-		.result_unpriv = REJECT,
-		.result = ACCEPT,
-	},
-	{
-		"valid map access into an array with a register",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
-			BPF_MOV64_IMM(BPF_REG_1, 4),
-			BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr_unpriv = "R0 leaks addr",
-		.result_unpriv = REJECT,
-		.result = ACCEPT,
-	},
-	{
-		"valid map access into an array with a variable",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 5),
-			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
-			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, MAX_ENTRIES, 3),
-			BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr_unpriv = "R0 leaks addr",
-		.result_unpriv = REJECT,
-		.result = ACCEPT,
-	},
-	{
-		"valid map access into an array with a signed variable",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 9),
-			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
-			BPF_JMP_IMM(BPF_JSGT, BPF_REG_1, 0xffffffff, 1),
-			BPF_MOV32_IMM(BPF_REG_1, 0),
-			BPF_MOV32_IMM(BPF_REG_2, MAX_ENTRIES),
-			BPF_JMP_REG(BPF_JSGT, BPF_REG_2, BPF_REG_1, 1),
-			BPF_MOV32_IMM(BPF_REG_1, 0),
-			BPF_ALU32_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr_unpriv = "R0 leaks addr",
-		.result_unpriv = REJECT,
-		.result = ACCEPT,
-	},
-	{
-		"invalid map access into an array with a constant",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, (MAX_ENTRIES + 1) << 2,
-				   offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr = "invalid access to map value, value_size=48 off=48 size=8",
-		.result = REJECT,
-	},
-	{
-		"invalid map access into an array with a register",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
-			BPF_MOV64_IMM(BPF_REG_1, MAX_ENTRIES + 1),
-			BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr = "R0 min value is outside of the array range",
-		.result = REJECT,
-	},
-	{
-		"invalid map access into an array with a variable",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
-			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
-			BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr = "R0 min value is negative, either use unsigned index or do a if (index >=0) check.",
-		.result = REJECT,
-	},
-	{
-		"invalid map access into an array with no floor check",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),
-			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
-			BPF_MOV32_IMM(BPF_REG_2, MAX_ENTRIES),
-			BPF_JMP_REG(BPF_JSGT, BPF_REG_2, BPF_REG_1, 1),
-			BPF_MOV32_IMM(BPF_REG_1, 0),
-			BPF_ALU32_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr = "R0 min value is negative, either use unsigned index or do a if (index >=0) check.",
-		.result = REJECT,
-	},
-	{
-		"invalid map access into an array with a invalid max check",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),
-			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
-			BPF_MOV32_IMM(BPF_REG_2, MAX_ENTRIES + 1),
-			BPF_JMP_REG(BPF_JGT, BPF_REG_2, BPF_REG_1, 1),
-			BPF_MOV32_IMM(BPF_REG_1, 0),
-			BPF_ALU32_IMM(BPF_LSH, BPF_REG_1, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
-			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3},
-		.errstr = "invalid access to map value, value_size=48 off=44 size=8",
-		.result = REJECT,
-	},
-	{
-		"invalid map access into an array with a invalid max check",
-		.insns = {
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 10),
-			BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
-			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
-			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
-			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
-			BPF_LD_MAP_FD(BPF_REG_1, 0),
-			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
-			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
-			BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_8),
-			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, offsetof(struct test_val, foo)),
-			BPF_EXIT_INSN(),
-		},
-		.test_val_map_fixup = {3, 11},
-		.errstr = "R0 min value is negative, either use unsigned index or do a if (index >=0) check.",
-		.result = REJECT,
 	},
 };
 
@@ -2402,12 +1193,12 @@ static int probe_filter_length(struct bpf_insn *fp)
 	return len + 1;
 }
 
-static int create_map(size_t val_size, int num)
+static int create_map(void)
 {
 	int map_fd;
 
 	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH,
-				sizeof(long long), val_size, num, 0);
+				sizeof(long long), sizeof(long long), 1024);
 	if (map_fd < 0)
 		printf("failed to create map '%s'\n", strerror(errno));
 
@@ -2419,7 +1210,7 @@ static int create_prog_array(void)
 	int map_fd;
 
 	map_fd = bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY,
-				sizeof(int), sizeof(int), 4, 0);
+				sizeof(int), sizeof(int), 4);
 	if (map_fd < 0)
 		printf("failed to create prog_array '%s'\n", strerror(errno));
 
@@ -2437,13 +1228,12 @@ static int test(void)
 		int prog_len = probe_filter_length(prog);
 		int *fixup = tests[i].fixup;
 		int *prog_array_fixup = tests[i].prog_array_fixup;
-		int *test_val_map_fixup = tests[i].test_val_map_fixup;
 		int expected_result;
 		const char *expected_errstr;
-		int map_fd = -1, prog_array_fd = -1, test_val_map_fd = -1;
+		int map_fd = -1, prog_array_fd = -1;
 
 		if (*fixup) {
-			map_fd = create_map(sizeof(long long), 1024);
+			map_fd = create_map();
 
 			do {
 				prog[*fixup].imm = map_fd;
@@ -2458,18 +1248,6 @@ static int test(void)
 				prog_array_fixup++;
 			} while (*prog_array_fixup);
 		}
-		if (*test_val_map_fixup) {
-			/* Unprivileged can't create a hash map.*/
-			if (unpriv)
-				continue;
-			test_val_map_fd = create_map(sizeof(struct test_val),
-						     256);
-			do {
-				prog[*test_val_map_fixup].imm = test_val_map_fd;
-				test_val_map_fixup++;
-			} while (*test_val_map_fixup);
-		}
-
 		printf("#%d %s ", i, tests[i].descr);
 
 		prog_fd = bpf_prog_load(prog_type ?: BPF_PROG_TYPE_SOCKET_FILTER,
@@ -2516,8 +1294,6 @@ fail:
 			close(map_fd);
 		if (prog_array_fd >= 0)
 			close(prog_array_fd);
-		if (test_val_map_fd >= 0)
-			close(test_val_map_fd);
 		close(prog_fd);
 
 	}
diff --git a/scripts/mod/modpost.c b/scripts/mod/modpost.c
index a02e25acb604..f27df7605999 100644
--- a/scripts/mod/modpost.c
+++ b/scripts/mod/modpost.c
@@ -838,7 +838,6 @@ static const char *const section_white_list[] =
 	".cmem*",			/* EZchip */
 	".fmt_slot*",			/* EZchip */
 	".gnu.lto*",
-	".discard.*",
 	NULL
 };
 
diff --git a/scripts/module-common.lds b/scripts/module-common.lds
index 9b6e246a45d0..53234e85192a 100644
--- a/scripts/module-common.lds
+++ b/scripts/module-common.lds
@@ -4,10 +4,7 @@
  * combine them automatically.
  */
 SECTIONS {
-	/DISCARD/ : {
-		*(.discard)
-		*(.discard.*)
-	}
+	/DISCARD/ : { *(.discard) }
 
 	__ksymtab		0 : { *(SORT(___ksymtab+*)) }
 	__ksymtab_gpl		0 : { *(SORT(___ksymtab_gpl+*)) }
diff --git a/security/commoncap.c b/security/commoncap.c
index 0249cb9b957e..368631db0933 100644
--- a/security/commoncap.c
+++ b/security/commoncap.c
@@ -466,8 +466,6 @@ static int get_file_caps(struct linux_binprm *bprm, bool *effective, bool *has_c
 
 	if (bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID)
 		return 0;
-	if (!current_in_userns(bprm->file->f_path.mnt->mnt_sb->s_user_ns))
-		return 0;
 
 	rc = get_vfs_caps_from_disk(bprm->file->f_path.dentry, &vcaps);
 	if (rc < 0) {
diff --git a/security/security.c b/security/security.c
index 65748c3b37ef..6cced62a81b6 100644
--- a/security/security.c
+++ b/security/security.c
@@ -11,7 +11,6 @@
  *	(at your option) any later version.
  */
 
-#include <linux/bpf.h>
 #include <linux/capability.h>
 #include <linux/dcache.h>
 #include <linux/module.h>
@@ -1555,37 +1554,6 @@ int security_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
 }
 #endif /* CONFIG_AUDIT */
 
-#ifdef CONFIG_BPF_SYSCALL
-int security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
-{
-	return call_int_hook(bpf, 0, cmd, attr, size);
-}
-int security_bpf_map(struct bpf_map *map, fmode_t fmode)
-{
-	return call_int_hook(bpf_map, 0, map, fmode);
-}
-int security_bpf_prog(struct bpf_prog *prog)
-{
-	return call_int_hook(bpf_prog, 0, prog);
-}
-int security_bpf_map_alloc(struct bpf_map *map)
-{
-	return call_int_hook(bpf_map_alloc_security, 0, map);
-}
-int security_bpf_prog_alloc(struct bpf_prog_aux *aux)
-{
-	return call_int_hook(bpf_prog_alloc_security, 0, aux);
-}
-void security_bpf_map_free(struct bpf_map *map)
-{
-	call_void_hook(bpf_map_free_security, map);
-}
-void security_bpf_prog_free(struct bpf_prog_aux *aux)
-{
-	call_void_hook(bpf_prog_free_security, aux);
-}
-#endif /* CONFIG_BPF_SYSCALL */
-
 struct security_hook_heads security_hook_heads = {
 	.binder_set_context_mgr =
 		LIST_HEAD_INIT(security_hook_heads.binder_set_context_mgr),
@@ -1932,20 +1900,4 @@ struct security_hook_heads security_hook_heads = {
 	.audit_rule_free =
 		LIST_HEAD_INIT(security_hook_heads.audit_rule_free),
 #endif /* CONFIG_AUDIT */
-#ifdef CONFIG_BPF_SYSCALL
-	.bpf =
-		LIST_HEAD_INIT(security_hook_heads.bpf),
-	.bpf_map =
-		LIST_HEAD_INIT(security_hook_heads.bpf_map),
-	.bpf_prog =
-		LIST_HEAD_INIT(security_hook_heads.bpf_prog),
-	.bpf_map_alloc_security =
-		LIST_HEAD_INIT(security_hook_heads.bpf_map_alloc_security),
-	.bpf_map_free_security =
-		LIST_HEAD_INIT(security_hook_heads.bpf_map_free_security),
-	.bpf_prog_alloc_security =
-		LIST_HEAD_INIT(security_hook_heads.bpf_prog_alloc_security),
-	.bpf_prog_free_security =
-		LIST_HEAD_INIT(security_hook_heads.bpf_prog_free_security),
-#endif /* CONFIG_BPF_SYSCALL */
 };
diff --git a/security/selinux/hooks.c b/security/selinux/hooks.c
index 22baa270681f..3ccb764d4e80 100644
--- a/security/selinux/hooks.c
+++ b/security/selinux/hooks.c
@@ -83,7 +83,6 @@
 #include <linux/export.h>
 #include <linux/msg.h>
 #include <linux/shm.h>
-#include <linux/bpf.h>
 
 #include "avc.h"
 #include "objsec.h"
@@ -1678,10 +1677,6 @@ static inline int file_path_has_perm(const struct cred *cred,
 	return inode_has_perm(cred, file_inode(file), av, &ad);
 }
 
-#ifdef CONFIG_BPF_SYSCALL
-static int bpf_fd_pass(struct file *file, u32 sid);
-#endif
-
 /* Check whether a task can use an open file descriptor to
    access an inode in a given way.  Check access to the
    descriptor itself, and then use dentry_has_perm to
@@ -1712,12 +1707,6 @@ static int file_has_perm(const struct cred *cred,
 			goto out;
 	}
 
-#ifdef CONFIG_BPF_SYSCALL
-	rc = bpf_fd_pass(file, cred_sid(cred));
-	if (rc)
-		return rc;
-#endif
-
 	/* av is zero if only checking access to the descriptor. */
 	rc = 0;
 	if (av)
@@ -2041,12 +2030,6 @@ static int selinux_binder_transfer_file(const struct cred *from,
 			return rc;
 	}
 
-#ifdef CONFIG_BPF_SYSCALL
-	rc = bpf_fd_pass(file, sid);
-	if (rc)
-		return rc;
-#endif
-
 	if (unlikely(IS_PRIVATE(inode)))
 		return 0;
 
@@ -5943,139 +5926,6 @@ static int selinux_key_getsecurity(struct key *key, char **_buffer)
 
 #endif
 
-#ifdef CONFIG_BPF_SYSCALL
-static int selinux_bpf(int cmd, union bpf_attr *attr,
-				     unsigned int size)
-{
-	u32 sid = current_sid();
-	int ret;
-
-	switch (cmd) {
-	case BPF_MAP_CREATE:
-		ret = avc_has_perm(sid, sid, SECCLASS_BPF, BPF__MAP_CREATE,
-				   NULL);
-		break;
-	case BPF_PROG_LOAD:
-		ret = avc_has_perm(sid, sid, SECCLASS_BPF, BPF__PROG_LOAD,
-				   NULL);
-		break;
-	default:
-		ret = 0;
-		break;
-	}
-
-	return ret;
-}
-
-static u32 bpf_map_fmode_to_av(fmode_t fmode)
-{
-	u32 av = 0;
-
-	if (fmode & FMODE_READ)
-		av |= BPF__MAP_READ;
-	if (fmode & FMODE_WRITE)
-		av |= BPF__MAP_WRITE;
-	return av;
-}
-
-/* This function will check the file pass through unix socket or binder to see
- * if it is a bpf related object. And apply correspinding checks on the bpf
- * object based on the type. The bpf maps and programs, not like other files and
- * socket, are using a shared anonymous inode inside the kernel as their inode.
- * So checking that inode cannot identify if the process have privilege to
- * access the bpf object and that's why we have to add this additional check in
- * selinux_file_receive and selinux_binder_transfer_files.
- */
-static int bpf_fd_pass(struct file *file, u32 sid)
-{
-	struct bpf_security_struct *bpfsec;
-	struct bpf_prog *prog;
-	struct bpf_map *map;
-	int ret;
-
-	if (file->f_op == &bpf_map_fops) {
-		map = file->private_data;
-		bpfsec = map->security;
-		ret = avc_has_perm(sid, bpfsec->sid, SECCLASS_BPF,
-				   bpf_map_fmode_to_av(file->f_mode), NULL);
-		if (ret)
-			return ret;
-	} else if (file->f_op == &bpf_prog_fops) {
-		prog = file->private_data;
-		bpfsec = prog->aux->security;
-		ret = avc_has_perm(sid, bpfsec->sid, SECCLASS_BPF,
-				   BPF__PROG_RUN, NULL);
-		if (ret)
-			return ret;
-	}
-	return 0;
-}
-
-static int selinux_bpf_map(struct bpf_map *map, fmode_t fmode)
-{
-	u32 sid = current_sid();
-	struct bpf_security_struct *bpfsec;
-
-	bpfsec = map->security;
-	return avc_has_perm(sid, bpfsec->sid, SECCLASS_BPF,
-			    bpf_map_fmode_to_av(fmode), NULL);
-}
-
-static int selinux_bpf_prog(struct bpf_prog *prog)
-{
-	u32 sid = current_sid();
-	struct bpf_security_struct *bpfsec;
-
-	bpfsec = prog->aux->security;
-	return avc_has_perm(sid, bpfsec->sid, SECCLASS_BPF,
-			    BPF__PROG_RUN, NULL);
-}
-
-static int selinux_bpf_map_alloc(struct bpf_map *map)
-{
-	struct bpf_security_struct *bpfsec;
-
-	bpfsec = kzalloc(sizeof(*bpfsec), GFP_KERNEL);
-	if (!bpfsec)
-		return -ENOMEM;
-
-	bpfsec->sid = current_sid();
-	map->security = bpfsec;
-
-	return 0;
-}
-
-static void selinux_bpf_map_free(struct bpf_map *map)
-{
-	struct bpf_security_struct *bpfsec = map->security;
-
-	map->security = NULL;
-	kfree(bpfsec);
-}
-
-static int selinux_bpf_prog_alloc(struct bpf_prog_aux *aux)
-{
-	struct bpf_security_struct *bpfsec;
-
-	bpfsec = kzalloc(sizeof(*bpfsec), GFP_KERNEL);
-	if (!bpfsec)
-		return -ENOMEM;
-
-	bpfsec->sid = current_sid();
-	aux->security = bpfsec;
-
-	return 0;
-}
-
-static void selinux_bpf_prog_free(struct bpf_prog_aux *aux)
-{
-	struct bpf_security_struct *bpfsec = aux->security;
-
-	aux->security = NULL;
-	kfree(bpfsec);
-}
-#endif
-
 static struct security_hook_list selinux_hooks[] = {
 	LSM_HOOK_INIT(binder_set_context_mgr, selinux_binder_set_context_mgr),
 	LSM_HOOK_INIT(binder_transaction, selinux_binder_transaction),
@@ -6286,16 +6136,6 @@ static struct security_hook_list selinux_hooks[] = {
 	LSM_HOOK_INIT(audit_rule_match, selinux_audit_rule_match),
 	LSM_HOOK_INIT(audit_rule_free, selinux_audit_rule_free),
 #endif
-
-#ifdef CONFIG_BPF_SYSCALL
-	LSM_HOOK_INIT(bpf, selinux_bpf),
-	LSM_HOOK_INIT(bpf_map, selinux_bpf_map),
-	LSM_HOOK_INIT(bpf_prog, selinux_bpf_prog),
-	LSM_HOOK_INIT(bpf_map_alloc_security, selinux_bpf_map_alloc),
-	LSM_HOOK_INIT(bpf_prog_alloc_security, selinux_bpf_prog_alloc),
-	LSM_HOOK_INIT(bpf_map_free_security, selinux_bpf_map_free),
-	LSM_HOOK_INIT(bpf_prog_free_security, selinux_bpf_prog_free),
-#endif
 };
 
 static __init int selinux_init(void)
diff --git a/security/selinux/include/classmap.h b/security/selinux/include/classmap.h
index e5dc06b558aa..8a764f40730b 100644
--- a/security/selinux/include/classmap.h
+++ b/security/selinux/include/classmap.h
@@ -159,7 +159,5 @@ struct security_class_mapping secclass_map[] = {
 		      NULL } },
 	{ "can_socket",
 	  { COMMON_SOCK_PERMS, NULL } },
-	{ "bpf",
-	  {"map_create", "map_read", "map_write", "prog_load", "prog_run"} },
 	{ NULL }
   };
diff --git a/security/selinux/include/objsec.h b/security/selinux/include/objsec.h
index 4c31ec14dd2c..f6027d67a0e6 100644
--- a/security/selinux/include/objsec.h
+++ b/security/selinux/include/objsec.h
@@ -124,10 +124,6 @@ struct key_security_struct {
 	u32 sid;	/* SID of key */
 };
 
-struct bpf_security_struct {
-	u32 sid;  /*SID of bpf obj creater*/
-};
-
 extern unsigned int selinux_checkreqprot;
 
 #endif /* _SELINUX_OBJSEC_H_ */
