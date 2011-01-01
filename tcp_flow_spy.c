/*
 * tcpflowspy - Observe the TCP flow summerized information with kprobes.
 *  
 * This module is based on tcpflowprobe:
 * The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 *
 * Copyright (C) 2010, Soheil Hassas Yeganeh <soheil@cs.toronto.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <net/tcp.h>

//#define TCP_FLOW_SPY_DEBUG

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#define SPY_COMPAT 18
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34))
#define SPY_COMPAT 32
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
#define SPY_COMPAT 34
#else 
#define SPY_COMPAT 35 
#endif

#define HASHSIZE_COEF .4
#define HASHTABLE_SIZE ((int) (HASHSIZE_COEF*bufsize))
#define MAX_CONTINOUS 128
#define SECTION_COUNT (bufsize/MAX_CONTINOUS)

MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@cs.toronto.edu>");
MODULE_DESCRIPTION("TCP flow snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1-ALPHA");

static int port __read_mostly = 0;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

static unsigned int bufsize __read_mostly = 4096;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (4096)");
module_param(bufsize, uint, 0);

static int bucket_length __read_mostly = 1;
MODULE_PARM_DESC(bucket_length, "Length of each bucket in the histogram (1) except the last bucket length is not bounded.");
module_param(bucket_length, int, 0);

//static int number_of_buckets  __read_mostly = 1;
//MODULE_PARM_DESC(number_of_buckets, "Number of buckets in the histogram (1)");
//module_param(number_of_buckets, int, 0);

#define NUMBER_OF_BUCKETS   10

static int live __read_mostly = 0;
MODULE_PARM_DESC(live, "(0) stats of completed flows are printed, (1) stats of live flows are printed.");
module_param(live, int, 0);

static struct tcp_flow_log* last_printed_flow_log = NULL;

static const char procname[] = "tcpflowspy";

struct tcp_flow_log {
    struct timespec first_packet_tstamp;
    struct timespec last_packet_tstamp;
    struct timespec last_printed_tstamp;

    __be32	saddr, daddr;
    __be16	sport, dport;

    u32 recv_count; // No of received packets 
    u32 snd_count; // No of sent packets
    u64	recv_size; // Avg length of the packet
    u64 snd_size; // Total size of packets in byte

    u32 last_recv_seq;
    u32 last_snd_seq;

    u32 out_of_order_packets;
    u32 total_retransmissions;

    u32 snd_cwnd_clamp;
    u32	ssthresh;
    u32	srtt;
    u32 rttvar;
    u32 last_cwnd;
    u32 rto; 

    int used;

    u32 snd_cwnd_histogram[NUMBER_OF_BUCKETS];

//    spinlock_t lock;

    struct tcp_flow_log* used_thread_next;
    struct tcp_flow_log* used_thread_prev;

    struct tcp_flow_log* next;
    struct tcp_flow_log* prev;
};

static struct {
    spinlock_t	lock;
    wait_queue_head_t wait;
   	struct timespec	start;
    struct timespec last_update;
    struct timespec last_read;

    struct tcp_flow_log *available;
    struct tcp_flow_log **storage;
    struct tcp_flow_log *finished;
    struct tcp_flow_log *used;
} tcp_flow_spy;

struct hashtable_entry {
    spinlock_t lock;
    struct tcp_flow_log* head; 
    struct tcp_flow_log* tail;
};

static struct {
    u32 count;

    struct hashtable_entry* entries;   
} tcp_flow_hashtable;


static inline struct timespec get_time(void) {
    struct timespec ts;
    ktime_get_real_ts(&ts);
    return ts;
}

static inline void add_in_used(struct tcp_flow_log* log) {
    if (unlikely(!log)) {
        return;
    }    

    log->used = 1; 
    log->used_thread_next = tcp_flow_spy.used;
    log->used_thread_prev = NULL;

    if (tcp_flow_spy.used) {
        tcp_flow_spy.used->used_thread_prev = log; 
    }    

    tcp_flow_spy.used = log; 
}

static inline void remove_from_used(struct tcp_flow_log* log) {
    if (unlikely(!log)) {
        return;
    } else {
        struct tcp_flow_log* prev = log->used_thread_prev;
        struct tcp_flow_log* next = log->used_thread_next;

        if (last_printed_flow_log == log) {
            last_printed_flow_log = 0;
        }

        if (prev) { 
            prev->used_thread_next = next;
        }    

        if (next) {
            next->used_thread_prev = prev;
        }    

        if (log == tcp_flow_spy.used) {
            tcp_flow_spy.used = next;
        }    
      
        log->used_thread_next = log->used_thread_prev = NULL;
    }
}



// Soheil: I could use inet hash function, but I prefer to have my own. 
static inline u32 skb_hash_function(__be32 saddr, __be32 daddr, 
                                    __be16 sport, __be16 dport) {

    unsigned int h = (saddr ^ sport) ^ (daddr ^ dport);
    h ^= h >> 16;
    h ^= h >> 8;
    h %= HASHTABLE_SIZE;
    return h;
}

static inline struct hashtable_entry* get_entry_for_skb(
        __be32 saddr, __be32 daddr, __be16 sport, __be16 dport) {
    struct hashtable_entry* entry;
    entry = 
        &(tcp_flow_hashtable.entries
                [skb_hash_function(saddr, daddr, sport, dport)]
            );                
    return entry;
}

static inline int is_log_for_skb(struct tcp_flow_log* log, __be32 saddr, 
        __be32 daddr, __be16 sport, __be16 dport) {
    return  (saddr == log->saddr && daddr == log->daddr 
                && dport == log->dport && sport == log->sport) || 
            (daddr == log->saddr && daddr == log->saddr 
                && dport == log->sport && sport == log->dport);
}

static inline struct tcp_flow_log* find_flow_log_for_skb( 
        struct hashtable_entry* entry,
        __be32 saddr, __be32 daddr, __be16 sport, __be16 dport) {
    struct tcp_flow_log* log_element;
    int count = 0;

    if (unlikely(!entry)) {
        return 0;
    }

    log_element = entry->head;

    while (log_element && count++ < bufsize) {
        if (is_log_for_skb(log_element, saddr, daddr, sport, dport)) {
            goto ret;
        }
        count++;
        log_element = log_element->next;
    }

ret:
    return log_element;
}

static inline void remove_from_hashentry(struct hashtable_entry* entry, 
        struct tcp_flow_log* log) {
    if (unlikely(!log || !entry)) {
        return;
    }

    if (log == entry->tail) {
        entry->tail = log->prev;
        if (entry->tail) {
            entry->tail->next = NULL;
        }
    }

    if (log == entry->head) {
        entry->head = log->next;
        if (entry->head) {
            entry->head->prev = NULL;
        }
    }

    if (log->next) {
        log->next->prev = log->prev;
    }

    if (log->prev) {
        log->prev->next = log->next;
    }

    log->prev = NULL; 
    log->next = NULL;
   
}

static inline struct tcp_flow_log* 
        remove_from_hashtable( struct hashtable_entry* entry,
            __be32 saddr, __be32 daddr, __be16 sport, __be16 dport) {
    struct tcp_flow_log* log = 
        find_flow_log_for_skb(entry, saddr, daddr, sport, dport);

    remove_from_hashentry(entry, log);
    return log;
}

static inline void reinitialize_tcp_flow_log(struct tcp_flow_log* log, 
        __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, 
        struct timespec tstamp) {
    int i = 0;

    if(unlikely(!log)){
        return;
    }

    //memset(log, 0, 
    //        sizeof(struct tcp_flow_log) 
    //            - 4 * sizeof(struct tcp_flow_log*) 
    //            - sizeof(spinlock_t) ); 
    //memset(log->snd_cwnd_histogram, 0, NUMBER_OF_BUCKETS * sizeof(u32)); 

    log->first_packet_tstamp = tstamp;
    log->last_packet_tstamp = tstamp;
    log->last_printed_tstamp.tv_sec = 0;
    log->last_printed_tstamp.tv_nsec = 0;

    log->saddr = saddr;
    log->daddr = daddr;
    log->sport = sport;
    log->dport = dport;

    log->recv_count = 0; 
    log->snd_count = 0;
    log->recv_size = 0;
    log->snd_size = 0;

    log->last_recv_seq = 0;
    log->last_snd_seq = 0;

    log->out_of_order_packets = 0;
    log->total_retransmissions = 0;

    log->snd_cwnd_clamp = 0;
    log->ssthresh = 0;
    log->srtt = 0;
    log->rttvar = 0;
    log->last_cwnd = 0;
    log->rto = 0; 

    log->used = 0;

    for (i = 0; i < NUMBER_OF_BUCKETS; i++) {
        log->snd_cwnd_histogram[i] = 0;
    }
}

static inline void insert_into_hashtable(struct hashtable_entry* entry, 
                                        struct tcp_flow_log* log) {
    if (unlikely(entry->tail)) {
        entry->tail->next = log;
    } else {
        entry->head = log;
    }
    
    log->prev = entry->tail;
    log->next = 0;
    entry->tail = log; 
}

/*static inline int is_finished(__be32 saddr, __be32 daddr, 
        __be16 sport, __be16 dport) {
    struct tcp_flow_log* finished = tcp_flow_spy.finished;
    while (finished) {
        if (is_log_for_skb(finished, saddr, daddr, sport, dport)) {
            return 1;
        }
        finished = finished->next;
    }
    return 0;
}*/

static inline struct hashtable_entry* initialize_hashtable(u32 size) {
    int i = 0;

    tcp_flow_hashtable.entries = 
        kcalloc(size, sizeof(struct hashtable_entry), GFP_KERNEL);

    if (tcp_flow_hashtable.entries) {
        for (i = 0; i < size; i++) {
            spin_lock_init(&tcp_flow_hashtable.entries[i].lock);
        }
    }

    tcp_flow_hashtable.count = 0;
    return tcp_flow_hashtable.entries;
}

static inline int tcp_flow_log_avail(void) {
   return tcp_flow_spy.available != 0;
}

#define FINISHED_STATES \
    (TCPF_CLOSE|TCPF_CLOSING|TCPF_TIME_WAIT|TCPF_LAST_ACK)

#define is_finished(s) ((1 << s->sk_state) & FINISHED_STATES)

static int jtcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb) {
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct tcphdr* th = tcp_hdr(skb); 
    const struct iphdr* iph = ip_hdr(skb); 
    unsigned long flags;

    /* Only update if port matches */
    if ((port == 0 || ntohs(th->dest) == port ||
                ntohs(th->source) == port)) {
        
        struct tcp_flow_log* p = NULL;
        struct timespec now = get_time();
        struct hashtable_entry* entry = 
            get_entry_for_skb(iph->saddr, iph->daddr, th->source, th->dest);

        spin_lock_irqsave(&entry->lock, flags);
        p = find_flow_log_for_skb(entry, 
                iph->saddr, iph->daddr, th->source, th->dest);
        spin_unlock_irqrestore(&entry->lock, flags);

        if (unlikely(!p)) {
            if (!th->syn) {
                goto ret;
            }
            
            spin_lock_irqsave(&tcp_flow_spy.lock, flags);
            if (tcp_flow_log_avail()) {
                p = tcp_flow_spy.available;
                tcp_flow_spy.available = tcp_flow_spy.available->next;
                add_in_used(p);
            }
            spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);

            if (likely(p)) {
                reinitialize_tcp_flow_log(p, 
                        iph->saddr, iph->daddr, th->source, th->dest, now);
                spin_lock_irqsave(&entry->lock, flags);
                insert_into_hashtable(entry, p);
                spin_unlock_irqrestore(&entry->lock, flags);
            } else {
                goto ret;
            }
        }

        // spin_lock_irqsave(&p->lock, flags);
        p->last_packet_tstamp = now;
        p->recv_count++;
        p->recv_size += skb->len; 
        if (likely(ntohl(th->seq) >= p->last_recv_seq)) {
            p->last_recv_seq = ntohl(th->seq);
        } else {
            p->out_of_order_packets++;
        }

        if (sk->sk_state == TCP_ESTABLISHED) {
            int cwnd_index = tp->snd_cwnd / bucket_length;
            cwnd_index = min(NUMBER_OF_BUCKETS - 1, cwnd_index);
            p->snd_cwnd_histogram[cwnd_index]++;
            p->last_cwnd = tp->snd_cwnd;
            p->snd_cwnd_clamp = tp->snd_cwnd_clamp; 
            p->ssthresh = tcp_current_ssthresh(sk);
            p->srtt = tp->srtt >> 3;
            p->rto = inet_csk(sk)->icsk_rto;
            p->rttvar = tp->rttvar; 
        }
        //spin_unlock_irqrestore(&p->lock, flags);
        
        if (is_finished(sk) || th->rst) {
            spin_lock_irqsave(&entry->lock, flags);
            remove_from_hashtable(entry, 
                    iph->saddr, iph->daddr, th->source, th->dest);
            spin_unlock_irqrestore(&entry->lock, flags);

            spin_lock_irqsave(&tcp_flow_spy.lock, flags);
            remove_from_used(p);
            p->next = tcp_flow_spy.finished;
            tcp_flow_spy.finished = p;
            spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);
        }
       
        if (is_finished(sk) || th->rst || live) {
            tcp_flow_spy.last_update = now;
            wake_up(&tcp_flow_spy.wait);
        }
    }

ret:
    jprobe_return();
    return 0;
}

static struct jprobe tcp_recv_jprobe = {
    .kp = {
        .symbol_name	= "tcp_v4_do_rcv",
    },
    .entry	= (kprobe_opcode_t*) jtcp_v4_do_rcv,
};

static int jtcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
                                gfp_t gfp_mask) {
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);
    unsigned long flags;

    __be16  sport = 
#if SPY_COMPAT >= 34
                inet->inet_sport,
#else
                inet->sport,
#endif
            dport = 
#if SPY_COMPAT >= 34
                inet->inet_dport;
#else
                inet->dport;
#endif

    __be32  saddr = 
#if SPY_COMPAT >= 34
                inet->inet_saddr,
#else
                inet->saddr,
#endif
            daddr =
#if SPY_COMPAT >= 34
                inet->inet_daddr;
#else
                inet->daddr;
#endif

    /* Only update if port matches */
    if ((port == 0 || ntohs(sport) == port ||
                ntohs(dport) == port)) {

        struct tcp_flow_log* p = NULL; 
        struct timespec now = get_time();
        struct hashtable_entry* entry = 
            get_entry_for_skb(saddr, daddr, sport, dport);

        spin_lock_irqsave(&entry->lock, flags);
        p = find_flow_log_for_skb(entry, saddr, daddr, sport, dport);
        spin_unlock_irqrestore(&entry->lock, flags);

        if (unlikely(!p)) {
            goto ret;
        }

        //spin_lock_irqsave(&p->lock, flags);
        p->last_packet_tstamp = now;
        p->snd_count++;
        p->snd_size += skb->len; 
        p->total_retransmissions = tp->total_retrans;

        if (likely(sk->sk_state == TCP_ESTABLISHED)) {
            int cwnd_index = tp->snd_cwnd / bucket_length;
            cwnd_index = min(NUMBER_OF_BUCKETS - 1, cwnd_index);
            p->snd_cwnd_histogram[cwnd_index]++;
            p->last_cwnd = tp->snd_cwnd;
            p->snd_cwnd_clamp = tp->snd_cwnd_clamp; 
            p->ssthresh = tcp_current_ssthresh(sk);
            p->srtt = tp->srtt >> 3;
            p->rto = inet_csk(sk)->icsk_rto;
            p->rttvar = tp->rttvar;
        }
        //spin_unlock_irqrestore(&p->lock, flags);

/*        if (is_finished(sk)) {
            
            spin_lock_irqsave(&entry->lock, flags);
            remove_from_hashtable(entry, 
                    saddr, daddr, sport, dport);
            spin_unlock_irqrestore(&entry->lock, flags);

            spin_lock_irqsave(&tcp_flow_spy.lock, flags);
            remove_from_used(p);
            p->next = tcp_flow_spy.finished;
            tcp_flow_spy.finished = p;
            spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);
        }

        if (is_finished(sk) || live) {
            tcp_flow_spy.last_update = now;
            wake_up(&tcp_flow_spy.wait);
        }
*/

    }

ret:
    jprobe_return();
    return 0;
}


static struct jprobe tcp_transmit_jprobe = {
    .kp = {
        .symbol_name = "tcp_transmit_skb",
    },
    .entry = (kprobe_opcode_t*) jtcp_transmit_skb,
};

static void jtcp_close(struct sock *sk, long timeout) {
    const struct inet_sock *inet = inet_sk(sk);
    unsigned long flags;

    __be16  sport = 
#if SPY_COMPAT >= 34
                inet->inet_sport,
#else
                inet->sport,
#endif
            dport = 
#if SPY_COMPAT >= 34
                inet->inet_dport;
#else
                inet->dport;
#endif

    __be32  saddr = 
#if SPY_COMPAT >= 34
                inet->inet_saddr,
#else
                inet->saddr,
#endif
            daddr =
#if SPY_COMPAT >= 34
                inet->inet_daddr;
#else   
                inet->daddr;
#endif
                
    /* Only update if port matches */
    if ((port == 0 || ntohs(sport) == port ||
                ntohs(dport) == port)) {

        struct tcp_flow_log* p = NULL; 
        struct hashtable_entry* entry = 
            get_entry_for_skb(saddr, daddr, sport, dport);
        struct timespec now = get_time();

        spin_lock_irqsave(&entry->lock, flags);
        p = remove_from_hashtable(entry, saddr, daddr, sport, dport);
        spin_unlock_irqrestore(&entry->lock, flags);

        if (likely(p)) {
            spin_lock_irqsave(&tcp_flow_spy.lock, flags);
            remove_from_used(p);
            p->next = tcp_flow_spy.finished;
            tcp_flow_spy.finished = p;
            spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);

            tcp_flow_spy.last_update = now;
            wake_up(&tcp_flow_spy.wait);
        }
    }
    jprobe_return();
}

static struct jprobe tcp_close_jprobe = {
    .kp = {
        .symbol_name = "tcp_close",
    },
    .entry = (kprobe_opcode_t*) jtcp_close,
};

static int tcpflowspy_open(struct inode * inode, struct file * file) {
    struct timespec now = get_time();
    tcp_flow_spy.start = now;
    tcp_flow_spy.last_read = now;
    tcp_flow_spy.last_update = now;
    return 0;
}

static void inline tcpprobe_set_normalized_timespec(
        struct timespec *ts, time_t sec, long nsec) {
    while (nsec >= NSEC_PER_SEC) {
        nsec -= NSEC_PER_SEC;
        ++sec;
    }
    while (nsec < 0) {
        nsec += NSEC_PER_SEC;
        --sec;
    }
    ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}


static inline struct timespec tcpprobe_timespec_sub (
         struct timespec lhs, struct timespec rhs) {
    struct timespec ts_delta;
    tcpprobe_set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
            lhs.tv_nsec - rhs.tv_nsec);
    return ts_delta;
}


static inline int tcpprobe_timespec_larger( 
        struct timespec lhs, struct timespec rhs) {
    int ret = lhs.tv_sec > rhs.tv_sec || 
        (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec > rhs.tv_nsec);
    return ret;
}

#define EXPIRE_SKB (2*60)

static inline int tcpflowspy_sprint(struct tcp_flow_log* p, int finished, 
        char *tbuf, int n, struct timespec now) {
    int size = 0;
    struct timespec duration; 
    //unsigned long flags;

    if (unlikely(!p)) {
        goto ret;
    }

    duration = 
        tcpprobe_timespec_sub(p->last_packet_tstamp, p->first_packet_tstamp);

    //spin_lock_irqsave(&p->lock, flags);
    size = snprintf(tbuf, n,
            "%lu%09lu (%d) %x:%u %x:%u %lu.%09lu %u %lu %u %lu %u %u %u %u %u %u %u %u,%u,%u,%u,%u,%u,%u,%u,%u,%u \n",
            (unsigned long) now.tv_sec,
            (unsigned long) now.tv_nsec,
            finished,
            (unsigned int) ntohl(p->saddr), ntohs(p->sport),
            (unsigned int) ntohl(p->daddr), ntohs(p->dport),
            (unsigned long) duration.tv_sec,
            (unsigned long) duration.tv_nsec,
            p->recv_count, 
            (unsigned long) p->recv_size, 
            p->snd_count,
            (unsigned long) p->snd_size,
            p->total_retransmissions, 
            p->out_of_order_packets, p->snd_cwnd_clamp,
            p->ssthresh, p->srtt, p->rto, p->last_cwnd,
            // This crime is done only for the sake of performance :D
            // This was dyanmic before :)) 
            p->snd_cwnd_histogram[0], p->snd_cwnd_histogram[1],
            p->snd_cwnd_histogram[2], p->snd_cwnd_histogram[3],
            p->snd_cwnd_histogram[4], p->snd_cwnd_histogram[5],
            p->snd_cwnd_histogram[6], p->snd_cwnd_histogram[7],
            p->snd_cwnd_histogram[8], p->snd_cwnd_histogram[9]);
    //spin_unlock_irqrestore(&p->lock, flags);

ret:
    return size;
}


static inline struct tcp_flow_log* 
    get_next_finished_log_for_print(void) {
    return tcp_flow_spy.finished;
}

static inline struct tcp_flow_log* 
                get_next_live_log_for_print(struct timespec expiration_time) {

    struct tcp_flow_log* ret_for_print = NULL;
    if (likely(tcp_flow_spy.used)) {
        if (last_printed_flow_log == NULL) {
            last_printed_flow_log = tcp_flow_spy.used;
        }

        if (tcpprobe_timespec_larger(
                    last_printed_flow_log->last_packet_tstamp, 
                    last_printed_flow_log->last_printed_tstamp) || 
            tcpprobe_timespec_larger(
                    expiration_time,
                    last_printed_flow_log->last_packet_tstamp)
           ) {
            ret_for_print = last_printed_flow_log;
        }
        
        last_printed_flow_log = last_printed_flow_log->used_thread_next;
    }   
    return ret_for_print;
}

#define PRINT_BUFF_SIZE 256
#define MIN_LOG_LENGTH 92

static ssize_t tcpflowspy_read(struct file *file, char __user *buf,
        size_t len, loff_t *ppos) {
    int error = 0;
    size_t cnt = 0;

    if (!buf)
        return -EINVAL;
    while (cnt < len) {
        char tbuf[PRINT_BUFF_SIZE];
        int width = 0;
        unsigned long flags;
        struct timespec now;
        struct tcp_flow_log* log_for_print = NULL;
        int finished = 0;
        struct timespec expiration_time; 
        struct hashtable_entry* entry = NULL;
        /* Wait for data in buffer */
        error = wait_event_interruptible(tcp_flow_spy.wait,
                    tcp_flow_spy.finished != 0 ||
                    tcpprobe_timespec_larger(
                        tcp_flow_spy.last_update, 
                        tcp_flow_spy.last_read)
                    );
        if (error)
            break;

        tcp_flow_spy.last_read = expiration_time = now = get_time();
        
        expiration_time.tv_sec -= EXPIRE_SKB;
        if (unlikely(expiration_time.tv_sec < 0)) {
            expiration_time.tv_sec = 0;
        }

        spin_lock_irqsave(&tcp_flow_spy.lock, flags);
        log_for_print = get_next_finished_log_for_print();
        if ((log_for_print == NULL) && live) {
            log_for_print = get_next_live_log_for_print(expiration_time);
        } else {
            finished = 1;
        }
        spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);

        if (log_for_print == NULL) {
            continue;
        }

        entry = get_entry_for_skb(  
                    log_for_print->saddr, 
                    log_for_print->daddr,
                    log_for_print->sport,
                    log_for_print->dport);

        if ( !finished && tcpprobe_timespec_larger(
                    expiration_time,
                    log_for_print->last_packet_tstamp)
           ) {
            finished = 1;
            spin_lock_irqsave(&entry->lock, flags);
            remove_from_hashtable
                (entry, log_for_print->saddr, log_for_print->daddr,
                 log_for_print->sport, log_for_print->dport);
            spin_unlock_irqrestore(&entry->lock, flags);

            spin_lock_irqsave(&tcp_flow_spy.lock, flags);
            remove_from_used(log_for_print);
            log_for_print->next = tcp_flow_spy.finished;
            tcp_flow_spy.finished = log_for_print;
            spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);
        }

//        spin_lock_irqsave(&entry->lock, flags);
        width = tcpflowspy_sprint(log_for_print, finished, 
                tbuf, sizeof(tbuf), now);
//        spin_unlock_irqrestore(&entry->lock, flags);

        if (width == 0) {
            continue;
        }

        if (cnt + width < len && finished){
            spin_lock_irqsave(&tcp_flow_spy.lock, flags);
            tcp_flow_spy.finished = log_for_print->next;
            log_for_print->next = tcp_flow_spy.available;
            tcp_flow_spy.available = log_for_print;
            spin_unlock_irqrestore(&tcp_flow_spy.lock, flags);
            log_for_print->used = 0;
        } 

        if (cnt + width >= len) {
            break;
        }

        log_for_print->last_printed_tstamp = now;

        if (copy_to_user(buf + cnt, tbuf, width))
            return -EFAULT;
        cnt += width;

        if (cnt + MIN_LOG_LENGTH >= len) {
            break;
        }
    }
    return cnt == 0 ? error : cnt;
}

static const struct file_operations tcpflowspy_fops = {
    .owner	 = THIS_MODULE,
    .open	 = tcpflowspy_open,
    .read    = tcpflowspy_read,
};

static __init int tcpflowspy_init(void) {
    int ret = -ENOMEM;
    int i = 0;
    init_waitqueue_head(&tcp_flow_spy.wait);
    spin_lock_init(&tcp_flow_spy.lock);

    if (bufsize == 0) {
        return -EINVAL;
    }

    bufsize = roundup_pow_of_two(bufsize);

    tcp_flow_spy.storage = 
        kcalloc(SECTION_COUNT, sizeof(struct tcp_flow_log*), GFP_KERNEL);
    if (!tcp_flow_spy.storage) {
        goto err0;
    }


    for (i = 0; i < SECTION_COUNT; i++) {

        tcp_flow_spy.storage[i] = 
            kcalloc(MAX_CONTINOUS, sizeof(struct tcp_flow_log), GFP_KERNEL);

        if (!tcp_flow_spy.storage[i]) {
            int j = 0;
            for (j = 0; j < i; j++) {
                kfree(tcp_flow_spy.storage[j]);
            }
            goto err0;
        }

    }

    tcp_flow_spy.available = tcp_flow_spy.storage[0]; 
    tcp_flow_spy.finished = NULL;
    tcp_flow_spy.used = NULL;

    if (!initialize_hashtable(HASHTABLE_SIZE)) {
        goto err2;
    }

    if (!proc_net_fops_create(
#if SPY_COMPAT >= 32
                &init_net,
#endif
                procname, S_IRUSR | S_IRGRP | S_IROTH, 
                &tcpflowspy_fops)) {
        goto err2;
    }

    ret = register_jprobe(&tcp_recv_jprobe);
    if (ret) {
        goto err1;
    }

    ret = register_jprobe(&tcp_transmit_jprobe);
    if (ret) {
        goto err1;
    }

    ret = register_jprobe(&tcp_close_jprobe);
    if (ret) {
        goto err1;
    }

    for (i = 0; i < SECTION_COUNT; i++) {
        int j  = 0;
        for (j = 0; j < MAX_CONTINOUS; j++) {

/*            tcp_flow_spy.storage[i][j].snd_cwnd_histogram = 
                kcalloc(NUMBER_OF_BUCKETS, sizeof(u32), GFP_KERNEL);

            if (!tcp_flow_spy.storage[i][j].snd_cwnd_histogram)
                goto err2;*/
            if (i != SECTION_COUNT - 1) {
                tcp_flow_spy.storage[i][j].next = 
                    j < MAX_CONTINOUS - 1 ? 
                    &(tcp_flow_spy.storage[i][j+1]) : 
                    &(tcp_flow_spy.storage[i+1][0]);
            } else {
                tcp_flow_spy.storage[i][j].next = 
                    j < MAX_CONTINOUS - 1 ? 
                    &(tcp_flow_spy.storage[i][j+1]) : 
                    NULL;                
            }
            //spin_lock_init(&tcp_flow_spy.storage[i][j].lock);
        }
    }

    debug_check_no_locks_freed(&tcp_flow_spy, sizeof(tcp_flow_spy));
    debug_check_no_locks_freed(&tcp_flow_hashtable, sizeof(tcp_flow_hashtable));

    pr_info("TCP flow spy registered (port=%d) bufsize=%u\n", port, bufsize);
    return 0;
err1:
    proc_net_remove(
#if SPY_COMPAT >= 32
            &init_net,
#endif
            procname);
err2:
    for (i = 0; i < SECTION_COUNT; i++) {
        kfree(tcp_flow_spy.storage[i]);
    }
err0:
    return ret;
}
module_init(tcpflowspy_init);

static __exit void tcpflowspy_exit(void) {
    int i = 0;

    proc_net_remove(
#if SPY_COMPAT >= 32
            &init_net,
#endif
            procname);
    unregister_jprobe(&tcp_recv_jprobe);
    unregister_jprobe(&tcp_transmit_jprobe);
    unregister_jprobe(&tcp_close_jprobe);

    for (i = 0; i < SECTION_COUNT; i++) {
        kfree(tcp_flow_spy.storage[i]);
    }

    pr_info("TCP flow spy unregistered \n");
 
}
module_exit(tcpflowspy_exit);
