struct buf {
	/* don't manipulate data member outside of buffer.c - it
	is a pointer into the malloc holding buffer itself */
	unsigned char * data;
	unsigned int len; /* the used size */
	unsigned int pos;
	unsigned int size; /* the memory size */

};

typedef struct buf buffer;

struct Link {

	void* item;
	struct Link* link;

};

struct Queue {

	struct Link* head;
	struct Link* tail;
	unsigned int count;

};

typedef struct PacketType {
	unsigned char type; /* SSH_MSG_FOO */
	void (*handler)(void);
} packettype;

struct AuthState {
	char *username; /* This is the username the client presents to check. It
					   is updated each run through, used for auth checking */
	unsigned char authtypes; /* Flags indicating which auth types are still 
								valid */
	unsigned int failcount; /* Number of (failed) authentication attempts.*/
	unsigned authdone : 1; /* 0 if we haven't authed, 1 if we have. Applies for
							  client and server (though has differing 
							  meanings). */
	unsigned perm_warn : 1; /* Server only, set if bad permissions on 
							   ~/.ssh/authorized_keys have already been
							   logged. */

	/* These are only used for the server */
	uid_t pw_uid;
	gid_t pw_gid;
	char *pw_dir;
	char *pw_shell;
	char *pw_name;
	char *pw_passwd;
	struct PubKeyOptions* pubkey_options;

};

struct KEXState {

	unsigned sentkexinit : 1; /*set when we've sent/recv kexinit packet */
	unsigned recvkexinit : 1;
	unsigned them_firstfollows : 1; /* true when first_kex_packet_follows is set */
	unsigned sentnewkeys : 1; /* set once we've send MSG_NEWKEYS (will be cleared once we have also received */
	unsigned recvnewkeys : 1; /* set once we've received MSG_NEWKEYS (cleared once we have also sent */

	unsigned donefirstkex : 1; /* Set to 1 after the first kex has completed,
								  ie the transport layer has been set up */

	unsigned our_first_follows_matches : 1;

	time_t lastkextime; /* time of the last kex */
	unsigned int datatrans; /* data transmitted since last kex */
	unsigned int datarecv; /* data received since last kex */

};

struct packetlist;
struct packetlist {
	struct packetlist *next;
	buffer * payload;
};
struct key_context {
};

enum dropbear_prio {
  DROPBEAR_PRIO_DEFAULT = 10,
  DROPBEAR_PRIO_LOWDELAY = 11,
  DROPBEAR_PRIO_BULK = 12,
};

struct Algo_Type {

	const char *name; /* identifying name */
	char val; /* a value for this cipher, or -1 for invalid */
	const void *data; /* algorithm specific data */
	char usable; /* whether we can use this algorithm */
	const void *mode; /* the mode, currently only used for ciphers,
						 points to a 'struct dropbear_cipher_mode' */
};
typedef struct Algo_Type algo_type;

typedef uint32_t mp_digit;

typedef struct  {
    int used, alloc, sign;
    mp_digit *dp;
} mp_int;

struct _m_list;

struct _m_list_elem {
	void *item;
	struct _m_list_elem *next;
	struct _m_list_elem *prev;
	struct _m_list *list;
};
	
typedef struct _m_list_elem m_list_elem;

struct _m_list {
	m_list_elem *first;
	m_list_elem *last;
};

typedef struct _m_list m_list;

struct sshsession {

	/* Is it a client or server? */
	unsigned char isserver;

	time_t connect_time; /* time the connection was established
							(cleared after auth once we're not
							respecting AUTH_TIMEOUT any more).
							A monotonic time, not realworld */

	int sock_in;
	int sock_out;

	/* remotehost will be initially NULL as we delay
	 * reading the remote version string. it will be set
	 * by the time any recv_() packet methods are called */
	char *remoteident;

	int maxfd; /* the maximum file descriptor to check with select() */


	/* Packet buffers/values etc */
	buffer *writepayload; /* Unencrypted payload to write - this is used
							 throughout the code, as handlers fill out this
							 buffer with the packet to send. */
	struct Queue writequeue; /* A queue of encrypted packets to send */
	unsigned int writequeue_len; /* Number of bytes pending to send in writequeue */
	buffer *readbuf; /* From the wire, decrypted in-place */
	buffer *payload; /* Post-decompression, the actual SSH packet. 
						May have extra data at the beginning, will be
						passed to packet processing functions positioned past
						that, see payload_beginning */
	unsigned int payload_beginning;
	unsigned int transseq, recvseq; /* Sequence IDs */

	/* Packet-handling flags */
	const packettype * packettypes; /* Packet handler mappings for this
										session, see process-packet.c */

	unsigned dataallowed : 1; /* whether we can send data packets or we are in
								 the middle of a KEX or something */

	unsigned char requirenext; /* byte indicating what packets we require next, 
									 or 0x00 for any.  */

	unsigned char ignorenext; /* whether to ignore the next packet,
								 used for kex_follows stuff */

	unsigned char lastpacket; /* What the last received packet type was */
	
	int signal_pipe[2]; /* stores endpoints of a self-pipe used for
						   race-free signal handling */

	m_list conn_pending;
						
	/* time of the last packet send/receive, for keepalive. Not real-world clock */
	time_t last_packet_time_keepalive_sent;
	time_t last_packet_time_keepalive_recv;
	time_t last_packet_time_any_sent;

	time_t last_packet_time_idle; /* time of the last packet transmission or receive, for
								idle timeout purposes so ignores SSH_MSG_IGNORE
								or responses to keepalives. Not real-world clock */


	/* KEX/encryption related */
	struct KEXState kexstate;
	struct key_context *keys;
	struct key_context *newkeys;
	buffer *session_id; /* this is the hash from the first kex */
	/* The below are used temporarily during kex, are freed after use */
	mp_int * dh_K; /* SSH_MSG_KEXDH_REPLY and sending SSH_MSH_NEWKEYS */
	buffer *hash; /* the session hash */
	buffer* kexhashbuf; /* session hash buffer calculated from various packets*/
	buffer* transkexinit; /* the kexinit packet we send should be kept so we
							 can add it to the hash when generating keys */

	/* Enables/disables compression */
	algo_type *compress_algos;
							
	/* a list of queued replies that should be sent after a KEX has
	   concluded (ie, while dataallowed was unset)*/
	struct packetlist *reply_queue_head, *reply_queue_tail;

	void(*remoteclosed)(void); /* A callback to handle closure of the
									  remote connection */

	void(*extra_session_cleanup)(void); /* client or server specific cleanup */
	void(*send_kex_first_guess)(void);

	struct AuthState authstate; /* Common amongst client and server, since most
								   struct elements are common */

	/* Channel related */
	struct Channel ** channels; /* these pointers may be null */
	unsigned int chansize; /* the number of Channel*s allocated for channels */
	unsigned int chancount; /* the number of Channel*s in use */
	const struct ChanType **chantypes; /* The valid channel types */
	int channel_signal_pending; /* Flag set by sigchld handler */

	/* TCP priority level for the main "port 22" tcp socket */
	enum dropbear_prio socket_prio;

	/* TCP forwarding - where manage listeners */
	struct Listener ** listeners;
	unsigned int listensize;

	/* Whether to allow binding to privileged ports (<1024). This doesn't
	 * really belong here, but nowhere else fits nicely */
	int allowprivport;

};

extern struct sshsession ses;

struct ChildPid {
	pid_t pid;
};
struct exitinfo {

	int exitpid; /* -1 if not exited */
	int exitstatus;
	int exitsignal;
	int exitcore;
};
struct serversession {

	/* Server specific options */
	int childpipe; /* kept open until we successfully authenticate */
	/* userauth */

	struct ChildPid * childpids; /* array of mappings childpid<->channel */
	unsigned int childpidsize;

	/* Used to avoid a race in the exit returncode handling - see
	 * svr-chansession.c for details */
	struct exitinfo lastexit;

	/* The numeric address they connected from, used for logging */
	char * addrstring;

	/* The resolved remote address, used for lastlog etc */
	char *remotehost;

	pid_t server_pid;


};

extern struct serversession svr_ses;