/* milter-dnsbl - a simple milter that consults DNSBLs and blocks incoming
 * email.
 *
 * You can read about the Milter API at http://www.milter.org/milter_api/
 * You are also advised to read ``Sendmail milters'' http://spambook.bcx.org
 */

#include "LICENSE.h"
#include "milter-dnsbl.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sysexits.h>
#include <pwd.h>
#include <lwres/lwres.h>
#include <lwres/netdb.h>
#include <libmilter/mfapi.h>

struct list {
	char *data;
	struct list *next;
};
struct list *dnsbls, *dnswls, *wl_domains;

extern char *optarg;
extern int optind, opterr, optopt;

int right_strcmp(char *, char *);
static sfsistat
dnsbl_connect(SMFICTX*, char*, _SOCK_ADDR*);

static
struct smfiDesc smfilter =
{
	"DNSBL",		/* filter name */
	SMFI_VERSION,		/* version code -- do not change */
	0,			/* flags */
	dnsbl_connect,		/* handle connection */
	NULL,			/* handle SMTP HELO/EHLO */
	NULL,			/* handle envelope sender */
	NULL,			/* handle envelope recipient */
	NULL,			/* handle header */
	NULL,			/* handle end-of-headers */
	NULL,			/* handle body chunk */
	NULL,			/* handle end-of-message */
	NULL,			/* handle message aborted */
	NULL,			/* handle connection cleanup */
};

static sfsistat
dnsbl_connect(SMFICTX* ctx, char* connhost, _SOCK_ADDR* connaddr)
{
	struct list *t;
	struct sockaddr_in *sin;
	u_char *ipv4str;

	if (connaddr == NULL) {
		return(SMFIS_ACCEPT);
	}

	sin = (struct sockaddr_in *) connaddr;
	ipv4str = (u_char *) &sin->sin_addr.s_addr;

	/* First check if connhost is whitelisted */

	t = wl_domains;
	while (t != NULL) {
		if (right_strcmp(connhost, t->data) == 0) {
			syslog(LOG_INFO, "accepting host %s (-W %s)", connhost, t->data);
			return(SMFIS_ACCEPT);
		}
		t = t->next;
	}

	t = dnswls;
	while (t != NULL) {
		if (check_dnsbl(ipv4str[0], ipv4str[1], ipv4str[2], ipv4str[3], t->data) == 0) {
			syslog(LOG_INFO, "accepting host %s (-w %s)", connhost, t->data);
			return(SMFIS_ACCEPT);
		}
		t = t->next;
	}

	/* Now check if connhost is blacklisted */

	t = dnsbls;
	while (t != NULL) {
		if (check_dnsbl(ipv4str[0], ipv4str[1], ipv4str[2], ipv4str[3], t->data) == 0) {
			syslog(LOG_INFO, "blocking host %s (%d.%d.%d.%d.%s)", connhost, ipv4str[3], ipv4str[2], ipv4str[1], ipv4str[0], t->data);
			/* When in production mode, use the next line.  While
			 * debugging comment the next line and return
			 * SMFIS_ACCEPT instead.
			 */
			return(SMFIS_REJECT); /* */
			/* return(SMFIS_ACCEPT); /* */
		}
		t = t->next;
	}

	syslog(LOG_INFO, "accepting host %s", connhost);
	return(SMFIS_ACCEPT);
}

/* Think of this as a rightmost strcmp() */
int
right_strcmp(char *x, char *y)
{
int xl, yl, l;
char *s;

	xl = strlen(x);
	yl = strlen(y);
	l = xl - yl;

	if (l < 0) {
		return l;
	} else {
		s = x + l;
		return (strncasecmp(s, y, yl));
	}
}

struct list *
add_list(struct list *d, char *data)
{
	struct list *t;
	int len;

	t = (struct list *) malloc(sizeof(struct list));
	len = strlen(data) + 1;
	t->data = (char *) malloc(len);
	memset(t->data, '\0', len);
	memcpy(t->data, data, len);
	t->next = d;

	return(t);
}

void
print_list(struct list *d)
{
	struct list *t;

	t = d;
	while (t != NULL) {
		printf(" - %s\n", t->data);
		t = t->next;
	}

	return;
}

/* Return values:
 * 	0 : host found listed in dnsbl
 * 	1 : host not found listed in dnsbl
 */
int
check_dnsbl(int a, int b, int c, int d, char *dnsbl)
{
	char *name;
	int l, herr;
	struct hostent *he;

	/* An IPv4 address is max 15 chars long (xxx.xxx.xxx.xxx) */
	l = 18 + strlen(dnsbl);
	name = (char *)malloc(l);
	if (name == NULL) {
		syslog(LOG_INFO, "check_dnsbl(): malloc() error: aborting");
		return(0);
	}
	memset(name, '\0', l);
	if (*dnsbl == '.') {
		sprintf(name, "%d.%d.%d.%d%s", d, c, b, a, dnsbl);
	} else {
		sprintf(name, "%d.%d.%d.%d.%s", d, c, b, a, dnsbl);
	}

	he = lwres_getipnodebyname(name, AF_INET, 0, &herr);
	free(name);
	if (he == NULL) {
		return(1);
	}

	lwres_freehostent(he);
	return(0);
}

void
usage(char *s)
{
	fprintf(stderr, "%s version: %s\n", _progname, _version);
	fprintf(stderr, "usage: %s [-h] [-d] <-u user> <-s socket> [-W domain] [-w list] <-l list>\n\n", s);
	fprintf(stderr, "\t-h : this help message\n");
	fprintf(stderr, "\t-d : daemonize\n");
	fprintf(stderr, "\t-u : username for the milter to run as\n");
	fprintf(stderr, "\t-s : socket for milter/sendmail communication\n");
	fprintf(stderr, "\t-W : whitelist hosts under this domain\n");
	fprintf(stderr, "\t-w : whitelist IP addresses in this list\n");
	fprintf(stderr, "\t-l : blacklist IP addresses in this DNSBL\n");
	fprintf(stderr, "\nMultiple -l, -w and -W options may be issued.\n");
	fprintf(stderr, "\nCopyright (c) 2007 Yiorgos Adamopoulos <adamo@dblab.ece.ntua.gr>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int u_flag;
	int s_flag;
	int d_flag;
	int W_flag;
	int w_flag;
	int l_flag;
	int ret;
	char *user;
	char *socket;
	char *ep;
	int uid;
	struct passwd *pwd;
	pid_t pid;
	int fd;

	u_flag = s_flag = d_flag = l_flag = w_flag = W_flag = 0;
	dnsbls = dnswls = wl_domains = NULL;

	while ((ret = getopt(argc, argv, "hdu:s:l:w:W:")) != -1) {
		switch(ret) {
		case 'd':
			d_flag++;
			break;
		case 'u':
			u_flag++;
			user = optarg;
			break;
		case 's':
			s_flag++;
			socket = optarg;
			break;
		case 'l':
			dnsbls = add_list(dnsbls, optarg);
			l_flag++;
			break;
		case 'w':
			dnswls = add_list(dnswls, optarg);
			w_flag++;
			break;
		case 'W':
			wl_domains = add_list(wl_domains, optarg);
			W_flag++;
			break;
		case 'h':
		default:
			usage(_progname);
		}
	}
	argc -= optind;
	argv += optind;

	if (!u_flag) {
		fprintf(stderr, "You must specify a user!\n");
		usage(_progname);
	}

	if (!s_flag) {
		fprintf(stderr, "You must specify a socket!\n");
		usage(_progname);
	}

	if (w_flag) {
		printf("Using whitelists:\n");
		print_list(dnswls);
	}

	if (W_flag) {
		printf("Whitelisting domains:\n");
		print_list(wl_domains);
	}

	if (!l_flag) {
		fprintf(stderr, "You must specify at least one DNSBL!\n");
		usage(_progname);
	} else {
		printf("Using blacklists:\n");
		print_list(dnsbls);
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s: cannot switch to user %s if not started as root!\n", _progname, user);
		exit(EX_USAGE);
	}

	/* OK running as root, now switch to user */
	uid = strtol(user, &ep, 0);
	if (*ep == '\0') {
		pwd = getpwuid(uid);
	} else {
		pwd = getpwnam(user);
	}

	if (pwd == NULL) {
		fprintf(stderr, "%s: unknown user: %s\n", _progname, user);
		exit(EX_NOUSER);
	}

	if (setgroups(0, NULL) < 0) {
		perror("setgroups()");
		exit(1);
	}

	if (setgid(pwd->pw_gid) < 0) {
		perror("setgid()");
		exit(1);
	}

	if (initgroups(user, pwd->pw_gid) < 0) {
		perror("initgroups()"); /* not a critical failure */
	}

	if (setuid(pwd->pw_uid) < 0) {
		perror("setuid()");
		exit(1);
	}

	openlog(_progname, 0, LOG_MAIL);

	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "smfi_register() failed.\n");
		exit(EX_UNAVAILABLE);
	}

	if (smfi_setconn(socket) == MI_FAILURE) {
		fprintf(stderr, "smfi_setconn() %s\n", strerror(errno));
		exit(EX_SOFTWARE);
	}

	if (smfi_opensocket(1) == MI_FAILURE) {
		fprintf(stderr, "smfi_opensocket() %s\n", strerror(errno));
		exit(EX_SOFTWARE);
	}

	(void) smfi_settimeout(7200);

	if (!d_flag) {
		fprintf(stderr, "Warning: not starting as daemon");
	} else {
		if (daemon(0, 0) < 0) {
			perror("daemon()");
			exit(1);
		}
	}

	syslog(LOG_INFO, "%s started successfuly!", _progname);
	return(smfi_main()); /* start doing business */
}
