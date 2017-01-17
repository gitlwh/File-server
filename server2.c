#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "support.h"

/*
 * help() - Print a help message
 */
void help(char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Initiate a network file server\n");
    printf("  -l    number of entries in cache\n");
    printf("  -p    port on which to listen for connections\n");
}

/*
 * die() - print an error and exit the program
 */
void die(const char *msg1, char *msg2) {
    fprintf(stderr, "%s, %s\n", msg1, msg2);
    exit(0);
}

/*
 * open_server_socket() - Open a listening socket and return its file
 *                        descriptor, or terminate the program
 */
int open_server_socket(int port) {
    int                listenfd;    /* the server's listening file descriptor */
    struct sockaddr_in addrs;       /* describes which clients we'll accept */
    int                optval = 1;  /* for configuring the socket */

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        die("Error creating socket: ", strerror(errno));

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int)) < 0)
        die("Error configuring socket: ", strerror(errno));

    /* Listenfd will be an endpoint for all requests to the port from any IP
       address */
    bzero((char *) &addrs, sizeof(addrs));
    addrs.sin_family = AF_INET;
    addrs.sin_addr.s_addr = htonl(INADDR_ANY);
    addrs.sin_port = htons((unsigned short)port);
    if (bind(listenfd, (struct sockaddr *)&addrs, sizeof(addrs)) < 0)
        die("Error in bind(): ", strerror(errno));

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 1024) < 0)  // backlog of 1024
        die("Error in listen(): ", strerror(errno));

    return listenfd;
}

/*
 * handle_requests() - given a listening file descriptor, continually wait
 *                     for a request to come in, and when it arrives, pass it
 *                     to service_function.  Note that this is not a
 *                     multi-threaded server.
 */
void handle_requests(int listenfd, void (*service_function)(int, int), int param) {
    while (1) {
        /* block until we get a connection */
        struct sockaddr_in clientaddr;
        int clientlen = sizeof(clientaddr);
        int connfd;
        if ((connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen)) < 0)
            die("Error in accept(): ", strerror(errno));

        /* print some info about the connection */
        struct hostent *hp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
                           sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        if (hp == NULL) {
            fprintf(stderr, "DNS error in gethostbyaddr() %d\n", h_errno);
            exit(0);
        }
        char *haddrp = inet_ntoa(clientaddr.sin_addr);
        printf("server connected to %s (%s)\n", hp->h_name, haddrp);

        /* serve requests */
        service_function(connfd, param);

        /* clean up, await new connection */
        if (close(connfd) < 0)
            die("Error in close(): ", strerror(errno));
    }
}

/*
 * file_server() - Read a request from a socket, satisfy the request, and
 *                 then close the connection.
 */
void file_server(int connfd, int lru_size) {
    /* TODO: set up a few static variables here to manage the LRU cache of
       files */

    /* TODO: replace following sample code with code that satisfies the
       requirements of the assignment */

    /* sample code: continually read lines from the client, and send them
       back to the client immediately */
    while (1) {
        const int MAXLINE = 8192;
        char      buf[MAXLINE];   /* a place to store text from the client */
        bzero(buf, MAXLINE);

        /* read from socket, recognizing that we may get short counts */
        char *bufp = buf;              /* current pointer into buffer */
        ssize_t nremain = MAXLINE;     /* max characters we can still read */
        size_t nsofar;                 /* characters read so far */
        FILE *stream;
        while (1) {
            /* read some data; swallow EINTRs */
            if ((nsofar = read(connfd, bufp, nremain)) < 0) {
                if (errno != EINTR)
                    die("read error: ", strerror(errno));
                continue;
            }
            /* end service to this client on EOF */
            if (nsofar == 0) {
                fprintf(stderr, "received EOF\n");
                return;
            }
            /* update pointer for next bit of reading */
            bufp += nsofar;
            nremain -= nsofar;
            if (*(bufp-1) == '\n') {
                *bufp = 0;
                break;
            }
        }

        if((stream = fopen("data","w+t"))==NULL)
		{
			printf("The file 'data' was not opened! \n");
		}
		else
			bzero(buffer,BUFFER_SIZE);
		bool readfirst=true;
		bool readsecond=true;
		bool put=false;
		bool get=false;
		char name[1024];
        while( length = recv(connfd,buffer,8192,0)){
			if(length < 0){
				printf("Recieve Data From Server %s Failed!\n", argv[1]);
				break;
			}
			if(readfirst){
				readfirst=false;
				printf("%s\n", buffer);
				if (strcmp(buffer,"PUT\n")==0){
					put=true;
				}else{
					get=true;
					char *res="OK\n";
					write(connfd, res, 1024);
				}
				bzero(buffer,8192);
				continue; 
			}
			if(put){
				
				if(readsecond){
					readsecond=false;
					if((stream = fopen(buffer,"w+t"))==NULL)
					{
						printf("The file 'data' was not opened! \n");
					}
					bzero(buffer,8192);
					continue;
				}
				int write_length = fwrite(buffer,sizeof(char),length,stream);
				printf("%s\n", buffer);
				
				if (write_length<length){
					printf("File is Write Failed\n");
					break;
				}
				bzero(buffer,BUFFER_SIZE); 
			}
			if(get){
				if(readsecond){
					readsecond=false;
					if((stream = fopen(buffer,"r"))==NULL)
					{
						printf("The file was not opened! \n");
					}
					strcpy(name,buffer);
					bzero(buffer,8192);
				}

				write(fd, name, 8192);
			    write(fd, "\n", 8192);
				struct stat st ;
			    stat( name, &st );
			    char str[100];
			    sprintf(str, "%d", st.st_size);
			    write(fd, str, 8192);
			    write(fd, "\n", 8192);
			    FILE *stream;
			    if((stream = fopen("data1","r"))==NULL)
			    {
			        printf("The file 'data1' was not opened! \n");
			        exit(1);
			    }
			    else
			        printf("The file 'filename' was opened! \n");

			    int lengsize = 0;
			    while((lengsize = fread(buffer,1,1024,stream)) > 0){
			        printf("lengsize = %d\n",lengsize);
			        if(send(connfd,buffer,lengsize,0)<0){
			            printf("Send File is Failed\n");
			            break;
			        }
			        bzero(buffer, 1024);
			    }
			}
		}
		if(put){
			char *res="OK\n";
			write(connfd, res, 1024);
		}
		fclose(stream);




        /* dump content back to client (again, must handle short counts) 
        printf("server received %d bytes\n", MAXLINE-nremain);
        nremain = bufp - buf;
        bufp = buf;
        while (nremain > 0) {
            /* write some data; swallow EINTRs 
            if ((nsofar = write(connfd, bufp, nremain)) <= 0) {
                if (errno != EINTR)
                    die("Write error: ", strerror(errno));
                nsofar = 0;
            }
            nremain -= nsofar;
            bufp += nsofar;
        }*/
    }
}

/*
 * main() - parse command line, create a socket, handle requests
 */
int main(int argc, char **argv) {
    /* for getopt */
    long opt;
    /* NB: the "part 3" behavior only should happen when lru_size > 0 */
    int  lru_size = 0;
    int  port     = 9000;

    check_team(argv[0]);

    /* parse the command-line options.  They are 'p' for port number,  */
    /* and 'l' for lru cache size.  'h' is also supported. */
    while ((opt = getopt(argc, argv, "hl:p:")) != -1) {
        switch(opt) {
          case 'h': help(argv[0]); break;
          case 'l': lru_size = atoi(argv[0]); break;
          case 'p': port = atoi(optarg); break;
        }
    }

    /* open a socket, and start handling requests */
    int fd = open_server_socket(port);
    handle_requests(fd, file_server, lru_size);

    exit(0);
}
