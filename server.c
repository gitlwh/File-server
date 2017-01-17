#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
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
#include <stdbool.h>
#include <signal.h>

int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
    BIO_free( keybio );
 
    return rsa;
}

 


int readData(int s, void *buf, int buflen)
{
    int total = 0;
    char *pbuf = (char*) buf;
    while (buflen > 0) {
        int numread = recv(s, pbuf, buflen, 0);
        if (numread <= 0) return numread;
        pbuf += numread;
        buflen -= numread;
        total += numread;
    }
    return total;
}

int sendData(int s, void *buf, int buflen)
{
    int total = 0;
    char *pbuf = (char*) buf;
    while (buflen > 0) {
        int numsent = send(s, pbuf, buflen, 0);
        if (numsent <= 0) return numsent;
        pbuf += numsent;
        buflen -= numsent;
        total += numsent;
    }
    return total;
}

char *str2md5(const char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char*)malloc(33);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return out;
}

struct node{
    char key[100];
    char data[8192];
    int length;
    struct node * next;
};


int cachenum;
struct node *firstone=NULL;
void initnode(){
    printf("INITIAL CACHE!\n");
    firstone=(struct node *)malloc(sizeof(struct node));
    firstone->next=NULL;
}
void shownode();
void addone(char* key, char*data, int len){
    printf("CACHE ADDONE\n");
    if(firstone==NULL){
        initnode();
    }
    struct node* this=firstone->next;
    struct node* last=firstone;
    while(this){
        if(strcmp(this->key,key)==0){
            break;
        }
        this=this->next;
        last=last->next;
    }
    if (this){
        printf("ALREADY IN CACHE!\n");
        
        //refresh
        bzero(this->key,100);
        bzero(this->data,8192);
        strcpy(this->key,key);
        int k = 0;
        for(;k < len;k++) 
            this->data[k] = data[k];
        printf("added:%s\n", this->data);
        firstone->length=len;

        //move to front
        last->next=this->next;
        this->next=firstone->next;
        firstone->next=this;
        printf("UPDATED!\n");
    }
    else{
        printf("ADD NEW CACHE NODE!\n");
        struct node* newnode=(struct node *)malloc(sizeof(struct node));
        newnode->next=firstone->next;
        firstone->next=newnode;
        bzero(newnode->key,100);
        bzero(newnode->data,8192);
        strcpy(newnode->key,key);
        int k = 0;
        for(;k < len;k++) 
            newnode->data[k] = data[k];
        //printf("added:%s\n", newnode->data);
        newnode->length=len;
        //printf("add one\n");
        //printf("length is %d\n", newnode->length);
        //printf("data is %d\n", newnode->data);
    }
    this=firstone->next;
    last=firstone;
    //printf("%d\n", cachenum);
    for (int i = 0; i < cachenum; ++i)
    {
        this=this->next;
        last=last->next;
        if(this==NULL)break;
    }
    if(this){
        //printf("delete one!\n");
        last->next=NULL;
        free(this);
    }
    printf("DONE!\n");
}

struct node* findone(char* key){
    struct node* this=firstone->next;
    while(this){
        if(strcmp(this->key,key)==0)return this;
        this=this->next;
    }
    return this;
}
void shownode(){
    struct node* this=firstone->next;
    //printf("show\n");
    if(firstone->next==NULL){
        //printf("no one in it!\n");
    }
    int i=1;
    while(this){
        printf("%d\n", i++);
        printf("key: %s\n", this->key);
        printf("data: %s\n", this->data);
        printf("length:%d\n", this->length);
        this=this->next;
    }
}
 void clearnode(int sig){
    struct node* this=firstone;
    //printf("clear\n");
    if(this==NULL){
        //printf("nothing in it!\n");
        exit(0); 
    }
    struct node* next=this->next;
    while(this->next){
        free(this);
        this=next;
        next=this->next;
    }
    free(this);
    //firstone=NULL;
    exit(0);
 }

char errormessage[1024];
int errornum;
void initialerror(){
    bzero(errormessage,1024);
    errornum=1;
}
void adderror(char * error){
    char errornumchar[100];
    char str[100];
    sprintf(str, "ERROR (%d):", errornum);
    errornum+=1;
    strcat(errormessage,str);
    strcat(errormessage,error);
}
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

    /* Listenfd will be an endstruct node for all requests to the port from any IP
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
    initnode();
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

int getPathInfo(const char *path, struct stat *path_info)
{
    return lstat(path, path_info) != -1;
}

int isFile(const char *path)
{
    struct stat path_info;
    if (!getPathInfo(path, &path_info))
    {
        return 0;
    }

    return S_ISREG(path_info.st_mode);
    return 1;    
}


int isBadPtr(const void *ptr)
{
    return ptr == NULL ? 1 : 0;
    //
}

void exitApp(const char *error_msg)
{
    perror(error_msg);
    exit(1);
}
int openInput(const char *filename, const char *mode, FILE** pFile, int exit_on_failure)
{
    *pFile = fopen(filename, mode);

    if (isBadPtr(*pFile))
    {
        if (exit_on_failure)
        {
            exitApp("File does not exist\n");
        }
        else
        {
            return 0;
        }
    }

    return 1;
}

void exitIfBadPtr(const void *ptr, char *error_msg)
{    
    if (isBadPtr(ptr))
    {
        exitApp(error_msg);
    }
}

void getFileLength(FILE *pFile, size_t *file_length)
{
    exitIfBadPtr(pFile, "Bad file pointer");

    int len;
    fseek(pFile, 0, SEEK_END);
    len = ftell(pFile);
    rewind(pFile);

    *file_length = (size_t)len;
}

void *allocateArray(size_t size, size_t count)
{
    void *ptr = malloc(size * count);
    exitIfBadPtr(ptr, "Failure to allocate memory.");
    return ptr;   
}

char *allocateCharArray(size_t num_bytes)
{
    return (char *)allocateArray(sizeof(char), num_bytes);  
}

int readStream(FILE *pFile, char *buffer, size_t read_length)
{
    if (isBadPtr(pFile) || isBadPtr(buffer))
    {
        return 0;
    }

    size_t chars_read = fread((void *)buffer, sizeof(char), read_length, pFile);

    if (chars_read != read_length)
    {
        return 0;
    }

    return 1;
}

void readFileContentsToArray(const char *filename, unsigned char **file_array_ptr, size_t *num_bytes, const char *mode)
{
    FILE *pFile = NULL;
    openInput(filename, mode, &pFile, 1);

    getFileLength(pFile, num_bytes);

    *file_array_ptr = allocateCharArray(*num_bytes);

    readStream(pFile, *file_array_ptr, *num_bytes);

    fclose(pFile);
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
    
        //printf("in\n");
        const int MAXLINE = 8192;
        char      buf[MAXLINE];   /* a place to store text from the client */
        bzero(buf, MAXLINE);

        /* read from socket, recognizing that we may get short counts */
        char *bufp = buf;              /* current struct nodeer into buffer */
        ssize_t nremain = MAXLINE;     /* max characters we can still read */
        size_t nsofar;                 /* characters read so far */

        bool put=false;
        bool get=false;
        char name[100];
        bzero(name,100);
        char size[100];
        bzero(size,100);
        FILE *stream;
        char res[1024];
        bzero(res,1024);
        /*
        while (1) {
            /* read some data; swallow EINTRs 
            if ((nsofar = read(connfd, bufp, nremain)) < 0) {
                if (errno != EINTR)
                    die("read error: ", strerror(errno));
                continue;
            }
            printf("get: %s, %d\n", bufp,nsofar);
            /* end service to this client on EOF 
            if (nsofar == 0) {
                fprintf(stderr, "received EOF\n");
                return;
            }
            /* update struct nodeer for next bit of reading 
            bufp += nsofar;
            nremain -= nsofar;
            printf("%c\n", *(bufp-1));
            printf("%s\n", *(bufp-1));
            if (*(bufp-1) == '\n') {
                printf("out!\n");
                *bufp = 0;
                break;
            }
        }*/
        if ((nsofar = readData(connfd, buf, 4)) < 0) {
            if (errno != EINTR)
                die("read error: ", strerror(errno));\
        }
        printf("GET COMAND:%s\n", buf);
        if(strcmp(buf,"PUTC")==0){
            //printf("set put\n");
            put=true;
        }else if(strcmp(buf,"GETC")==0)
        {
            get=true;
        }
        
        if(put){
            initialerror();
            bzero(buf,MAXLINE);
            //printf("in put\n");
            readData(connfd, name, 100);
            char* a=name;
            printf("RECEIVE:%s\n", name);
            readData(connfd, size, 100);
            //printf("recieve size:%s\n", size);
            char recvcs[33];
            readData(connfd,recvcs,33);
            int intsize=atoi(size);
            //printf("recieve size2:%d\n", intsize);
            readData(connfd,buf,intsize);
            //printf("recieve data buf:%s\n", buf);
            //test 


            char* cs;
            cs=str2md5(buf, intsize);
            if(strcmp(cs,recvcs)==0){
                
                strcpy(res,"OKC");
                sendData(connfd, res, 1024);
            }else{
                adderror("the md5 is not same!\n");
                sendData(connfd, errormessage, 1024);
                return;
            }
            free(cs);
            if((stream = fopen(name,"wb"))==NULL){
                printf("The file was not opened! \n");
            }
            int write_length = fwrite(buf,sizeof(char),intsize,stream);
            addone(name,buf,intsize);
            printf("SAVED\n");
            //shownode();
            bzero(buf,MAXLINE);
            
            fclose(stream);

        }
        if(get){
            initialerror();
            //printf("in get\n");
            readData(connfd,name,100);
            struct node *found=findone(name);
            printf("FILE NAME:%s\n", name);    
            unsigned char *file_contents = NULL;
            if(found){
                printf("FOUND IN CACHE!\n");
                //shownode();
                //printf("%s\n", found->data);
                //printf("%d\n", found->length);
                char * content=found->data;
                int length=found->length;
                char str[100];
                sprintf(str, "%d", found->length);
                strcat(errormessage,"OKC");
                sendData(connfd,errormessage,1024);
                char* cs;
                cs=str2md5(content, found->length);
                //printf("the md5 I send: %s\n", cs);
                sendData(connfd,cs,33);
                free(cs);
                //printf("the size I send%s\n", str);
                sendData(connfd,str,100);
                //printf("the content i send%s\n",content);
                sendData(connfd,content,found->length);
                printf("SENT!");
                return;
            }
            printf("NOT FOUND IN CACHE! LOOKING FOR IN FILE!\n");
            //shownode();

             if (!isFile(name))
            {
                printf("no such file\n");
                printf("%s\n", strerror(errno));
                adderror(strerror(errno));
                sendData(connfd,errormessage,1024);
                return;
            }
            printf("FOUND! SENDING......\n");


            size_t file_length;
            readFileContentsToArray(name, &file_contents, &file_length, "rb");


            char str[100];
            bzero(str,100);
            sprintf(str, "%d", file_length);
            if(strlen(errormessage)==0){
                strcat(errormessage,"OKC");
                sendData(connfd,errormessage,1024);
            }
            
            char* cs;
            cs=str2md5(file_contents, file_length);
            //printf("the md5 I send: %s\n", cs);
            sendData(connfd,cs,33);
            free(cs);
            //printf("the size I send%s, %d\n", str,file_length);
            sendData(connfd,str,100);
            //printf("the content i send%s\n",file_contents);

            int write_length = sendData(connfd,file_contents,file_length);
            addone(name,file_contents,file_length);
            printf("DONE!\n");
            free(file_contents);

        }

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
    signal(SIGINT, clearnode);

    /* parse the command-line options.  They are 'p' for port number,  */
    /* and 'l' for lru cache size.  'h' is also supported. */
    while ((opt = getopt(argc, argv, "hl:p:")) != -1) {
        switch(opt) {
          case 'h': help(argv[0]); break;
          case 'l': lru_size = atoi(optarg); break;
          case 'p': port = atoi(optarg); break;
        }
    }
    //printf("lru_size%d\n", lru_size);
    cachenum=lru_size;
    /* open a socket, and start handling requests */
    int fd = open_server_socket(port);
    handle_requests(fd, file_server, lru_size);

    exit(0);
}
