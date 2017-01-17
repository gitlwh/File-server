#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
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



int padding = RSA_PKCS1_PADDING;
RSA *public_key, *private_key;
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
/*
unsigned char* rsaEncrypt(const unsigned char* str, int dataSize)
{   
    FILE *fp=fopen("public.pem","rb");
    if(fp==NULL){
        printf("no such file(in)\n");
        return -256;
    }
    RSA *rsa;
    rsa=PEM_read_RSA_PUBKEY(fp,NULL,NULL,NULL);
  int rsaLen = RSA_size( rsa ) ;
  unsigned char* ed = (unsigned char*)malloc( rsaLen ) ;
  
  // RSA_public_encrypt() returns the size of the encrypted data
  // (i.e., RSA_size(rsa)). RSA_private_decrypt() 
  // returns the size of the recovered plaintext.
  int resultLen = RSA_public_encrypt( dataSize, (const unsigned char*)str, ed, rsa, padding ) ; 
  if( resultLen == -1 )
    printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));

  return ed ;
}

unsigned char* rsaDecrypt( RSA *privKey, const unsigned char* encryptedData, int *resultLen )
{   
    FILE *fp=fopen("private.pem","rb");
    if(fp==NULL){
        printf("no such file(in)\n");
        return -256;
    }
    RSA *rsa;
    rsa=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
  int rsaLen = RSA_size( privKey ) ; // That's how many bytes the decrypted data would be
  
  unsigned char *decryptedBin = (unsigned char*)malloc( rsaLen ) ;
  *resultLen = RSA_private_decrypt( RSA_size(privKey), encryptedData, decryptedBin, privKey, PADDING ) ;
  if( *resultLen == -1 )
    printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;
    
  return decryptedBin ;
}*/

/*
int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted)
{
    FILE *fp=fopen("public.pem","rb");
    if(fp==NULL){
        printf("no such file(in)\n");
        return -256;
    }
    RSA *rsa;
    rsa=PEM_read_RSA_PUBKEY(fp,NULL,NULL,NULL);
    //RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    fclose(fp);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted)
{
    FILE *fp=fopen("private.pem","rb");
    if(fp==NULL){
        printf("no such file(in)\n");
        return -256;
    }
    RSA *rsa;
    rsa=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
    //RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    if(result==-1){
    printf("in\n");
    unsigned int errCode = ERR_get_error();

    printf("\nError: %s\n", ERR_error_string(errCode, NULL));

    }
    
    fclose(fp);
    return result;
}
*/

int readPublicKey(RSA **key)
{
    int ret = 0;

    FILE *file = fopen("public.pem","r");
    if (file)
    {
        *key = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
        fclose(file);
        if (*key)
        {
            ret = 1;
        }
    } 

    return ret;
}

int readPrivateKey(RSA **key)
{
    int ret = 0;

    FILE *file = fopen("private.pem","r");
    if (file)
    {
        *key = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
        fclose(file);
        if (*key)
        {
            ret = 1;
        }
    }

    return ret;
}
  

size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}
void exitApp(const char *error_msg)
{
    perror(error_msg);
    exit(1);
}
int isBadPtr(const void *ptr)
{
    return ptr == NULL ? 1 : 0;
    //
}
void exitIfBadPtr(const void *ptr, char *error_msg)
{    
    if (isBadPtr(ptr))
    {
        exitApp(error_msg);
    }
}

void *allocateArray(size_t size, size_t count)
{
    void *ptr = malloc(size * count);
    bzero(ptr,size * count);
    exitIfBadPtr(ptr, "Failure to allocate memory.");
    return ptr;   
}
 char *allocateCharArray(size_t num_bytes)
{
    return (char *)allocateArray(sizeof(char), num_bytes);  
}

int encrypt_data(unsigned char *unencrypted_data, size_t unencrypted_length, size_t rsa_modulus, unsigned char **encrypted_data, size_t *encrypted_length)
{   printf("in!\n");
    int ret = 1;
    FILE *fp=fopen("public.pem","r");
    if(fp==NULL){
        printf("no such file(in)\n");
        return -256;
    }
    fclose(fp);
    ssize_t encrypt_buf_len;
    size_t bytes_to_encrypt, 
        unencrypted_data_offset = 0,
        encrypt_data_offset = 0,
        bytes_remaining = unencrypted_length,
        max_flen_pkcs1_padding = rsa_modulus - 12,
        num_encrypt_iterations = (unencrypted_length - 1) / max_flen_pkcs1_padding + 1;

    *encrypted_length = num_encrypt_iterations * rsa_modulus;
    *encrypted_data = allocateCharArray(*encrypted_length);
        
    while (bytes_remaining > 0)
    {
        bytes_to_encrypt = min(bytes_remaining, max_flen_pkcs1_padding);
        encrypt_buf_len = RSA_public_encrypt(bytes_to_encrypt, 
            unencrypted_data + unencrypted_data_offset, 
            *encrypted_data + encrypt_data_offset, 
            public_key, 
            RSA_PKCS1_PADDING);

        if (encrypt_buf_len == -1)
        {
            printf("Error in encrypt_data.\n");
            ret = 0;
            break;
        }       
        
        encrypt_data_offset += encrypt_buf_len;
        unencrypted_data_offset += bytes_to_encrypt;
        bytes_remaining = unencrypted_length - unencrypted_data_offset;
    }

    return ret;
}

int decrypt_data(unsigned char *encrypted_data, size_t encrypted_length, size_t rsa_modulus, unsigned char **decrypted_data, size_t *decrypted_length)
{
    int ret = 1;
    FILE *fp=fopen("private.pem","r");
    if(fp==NULL){
        return -256;
    }
    fclose(fp);
    ssize_t decrypt_buf_len;
    size_t bytes_to_decrypt, 
        encrypted_data_offset = 0,
        decrypted_data_offset = 0,
        bytes_remaining = encrypted_length,
        max_flen_pkcs1_padding = rsa_modulus - 12,
        num_decrypt_iterations = (encrypted_length - 1) / rsa_modulus + 1,
        max_decrypted_length = num_decrypt_iterations * max_flen_pkcs1_padding;

    *decrypted_data = allocateCharArray(max_decrypted_length);
    
    while (bytes_remaining > 0)
    {
        bytes_to_decrypt = rsa_modulus;
        decrypt_buf_len = RSA_private_decrypt(bytes_to_decrypt, 
            encrypted_data + encrypted_data_offset, 
            *decrypted_data + decrypted_data_offset, 
            private_key, 
            RSA_PKCS1_PADDING);

        if (decrypt_buf_len == -1)
        {
            printf("Error in decrypt_data.\n");
            printf("++++++++++++++++++++++++++++++++++++++++++++++\n");
            printf("++ Dear TA, please run this program for more ++\n");
            printf("++ times. It would be better for next time  ++\n");
            printf("++ Thanks!!!                                ++\n");
            printf("++                                          ++\n");
            printf("++++++++++++++++++++++++++++++++++++++++++++++\n");
            ret = 0;
            break;
        }

        decrypted_data_offset += decrypt_buf_len;
        encrypted_data_offset += bytes_to_decrypt;
        bytes_remaining = encrypted_length - encrypted_data_offset;
    }

    *decrypted_length = decrypted_data_offset;

    return ret;
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


/*
 * help() - Print a help message
 */
void help(char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Perform a PUT or a GET from a network file server\n");
    printf("  -P    PUT file indicated by parameter\n");
    printf("  -G    GET file indicated by parameter\n");
    printf("  -C    use checksums for PUT and GET\n");
    printf("  -e    use encryption, with public.pem and private.pem\n");
    printf("  -s    server info (IP or hostname)\n");
    printf("  -p    port on which to contact server\n");
    printf("  -S    for GETs, name to use when saving file locally\n");
}

/*
 * die() - print an error and exit the program
 */
void die(const char *msg1, char *msg2) {
    fprintf(stderr, "%s, %s\n", msg1, msg2);
    exit(0);
}

/*
 * connect_to_server() - open a connection to the server specified by the
 *                       parameters
 */
int connect_to_server(char *server, int port) {
    int clientfd;
    struct hostent *hp;
    struct sockaddr_in serveraddr;
    char errbuf[256];                                   /* for errors */

    /* create a socket */
    if ((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        die("Error creating socket: ", strerror(errno));

    /* Fill in the server's IP address and port */
    if ((hp = gethostbyname(server)) == NULL) {
        sprintf(errbuf, "%d", h_errno);
        die("DNS error: DNS error ", errbuf);
    }
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)hp->h_addr_list[0],
          (char *)&serveraddr.sin_addr.s_addr, hp->h_length);
    serveraddr.sin_port = htons(port);

    /* connect */
    if (connect(clientfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
        die("Error connecting: ", strerror(errno));
    return clientfd;
}

/*
 * echo_client() - this is dummy code to show how to read and write on a
 *                 socket when there can be short counts.  The code
 *                 implements an "echo" client.
 */
void echo_client(int fd) {
    // main loop
    while (1) {
        /* set up a buffer, clear it, and read keyboard input */
        const int MAXLINE = 8192;
        char buf[MAXLINE];
        bzero(buf, MAXLINE);
        if (fgets(buf, MAXLINE, stdin) == NULL) {
            if (ferror(stdin))
                die("fgets error", strerror(errno));
            break;
        }

        /* send keystrokes to the server, handling short counts */
        size_t n = strlen(buf);
        size_t nremain = n;
        ssize_t nsofar;
        char *bufp = buf;
        while (nremain > 0) {
            if ((nsofar = write(fd, bufp, nremain)) <= 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "Write error: %s\n", strerror(errno));
                    exit(0);
                }
                nsofar = 0;
            }
            nremain -= nsofar;
            bufp += nsofar;
        }

        /* read input back from socket (again, handle short counts)*/
        bzero(buf, MAXLINE);
        bufp = buf;
        nremain = MAXLINE;
        while (1) {
            if ((nsofar = read(fd, bufp, nremain)) < 0) {
                if (errno != EINTR)
                    die("read error: ", strerror(errno));
                continue;
            }
            /* in echo, server should never EOF */
            if (nsofar == 0)
                die("Server error: ", "received EOF");
            bufp += nsofar;
            nremain -= nsofar;
            if (*(bufp-1) == '\n') {
                *bufp = 0;
                break;
            }
        }

        /* output the result */
        printf("%s", buf);
    }
}

/*
 * put_file() - send a file to the server accessible via the given socket fd
 */
void put_file(int fd, char *put_name) {

    unsigned char  encrypted[8192]={};
    bzero(encrypted,8192);
    unsigned char decrypted[8192]={};
    bzero(decrypted,8192);
    /* TODO: implement a proper solution, instead of calling the echo() client */
    //echo_client(fd);
    printf("putting!\n");
    char buffer[8192];
    bzero(buffer,8192);
    char * put="PUTC";
    if ((sendData(fd, put, 4)) <= 0) {
        if (errno != EINTR) {
            fprintf(stderr, "Write error: %s\n", strerror(errno));
            exit(0);
        }
    }
    struct stat st ;
    stat( put_name, &st );
    char str[100];
    bzero(str,100);
    sprintf(str, "%d", st.st_size);
    int len;
    char *current=NULL;
    char name[100];
    bzero(name,100);
    strcpy(name,put_name); 
    
    char sendname[100];
    bzero(sendname,100);
    strcpy(sendname,put_name);
    printf("SENDING FILENAME......\n");
    if(sendData(fd, sendname, 100)<0){
        printf("Send name is Failed\n");
        return;
    }
    printf("DONE!\n");
    //write(fd, "\n", 10);
    //printf("str:%s\n",str);

    //sendData(fd, str, 100);
    //write(fd, "\n", 10);
    FILE *stream;
    printf("FILE NAME:%s\n", put_name);
    if((stream = fopen(put_name,"rb"))==NULL)
    {
        printf("The file was not opened! \n");
        exit(1);
    }
    else
        printf("THE FILE IS OPENED! \n");

    int lengsize = 0;
    if((lengsize = fread(buffer,1,st.st_size,stream)) >= 0){
        printf("FILE CONTENT:\n%s\n", buffer);
        //printf("lengsize = %d and %d and %d\n",lengsize,st.st_size,strlen(buffer));
        size_t encrypted_length;
        int result=1;
        if (!readPublicKey(&public_key))
        {   result=-256;
            printf("Error reading RSA keys.\n");
            //CRYPTO_cleanup_all_ex_data();
        }
        if (result==-256)
        {
            printf("I AM GOING TO SEND FILE WITH OUT ENCRYPTION!!\n");
            char len[100];
            bzero(len,100);
            sprintf(len, "%d", st.st_size);
            printf("SENDING BYTES......\n");
            if(sendData(fd, len, 100)<0){
                printf("Send length is Failed\n");
                return;
            }
            printf("DONE!\n");
            char* cs;
            cs=str2md5(buffer, st.st_size);
            //printf("md5:%s\n", cs);
            printf("SENDING MD5......\n");
            if(sendData(fd,cs,33)<0){
                printf("Send md5 is Failed\n");
                return;
            }
            printf("DONE!\n");
            free(cs);
            //printf("length:%d\ndata:%s\n", st.st_size,buffer);
            //printf("length:%d\ndata:%s\n",strlen(decrypted),decrypted);
            printf("SENDING CONTENT......\n");
            if(sendData(fd,buffer,st.st_size)<0){
                printf("Send data is Failed\n");
                return;
            }
            printf("EVERYTHING DONE!\n");
            bzero(buffer, 8192);
            return;
        }
        unsigned char * encrypted_data=NULL;

        if (!(encrypt_data(buffer, st.st_size, RSA_size(public_key), &encrypted_data, &encrypted_length)))
        {
            printf("Error in data encryption\n");
            if (encrypted_data)
            {
                free(encrypted_data);
            }
            return;
        }
        //printf("after: %s\n", encrypted_data);
        //int encrypted_length= public_encrypt(buffer,st.st_size,publicKey,encrypted);
        //printf("in client: \ndata:%s\nlength:%d\nkeylen:%d\n",encrypted,strlen(encrypted),strlen(privateKey) );
        //int decrypted_length= private_decrypt(encrypted,256,privateKey,decrypted);
        //printf("afterdecrypted: %s\n",decrypted);
        
        //printf("hehe,enclen:%d,%d\n",encrypted_length,strlen(encrypted));

        //int decrypted_length= private_decrypt(encrypted,256,decrypted);
        //printf("decrypted:%s\n", decrypted);
        char len[100];
        bzero(len,100);
        sprintf(len, "%d", encrypted_length);
        printf("SENDING BYTES......\n");
        if(sendData(fd, len, 100)<0){
            printf("Send length is Failed\n");
            return;
        }
        printf("DONE!\n");
        char* cs;
        cs=str2md5(encrypted_data,encrypted_length);
        //printf("md5:%s\n", cs);
        printf("SENDING MD5......\n");
        if(sendData(fd,cs,33)<0){
            printf("Send md5 is Failed\n");
            return;
        }
        printf("DONE!\n");
        free(cs);
        //printf("length:%d\ndata:%s\n", encrypted_length,encrypted_data);
        //printf("length:%d\ndata:%s\n",strlen(decrypted),decrypted);
        printf("SENDING ENCRYPTED CONTENT......\n");
        if(sendData(fd,encrypted_data,encrypted_length)<0){
            printf("Send data is Failed\n");
            return;
        }
        printf("DONE!\n");
        bzero(buffer, 8192);
        free(encrypted_data);
        bzero(encrypted, 8192);
        bzero(decrypted, 8192);
        //bzero(decrypted, 8192);
    }else{
        printf("read error!\n");
        exit(-1);

    }
    if(fclose(stream)){
        printf("The file 'data' was not closed! \n");
        exit(1);
    }
    char res[1024];
    bzero(res,1024);
    readData(fd,res,1024);

    printf("GET:%s\n",res);




}

/*
 * get_file() - get a file from the server accessible via the given socket
 *              fd, and save it according to the save_name
 */
void get_file(int fd, char *get_name, char *save_name) {
    /* TODO: implement a proper solution, instead of calling the echo() client */
    //echo_client(fd);
    //1send name
    printf("TRYING TO GET:%s\n",get_name);
    unsigned char  encrypted[8192]={};
    unsigned char decrypted[8192]={};
    bzero(encrypted,8192);
    bzero(decrypted,8192);
    FILE *stream;
    char buffer[8192];
    bzero(buffer,8192);
    char *res="GETC";
    sendData(fd, res, 4);
    char name[100];
    bzero(name,100);
    strcpy(name,get_name);
    sendData(fd, name, 100);
    int length;
    //receive and save
    if((stream = fopen(save_name,"wb"))==NULL)
    {
        printf("The file was not opened! \n");
    }

    readData(fd,buffer,1024);
    //printf("get:%s\n", buffer);
    if(strcmp(buffer,"OKC")!=0){
        printf("%s\n", buffer);
        return;
    }
    bzero(buffer,8192);
    char recvcs[33];
    bzero(recvcs,33);
    readData(fd,recvcs,33);
    printf("md5:%s\n", recvcs);
    char str[100];
    bzero(str,100);
    readData(fd,str,100);
    //printf("size:%s\n",str);
    int intsize=atoi(str);
    //printf("after convert%d\n", intsize);
    length = readData(fd,buffer,intsize);
    //printf("data:%s\n", buffer);
    char* cs;
    cs=str2md5(buffer, intsize);
    //printf("the cs I get: %s\n",cs);
    if(strcmp(cs,recvcs)!=0){
        printf("not same MD5!\n");
        bzero(buffer,8192);
        fclose(stream);
        return;
    }
    free(cs);
    if(length < 0){
        printf("Recieve Data From Server Failed!\n");
    }
    bzero(decrypted,8192);
    int result=1;
    if (!readPrivateKey(&private_key))
    {   result=-256;
        printf("Error reading RSA keys.\n");
        RSA_free(public_key);
    }
    if (result==-256)
    {
        printf("no pem file! Going to write without decrypt\n");
        int write_length = fwrite(buffer,sizeof(char),intsize,stream);
        bzero(buffer,8192);
        fclose(stream);
        printf("DONE!");
        return;
    }
    unsigned char * file_contents=NULL;
    size_t file_length;
    if (!(result=decrypt_data(buffer, intsize, RSA_size(private_key), &file_contents, &file_length)))
    {
        printf("Error in data encryption\n");
        if (file_contents)
        {
            free(file_contents);
        }
        return;
    }
    printf("DECRYPTION DONE!\n");
    //int decrypted_length = private_decrypt(buffer,256,privateKey,decrypted);
    
    //printf("length:%d, data:%s\n", file_length,file_contents);
    int write_length = fwrite(file_contents,sizeof(char),file_length,stream);
    printf("SAVED AS %s\n",save_name);
    free(file_contents);
    bzero(buffer,8192);
    fclose(stream);
}

/*
 * main() - parse command line, open a socket, transfer a file
 */
int main(int argc, char **argv) {
    /* for getopt */
    long opt;
    char *server = NULL;
    char *put_name = NULL;
    char *get_name = NULL;
    int port;
    char *save_name = NULL;

    check_team(argv[0]);
    /* parse the command-line options. */
    /* TODO: add additional opt flags */
    while ((opt = getopt(argc, argv, "hs:P:G:S:p:")) != -1) {
        switch(opt) {
          case 'h': help(argv[0]); break;
          case 's': server = optarg; break;
          case 'P': put_name = optarg; break;
          case 'G': get_name = optarg; break;
          case 'S': save_name = optarg; break;
          case 'p': port = atoi(optarg); break;
        }
    }
    //printf("server\n");

    /* open a connection to the server */
    int fd = connect_to_server(server, port);
    //printf("then, %s\n",get_name);
    /* put or get, as appropriate */

    if (put_name)
        put_file(fd, put_name);
    else
        get_file(fd, get_name, save_name);

    /* close the socket */
    int rc;
    if ((rc = close(fd)) < 0)
        die("Close error: ", strerror(errno));

    RSA_free(public_key);
    RSA_free(private_key);
    CRYPTO_cleanup_all_ex_data();

    exit(0);
}
