#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#define BSIZE 0x1000
#define BUF_LEN 1024

/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */
static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args{
  struct sockaddr_in destaddr; //destination/server address
  unsigned short port; //destination/listen port
  unsigned short listen; //listen flag
  int n_bytes; //number of bytes to send
  int offset; //file offset
  int verbose; //verbose output info
  int website; // retrieve website at client 
  char * filename; //input/output file
}nc_args_t;


/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
void usage(FILE * file){
  fprintf(file,
         "netcat_part [OPTIONS]  dest_ip file \n"
         "\t -h           \t\t Print this help screen\n"
         "\t -v           \t\t Verbose output\n"
	 "\t -w           \t\t Enable website get mode at client\n"
         "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         "\t -o offset    \t\t Offset into file to start sending\n"
         "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         );
}

/**
 *parse_args(nc_args_t * nc_args, int argc, char * argv[]) -> void
 *
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return resutls
 **/

void parse_args(nc_args_t * nc_args, int argc, char * argv[]){
  int ch;
  struct hostent * hostinfo;

  //set defaults
  nc_args->n_bytes = 0;
  nc_args->offset = 0;
  nc_args->listen = 0;
  nc_args->port = 6767;
  nc_args->verbose = 0;

  while ((ch = getopt(argc, argv, "hwvp:n:o:l")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'l': //listen
      nc_args->listen = 1;
      break;
    case 'p': //port
      nc_args->port = atoi(optarg);
      break;
    case 'o'://offset
      nc_args->offset = atoi(optarg);
      break;
    case 'n'://bytes
      nc_args->n_bytes = atoi(optarg);
      break;
    case 'v':
      nc_args->verbose = 1;
      break;
    case 'w':
      nc_args->website = 1;
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }

  argc -= optind;
  argv += optind;

  if (argc < 2){
    fprintf(stderr, "ERROR: Require ip and file\n");
    usage(stderr);
    exit(1);
  }
    

  /* Initial the sockaddr_in based on the parsing */
  if(!(hostinfo = gethostbyname(argv[0]))){
    fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
    usage(stderr);
    exit(1);
  }
  
  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
        hostinfo->h_length);
  
  if(nc_args->listen){
    nc_args->destaddr.sin_port = htons(nc_args->port);
  }else{
    nc_args->destaddr.sin_port = htons(nc_args->port);
  }

  
  /* Save file name */
  nc_args->filename = malloc(strlen(argv[1])+1);
  strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
  
  
  return;

}

///////////////////////////////////////////////////////////////////////////////
void webmode(int sockfp,nc_args_t nc_args,int count, char * file_name)
{
char buf[BSIZE];
//printf("\n inside webmode");

if((sockfp=socket(AF_INET,SOCK_STREAM,0))== -1)
{
perror("socket");
exit(1);
}
if(nc_args.verbose == 1) printf("\n socket created to request web page");

if(count==0) 
{
count=1000;
}
//printf(" bytesnumber intialized to %d",count);
char req[count];
int bytes,bytessent;
int TIMEOUT_SECS=5;
FILE *fp = fopen(file_name, "r");
if(!fp){
printf("Invalid file name");
exit(1);
}

fread(req,1,count,fp);
//printf("\n Format string is %s",req);
if (connect(sockfp,(struct sockaddr *)&(nc_args.destaddr),sizeof(nc_args.destaddr)) < 0) 
 perror("Connect");

//printf("Before sent request to server");
bytessent=send(sockfp,req,count,0);
//Send web req to server
//printf("\n bytes : %d",bytessent);
if(bytessent<0){
printf("send request to server  failed");
exit(1);
}
if(nc_args.verbose == 1)printf("sent request to web server \n ");
  FILE *file = fopen("webfile.txt", "w");
while (1) {
       
  	  alarm(TIMEOUT_SECS);
        bytes = recvfrom (sockfp, buf, BSIZE, 0, 0, 0);
         if (errno == EINTR) {
                   printf("Error: Timeout Exceedded");
                    close(sockfp);
                    exit(1);
                }
        if (bytes == -1) {
            fprintf (stderr, "%s\n", strerror(errno));
            exit (1);
        }
        buf[bytes] = '\0';

        //printf ("%s", buf);

        if (bytes == 0) {
            break;
        }

int status = fputs(buf, file);
    }
//writing into file named webfile.txt
if(nc_args.verbose == 1) printf(" request is processed and stored in webfile.txt \n ");

}





///////////////////////////////////////////////////////////////////







void call_HMAC(char* key, char * data,int data_length, char * msgdigest, int* len){
    
    //printf("inside HMAC \n");

    unsigned char* digest;
    
   
    //digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);
    digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, data_length , NULL, NULL);
    printf("size of digest: %u ", sizeof(digest));
    
    printf("inside HMAC digest: %s  \n", digest);

    ////////////////////////////////////////////////////
    // this convert 20 byte digest to 40 bytes hexadecimal
    char codeString[40];
    int i;
    for(i = 0; i < 20; i++)
         {
             sprintf(&msgdigest[i*2], "%02x", (unsigned int)digest[i]);
             sprintf(&codeString[i*2], "%02x", (unsigned int)digest[i]);
             
        }

    printf(" inside HMAC: HMAC digest in hexa : %s\n", codeString);
    printf("inside HMAC: msgdigest digest in hexa : %s\n", msgdigest);

    //if(nc_args.verbose == 1) printf("HMAC computed for message/ chunck: %s  is :: %s \n",data,codestring);
    //msgdigest=codeString;
    *len= 40;
    
    ///////////////////////////////////////////////
    
    
    return;    
}

void waite_for_server(int sockfd){
        
        
        printf(" \nNow waiting to hear from server\n :");
        // check
        static const unsigned int TIMEOUT_SECS = 5;
        struct sockaddr_storage fromAddr; // Source address of server
        socklen_t fromAddrLen = sizeof(fromAddr);
        alarm(TIMEOUT_SECS);
        char buffer[1000 + 1]; // I/O buffer
        //alarm(TIMEOUT_SECS);
        int numBytes;
        
        while ((numBytes = recvfrom(sockfd, buffer, 1000, 0,
                (struct sockaddr *) &fromAddr, &fromAddrLen)) < 0) {
                if (errno == EINTR) {
                    
                    printf("Error: Recived Error msg from the server");
                    close(sockfd);
                }
            
        }

        
        //if(nc_args.verbose == 1) printf(" numBytes recived from the server is %i \n", numBytes );
        
//       if(nc_args.verbose == 1) printf(" Msg recived from the server is %s \n", buffer );
    
         printf(" Msg recived from the server is %s \n", buffer );

    
    
// return 0;    
}


void send_data(int sockfd, int offset_file, int byteNumber_file, char* file_name){
    
    FILE *file = fopen(file_name, "r");
    
    if (!file)
    {
        printf("ERROR: Can not open file for reading");
        exit(1);
        
    }
    
    /////////////////////////////////////////
    char buf[956]; // 44 byte for security hash+length , 
    int secure_bytes=44; // reserved for hash+ 4 byte (int for length) .. Hash is 20 byte bute we convert to hexa so it is 40 byte string
    int readedBytes ;
    int off;
    int sent;
    int s;
    unsigned char msg_buff[1001];
    
    char* msgdigest= malloc (40* sizeof(char));;
    int * len= malloc (1* sizeof(int));
    //*len=40;
    char hhlen[5];
    
    if (byteNumber_file == 0 )
    {
        
        while (!feof(file))
        {
            // read 1000 byte each time and but it on buffer and send it to to the server
            
            readedBytes = fread(buf, 1, sizeof(buf), file);
            
            if (readedBytes> 1)
            {
             
                off = 0;  
                while (off< readedBytes)
                {
                    
                    // get the hmac code for the bytes and add to it to send
                    call_HMAC(key, &buf[off],readedBytes - off,msgdigest,len);
                    sprintf(hhlen, "%04x", *len);
                    
                    //printf(" computed HMAC for bytes : %s \n",msgdigest);
                    //printf(" Length  HMAC for bytes : %s \n",hhlen);
                    // COPY msg from buffer and add to it the HMAC code and the length of HMAC code
                    int idx=0;
                    int idxx=0;
                    for ( idx=0;idx< readedBytes - off;idx++)
                             msg_buff[idx]=* (&buf[off+idx]);
                    msg_buff[idx]=NULL;
                    
                    //printf("msg  (1) oringial msg : %s  \n",msg_buff);
                    //printf("SIZE OF msg  (1) oringial msg : %i  \n",strlen(msg_buff));
                    strcat(msg_buff, msgdigest);
                    
                    //printf("msg  (2) original msg + HMAC code : %s \n",msg_buff);
                    //printf("Size of msg  (2) original msg + HMAC code : is %i \n",strlen(msg_buff));
                    
                    //printf("hhlen  %s --\n",hhlen); 
                    strcat(msg_buff, hhlen);
                    
                   
                     //printf("msg  (3) original msg + HMAC code +len of Hash : %s \n",msg_buff);
                    
                     //printf("length of the whole msg is  %i \n",strlen(msg_buff));
                    
                    //sent = send(sockfd, &buf[off], readedBytes - off, 0);
                    
                    sent = send(sockfd, msg_buff, strlen(msg_buff), 0);
                    //if(nc_args.verbose == 1) printf("%i Bytes are sent to the server:",sent);
                    
                    if (sent < 1)
                    {
                        printf("Can't write to socket");
                        fclose(file);
                        return;
                    }
                    waite_for_server(sockfd);
                    
                    off += sent;

                 }
            
            }
        
        }

    }
    
    if (byteNumber_file > 0)
    {
        // Note the file is already opened so seek and read numbre of bytes and send it to the srever
        
        
        s=fseek(file,offset_file,SEEK_CUR);
        
        //printf(" seek of file status %i \n",s);

        if (s==0)
        {
            
            readedBytes=0;
            int readedtillNow=0;
            while (!feof(file) && readedtillNow <byteNumber_file)
            {
                // read 1000 byte each time and but it on buffer and send it to to the server
                
                printf(" %ibuffer size and byteNumber_file%i \n",sizeof(buf),byteNumber_file);

                if (sizeof(buf) > byteNumber_file)
                {
                    int readedBytes = fread(buf, 1, byteNumber_file, file);
                    readedtillNow=readedtillNow+readedBytes;
                    
                    if (readedBytes> 1)
                    {
                        
                        int off = 0;
                        while (off< readedBytes)
                        {
                            
                            ////// add MAC
                            call_HMAC(key, &buf[off],readedBytes - off,msgdigest,len);
                            sprintf(hhlen, "%04x", *len);
                            
                            //printf(" computed HMAC for bytes : %s \n",msgdigest);
                            //printf(" Length  HMAC for bytes : %s \n",hhlen);
                            // COPY msg from buffer and add to it the HMAC code and the length of HMAC code
                            int idx=0;
                            int idxx=0;
                            for ( idx=0;idx< readedBytes - off;idx++)
                                     msg_buff[idx]=* (&buf[off+idx]);
                            msg_buff[idx]=NULL;
                            
                            //printf("msg  (1) oringial msg : %s  \n",msg_buff);
                            //printf("SIZE OF msg  (1) oringial msg : %i  \n",strlen(msg_buff));
                            strcat(msg_buff, msgdigest);
                            
                            //printf("msg  (2) original msg + HMAC code : %s \n",msg_buff);
                            //printf("Size of msg  (2) original msg + HMAC code : is %i \n",strlen(msg_buff));
                            
                            //printf("hhlen  %s --\n",hhlen); 
                            strcat(msg_buff, hhlen);
                            
                           
                             //printf("msg  (3) original msg + HMAC code +len of Hash : %s \n",msg_buff);
                            
                            //printf("length of the whole msg is  %i \n",strlen(msg_buff));
                            
                            //sent = send(sockfd, &buf[off], readedBytes - off, 0);
                            
                            int sent = send(sockfd, msg_buff, strlen(msg_buff), 0);
                         //   if(nc_args.verbose == 1) printf("%i Bytes are sent to the server:",sent);
                            waite_for_server(sockfd);
                            
                            ////////
                            
                            if (sent < 1)
                            {
                                printf("Can't write to socket\n");
                                fclose(file);
                                return;
                            }
                            
                            off += sent;
                            
                        }
                        
                     }

                    
                } // end if
                
                
                else
                {
                    int readedBytes = fread(buf, 1, sizeof(buf), file);
                    readedtillNow=readedtillNow+readedBytes;

                    if (readedBytes> 1)
                    {
                        
                        int off = 0;
                        while (off< readedBytes)
                        {
                            
                            
                            ////// add MAC
                            call_HMAC(key, &buf[off],readedBytes - off,msgdigest,len);
                            sprintf(hhlen, "%04x", *len);
                            
                            //printf(" computed HMAC for bytes : %s \n",msgdigest);
                            //printf(" Length  HMAC for bytes : %s \n",hhlen);
                            // COPY msg from buffer and add to it the HMAC code and the length of HMAC code
                            int idx=0;
                            int idxx=0;
                            for ( idx=0;idx< readedBytes - off;idx++)
                                     msg_buff[idx]=* (&buf[off+idx]);
                            msg_buff[idx]=NULL;
                            
                            //printf("msg  (1) oringial msg : %s  \n",msg_buff);
                            //printf("SIZE OF msg  (1) oringial msg : %i  \n",strlen(msg_buff));
                            strcat(msg_buff, msgdigest);
                            
                            //printf("msg  (2) original msg + HMAC code : %s \n",msg_buff);
                            //printf("Size of msg  (2) original msg + HMAC code : is %i \n",strlen(msg_buff));
                            
                            //printf("hhlen  %s --\n",hhlen); 
                            strcat(msg_buff, hhlen);
                            
                           
                             //printf("msg  (3) original msg + HMAC code +len of Hash : %s \n",msg_buff);
                            
                             //printf("length of the whole msg is  %i \n",strlen(msg_buff));
                            
                            //sent = send(sockfd, &buf[off], readedBytes - off, 0);
                            
                            int sent = send(sockfd, msg_buff, strlen(msg_buff), 0);
                            // printf("%i Bytes are sent to the server:",sent);
                           
                            waite_for_server(sockfd);
                            //int sent = send(sockfd, &buf[off], readedBytes - off, 0);
                         //   if(nc_args.verbose == 1) printf("%i Bytes are sent to the server: \n",sent);

                            if (sent < 1)
                            {
                                printf("Can't write to socket\n");
                                fclose(file);
                                return;
                            }
                            
                            off += sent;
                            
                           
                            
                        }
                        
                    }
                }// end else
                
            } // end while

        }  // end if
        else
        {
            printf(" Error:Can not seek to this file position\n");
            return;
        }
        
    
        
    
    close(sockfd);
    
    fclose(file);
    
 

    }



}



void handle_processing_checkHMAC_write_to_file (int sock, FILE* fp)
{
    int n;
    //char* key= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    

    char* msgdigest= malloc (41* sizeof(char));;
    int * len= malloc (1* sizeof(int));
    
    
    
    
    while(1)
    {
        char buffer[1000];
        bzero(buffer,1000);
        n = read(sock,buffer,1000);
        if (n < 0)
        {
            perror("ERROR reading from socket");
            exit(1);
        }
    
        buffer[n]=NULL;
    
    char* orgmsg= malloc((n-44)*sizeof(char));
    char* clientHMAC= malloc((41)*sizeof(char));
    strncpy ( orgmsg, buffer, n-44);
    strncpy ( clientHMAC, &buffer[n-44],40);
    
    clientHMAC[40]=NULL;
    msgdigest[40]=NULL;
    call_HMAC(key, orgmsg,n-44,msgdigest,len);
    
    if (strcmp (clientHMAC,msgdigest) == 0)
    {
//       if(nc_args.verbose == 1) printf("This message is authenictaed, Now Writing to file \n");
        fwrite(orgmsg,1,n-44,fp);
        fflush(fp);
        n = write(sock,"I got your message",18);
        if (n < 0) 
        {
            perror("ERROR writing to socket");
            exit(1);
        }    
        
        printf("Done WWriting to file \n");
    }
    else{
            printf("This message is not authenictaed \n");

            exit(0);
        }
    
        
    }
    
        close(sock);

    
    
}
void server3(int sockfd,nc_args_t nc_args){
    
    //nc_args.destaddr.sin_addr.s_addr= htonl (INADDR_ANY);
    nc_args.destaddr.sin_addr.s_addr = INADDR_ANY;
    struct sockaddr_in client_addr;
    int pid;
    int newsockfd, portno, clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int  n;
    
    

    if(bind(sockfd,(const struct sockaddr *)&(nc_args.destaddr),sizeof(nc_args.destaddr))<0)
    {
        
    perror("Bind");
    exit(1);
    }
    

    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    
    while (1) 
    {
             newsockfd = accept(sockfd, 
                (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0)
        {
            perror("error on accept");
            close(sockfd);
            exit(1);
        }
        /* Create child process */
        pid = fork();
        if (pid < 0)
        {
            perror("error on fork");
            close(sockfd);
	    exit(1);
        }
        if (pid == 0)  
        {
            close(sockfd);
               FILE *fp = fopen(nc_args.filename, "w");
            if(!fp){
            printf("Can not open file for writing");
            exit(1);
                }

            handle_processing_checkHMAC_write_to_file(newsockfd,fp);
            fclose(fp);
            
            exit(0);
        }
        else
        {
            close(newsockfd);
        }
    } /* end of while */
    
   close(sockfd); 
}




/////////////////////////////////////////////////////////////////////////////
int main(int argc, char * argv[])
{

  nc_args_t nc_args;
  int sockfd;
  char input[BUF_LEN];

  //initializes the arguments struct for your use
  parse_args(&nc_args, argc, argv);
  //printf("argc intialized!!\n");

if((sockfd=socket(AF_INET,SOCK_STREAM,0))== -1)
{
perror("socket");
exit(1);
}
//printf("socket created..waiting to connect");
//printf("Bytes :%d , Filename: %d",nc_args.n_bytes,nc_args.filename);

if(nc_args.website == 1)
{ 	
if(nc_args.verbose == 1) printf("In website mode \n ");
webmode(sockfd,nc_args,nc_args.n_bytes,nc_args.filename);
}
else if (nc_args.listen == 1) {
if(nc_args.verbose == 1) printf("In Listen mode \n");
server3(sockfd,nc_args);
close(sockfd);
}
else{

   if(nc_args.verbose == 1) printf("In Client mode \n ");
   if (connect(sockfd,(struct sockaddr *)&(nc_args.destaddr),sizeof(nc_args.destaddr)) < 0) 
        {
            perror("Connect");
         }
           else{
            printf(" Now client send the data  on socket %i \n",sockfd);
         //nc_args->filename;
         //nc_args->offset = atoi(optarg);
         //nc_args->n_bytes = atoi(optarg);
         send_data(sockfd, nc_args.offset, nc_args.n_bytes, nc_args.filename);
          }
   
  }

              
  return 0;
}
