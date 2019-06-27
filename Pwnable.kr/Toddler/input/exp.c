///A script to bypass checks, remember to create softlink of flag under /tmp

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> 
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main()
{
    /* stage 1 */
    char *argv[101] = {0};
    for(int i = 1; i<100; ++i)
        argv[i] = "a";
    argv[0] = "/home/input2/input";
    argv['A'] = "\x00";
    argv['B'] = "\x20\x0a\x0d";
    argv['C'] = "9999"; //server port
    argv[100] = NULL;

    /* stage 3 */
    char *envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};

    /* stage 4 */  // ! : file open before execve , or the check will fail 
    FILE *fp = fopen("\x0a", "wb"); // wb,w are similar in linux but differ in win
    if(!fp)                         //see \x0d\x0a in win and \x0a in linux
    {
        perror("Cannot open file.");
        exit(1);
    }
    printf("open file success.\n");
    fwrite("\x00\x00\x00\x00", 4, 1, fp);
    fclose(fp);
    
    /* stage 2 */
    int pipe_stdin[2] = {-1, -1};
    int pipe_stderr[2] = {-1, -1};
    pid_t pid_child;
    if ( pipe(pipe_stdin) < 0 || pipe(pipe_stderr) < 0 )
    {
        perror("Cannot create the pipe.");
        exit(1);
    }

    #define STDIN_READ   pipe_stdin[0]
    #define STDIN_WRITE  pipe_stdin[1]
    #define STDERR_READ  pipe_stderr[0]
    #define STDERR_WRITE pipe_stderr[1]
    if ( ( pid_child = fork() ) < 0 )   // do not forget the ()!
    {
        perror("Cannot create fork child.");
        exit(1);
    }

    if( pid_child == 0 )
    {
        /*child proc*/
        sleep(1); //wait to pipe link 0,2
        close(STDIN_READ);
        close(STDERR_READ);
        write(STDIN_WRITE, "\x00\x0a\x00\xff", 4);
        write(STDERR_WRITE, "\x00\x0a\x02\xff", 4);
    }
    else
    {
        /*parent proc*/
        close(STDIN_WRITE);
        close(STDERR_WRITE);
        dup2(STDIN_READ, 0);  //dup to 0-stdin
        dup2(STDERR_READ, 2); //dup to 2-stderr
        printf("start execve input.\n");
        execve("/home/input2/input", argv, envp);
            perror("Fail to execute the program");
            exit(1);
    }
    printf("pipe link.\n");

    /* stage 5 */
    sleep(2); // wait the server start
    int sockfd;
    char buf[10] = {0}; // buf to be sent
    int len;            // len of avail buf
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons(9999);  // port in argv['C'] 
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //local
    if( (sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )  
    {  
        perror("socket error.");  
        exit(1);  
    }  
    if ( connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0 )
    {
        perror("connect error.");
        exit(1);
        }
    printf("socket connect.\n");
    strcpy(buf, "\xde\xad\xbe\xef");
    len = strlen(buf);
    send(sockfd, buf, len, 0);
    close(sockfd);  

    return 0;
}
