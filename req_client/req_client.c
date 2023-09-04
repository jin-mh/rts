#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/time.h> //gettimeofday()
#include <unistd.h>

int open_client_sock(const char *hostname, int port)
{
    int sock_fd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        return -1;
    }
    sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // 호스트의 ip 목록출력
    for (int i = 0; host->h_addr_list[i]; i++)
        puts(inet_ntoa(*(struct in_addr *)host->h_addr_list[i]));

    addr.sin_addr.s_addr = *(host->h_addr_list[0]);
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sock_fd);
        perror(hostname);
        return -1;
    }
    return sock_fd;
}
SSL_CTX *InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();                   // Load cryptos, et.al.
    SSL_load_error_strings();                       // Bring in and register error messages
    method = (SSL_METHOD *)TLSv1_2_client_method(); // Create new client-method instance
    ctx = SSL_CTX_new(method);                      // Create new context
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{ // load cert
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        return -1;
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        return -1;
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
        return -1; // set the local certificate from CertFile
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
        return -1; // set the private key from KeyFile (may be the same as CertFile)

    if (!SSL_CTX_check_private_key(ctx))
    { // verify private key
        fprintf(stderr, "Private key does not match the public certificate\n");
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    return 0;
}

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); // get the server's certificate
    if (cert != NULL)
    { // 서버 인증서 내용 확인
        // printf("Server certificates:\n");
        // line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        // printf("Subject: %s\n", line);
        // free(line); // free the malloc'ed string
        // line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        // printf("Issuer: %s\n", line);
        // free(line);      // free the malloc'ed string
        X509_free(cert); // free the malloc'ed certificate copy
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{
    // system("echo -e '\n\n\n\n\n\n\n' | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem");
    // system("cp ~/3thr/openssl/server/mycert.pem ~/3thr/openssl/client/");
    SSL_CTX *ctx;
    int server_sock;
    SSL *ssl;
    char buff[1024];
    int recvlen = -1;
    char *hostname = "127.0.0.1";
    int portnum = 5080;

    if (count < 2)
        exit(1);
    SSL_library_init();

    ctx = InitCTX();
    if (LoadCertificates(ctx, "cert1.pem", "cert1.pem") != 0)
        exit(1); // 내 인증서 확인 실패
    server_sock = open_client_sock(hostname, portnum);

    ssl = SSL_new(ctx);           // create new SSL connection state
    SSL_set_fd(ssl, server_sock); // attach the socket fd
    if (SSL_connect(ssl) == -1)   // perform the connection
        ERR_print_errors_fp(stderr);
    else
    {
        char RequestMessage[21]; // 전송 메세지 문자열
        RequestMessage[20] = '\0';
        // struct timeval tv;
        // gettimeofday(&tv, NULL);
        // sprintf(RequestMessage, "/*TEST_%010llu%10llu*/", 0, tv.tv_sec); // 현재시간 -10 이후의 파일 요청 메세지 생성
        sprintf(RequestMessage, "/*TEST_%s*/", strings[1]); // timestamp 메세지 생성
        puts(RequestMessage);

        printf("\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
        SSL_write(ssl, RequestMessage, strlen(RequestMessage));

        recvlen = SSL_read(ssl, buff, sizeof(buff) - 1); // 확인메세지 수신
        buff[recvlen] = 0;
        printf("Received: \"%s\"\n", buff); // 수신 메세지 출력
        SSL_free(ssl);                      // release connection state
    }
    close(server_sock); // close socket
    SSL_CTX_free(ctx);  // release context
    return 0;
}