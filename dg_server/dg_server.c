#include <stdio.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Create the SSL socket and intialize the socket address structure
int open_serv_sock(int port)
{
    int sock_fd;
    struct sockaddr_in addr;
    sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("can't bind port");
        return -1;
    }
    if (listen(sock_fd, 10) != 0)
    {
        perror("Can't configure listening port");
        return -1;
    }
    return sock_fd;
}
SSL_CTX *InitServerCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();                   // load & register all cryptos, etc.
    SSL_load_error_strings();                       // load all error messages
    method = (SSL_METHOD *)TLSv1_2_server_method(); // create new server-method instance
    ctx = SSL_CTX_new(method);                      // create new context from method
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return (SSL_CTX *)-1;
    }
    return ctx;
}
int LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        return -1;
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        return -1;
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
        return -1;
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
        return -1;

    if (!SSL_CTX_check_private_key(ctx))
    { // verify private key
        fprintf(stderr, "Private key does not match the public certificate\n");
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}
int ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); // Get certificates (if available)
    if (cert != NULL)
    {                                                // Verify a X.509 certification.
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();  // a newly initialised X509_STORE_CTX structure
        X509_STORE *store = X509_STORE_new();        // a newly initialised X509_STORE structure
        X509_STORE_add_cert(store, cert);            // Copy a certificate to X509_STORE structure
        X509_STORE_CTX_init(ctx, store, cert, NULL); // Set up a X509_STORE_CTX for verification.

        if (X509_verify_cert(ctx) == 1) // Verify a X.509 certification.
            printf("cert ok\n");
        else
            printf("cert fail\n");

        X509_free(cert);
        return 0;
    }
    else
        printf("No or Invalid certificates.\n");
    return 1;
}
void Servlet(SSL *ssl) // Serve the connection -- threadable
{
    char buff[1024] = {0};
    int buffsize = sizeof(buff) / sizeof(char);
    int recvsize;
    if (SSL_accept(ssl) == -1) // do SSL-protocol accept
        ERR_print_errors_fp(stderr);
    else
    {
        if (ShowCerts(ssl) > 0) // cert fail
            printf("Certification verifying filed.\n");
        else // get certificates
        {
            recvsize = SSL_read(ssl, buff, buffsize); // get request
            buff[recvsize] = '\0';
            const char valid_msg_start[] = "/*TEST";
            const char valid_msg_end[] = "*/";

            printf("Client msg: \"%s\"\n", buff);
            if (recvsize <= 0)
                ERR_print_errors_fp(stderr);
            else if (strncmp(buff, valid_msg_start, strlen(valid_msg_start)) || strncmp(&buff[recvsize - strlen(valid_msg_end)], valid_msg_end, strlen(valid_msg_end)))
            {
                printf("Invalid msg\n");
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); // send error reply
            }
            else
            {
                recvsize = SSL_read(ssl, buff, buffsize - 1);
                buff[recvsize] = '\0';
                while (strncmp(&buff[strlen(buff) - 6], "_c.log", 6) == 0)
                {
                    FILE *fp = fopen(buff, "wb");
                    printf("%s\n", buff);
                    uint64_t filesize;
                    SSL_read(ssl, &filesize, sizeof(uint64_t));
                    while (filesize > 0)
                    {
                        recvsize = SSL_read(ssl, buff, buffsize - 1);
                        filesize -= recvsize;
                        fwrite(buff, sizeof(char), recvsize, fp);
                    }
                    fclose(fp);

                    recvsize = SSL_read(ssl, buff, buffsize - 1);
                    buff[recvsize] = '\0';
                }
            }
        }
    }
    int sock_fd = SSL_get_fd(ssl); // get socket fd
    SSL_free(ssl);                 // release SSL state
    close(sock_fd);                // close connection
}
int main(void)
{
    // system("echo -e '\n\n\n\n\n\n\n' | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem");
    SSL_CTX *ctx;
    int server_sock;
    int portnum = 7001;

    SSL_library_init();    //  Initialize the SSL library
    ctx = InitServerCTX(); // initialize SSL
    if (LoadCertificates(ctx, "cert2.pem", "cert2.pem") != 0)
        exit(1);                           // 내 인증서 확인 실패
    server_sock = open_serv_sock(portnum); // create server socket
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server_sock, (struct sockaddr *)&addr, &len); // accept connection as usual
        if (client != -1)
        {
            struct linger solinger = {1, 10}; // set time_wait true, time_wait = 10sec
            if (setsockopt(client, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger)) == -1)
                perror("setsockopt error");

            printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            ssl = SSL_new(ctx);      // get new SSL state with context
            SSL_set_fd(ssl, client); // set connection socket to SSL state
            Servlet(ssl);            // service connection
        }
    }
    close(server_sock); // close server socket
    SSL_CTX_free(ctx);  // release context
}