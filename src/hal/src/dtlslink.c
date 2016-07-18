/*std lib includes*/
#include <string.h>
#include <stdint.h>

/*FreeRtos includes*/
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "queue.h"

/*WolfSSL includes*/
#include <WolfSSL/ssl.h>

/*CRTP includes*/
#include "crtp.h"

/*radiolink maybe*/
#include "radiolink.h"


/* WolfSSL porting guide
 * 2.1 i dont know the size of Long and Long Long. This is a 32bit system, there is a change to make lets just find it.
 * 2.2 the system is little endian(no change needed)
 * 2.3 NO_WRITEV as <sys/uio.h> not available
 * 2.4 READ MORE CAREFULLY  #define WOLFSSL_USER_IO , defining LARGE_STATIC_BUFFERS instead of making smaller buffers?
 * 2.5 NO FILE SYSTEM so read more carefully
 * 2.6 I DONT KNOW ABOUT THE THREADING
 * 2.7 Hardware RNG available
 * 2.8 USE_FAST_MATH as memory is low
 * 2.9 DEFINE USER_TIME as i dont think time.h is available, time.h might be available
 * 2.10 STD C lib is available
 * 2.11 Debug can be implemented later. it seems i just need to enable it and handle it.
 * 2.12 using the standard public key would work fine
 * 2.13 i dont see a need to make custom encrypt/decrypt functions
 * 2.14 we do need to disable a bunch of stuff as we need to reduce the size of the library #define DTLS
 */
/* The Point of this link.
 * Create a DTLS link between this server and a client on a PC.
 * Functions needed to create DTLS functionality:
 *
 * Create DTLS link
 * -wait to recieve DTLS link initialisation from client.
 * is the DTLS link created
 * -simple check to see if there is a DTLS session running
 * send data over the DTLS link
 * -recieve clear text to encrypt from crtp module?
 * -send the encrypted text to crtp module?
 * recieve data over the DTLS link
 * -recieve encrypted text to decrypt from crtp module?
 * -send the decrypted text to crtp module?
 * close the DTLS link
 * -wait to recieve DTLS deinitialisation from client
 */


#define MSGLEN 30 //i do belive a message may be at most 28 bytes. so that is how many chars we can use. a bit limiting
/*
 * i need to make a structure to handle these buffers.
 */

/*
static struct char[MSGLEN] cipherBuffers//Maybe? prob no
{
	.clearSend		 = addClearSend,
	.clearRecieve	 = addClearRecieve,
	.cipherSend 	 = addCipherSend,
	.cipherRecieve 	 = addCipherRecieve,
};
*/

/*
 * needed to allow custom IO using CRTP instead of TCP/IP or UDB in this case as DTLS is used.
 */

extern char clearSend[];	//clear text going out buffer
extern char cipherSend[];	//encrypted text going out buffer
extern char clearRecieve[];	//clear text going in buffer
extern char cipherRecieve[];	//encrypted text going in buffer
extern char serverCertBuffer[];
//*ssl = session, *buf = encrypted message to send, sz = size of buffer, *ctx = network socket filedescriptor?
typedef int (*CallbackIORecv)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
//*ssl = session, *buf = encrypted message to decrypt, sz = size of buffer, *ctx = network socket filedescriptor?
typedef int (*CallbackIOSend)(WOLFSSL *ssl, char *buf, int sz, void *ctx);


/*
 * these functions need to be used so that the correct functions are used to send and recieve packets.
 * wolfSSL_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv CBIORecv)
 * wolfSSL_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend CBIOSend)
 * wolfSSL_SetIOReadCtx(WOLFSSL* ssl, void *rctx)
 * wolfSSL_SetIOWriteCtx(WOLFSSL* ssl, void *wctx)
 */

/*
 * is a similar structure required for dtls link handling?
static struct crtpLinkOperations radiolinkOp =
{
  .setEnable         = radiolinkSetEnable,
  .sendPacket        = radiolinkSendCRTPPacket,
  .receivePacket     = radiolinkReceiveCRTPPacket,
};
 */
//for colour coding and maybe a alternative?
static struct crtpLinkOperations dtlslinkOp =
{
  .setEnable         = dtlsSetEnable,
  .sendPacket        = dtlsSendPacket,
  .receivePacket     = dtlsReceivePacket,
};

void dtlstunnelinit(void)//probably wont be argumentless for long
{
	WOLFSSL_CTX* ctx; //i don't know what this is or where to use it.
	WOLFSSL* ssl; //object pointer to wolfSSL structure.

	char clearSend[MSGLEN];	//clear text going out buffer
	char cipherSend[MSGLEN];	//encrypted text going out buffer
	char clearRecieve[MSGLEN];	//clear text going in buffer
	char cipherRecieve[MSGLEN];	//encrypted text going in buffer



	wolfSSL_Init();
	wolfSSL_Debugging_ON(); // here maybe? or do i need to enable this before wolfSSL_Init()? just as good to enable dontya think?

	//set wolfssl to DTLS 1.2.
	if ( (ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL)
	{
	    exit(EXIT_FAILURE);
	}


	//following code uses a filesystem, which we dont have. somehow i need access to these things with no filesystem. something about more buffers.

	/* Load CA certificates */
	//function to load CA certificates
	WolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in, long sz, int format);


	if (wolfSSL_CTX_load_verify_locations(ctx,"../certs/ca-cert.pem",0) != SSL_SUCCESS)
	{
	    fprintf(stderr, "Error loading ../certs/ca-cert.pem, please check the file.\n");
	    exit(EXIT_FAILURE);
	}
	/* Load server certificates */
	//function to load certificate buffer
	WolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx, const unsigned char* in, long sz, int format);


	if (WolfSSL_CTX_use_certificate_buffer() != SSL_SUCCESS)
	{
		fprintf(stderr, "Error loading cert buffer please check the buffer.\n");
	    exit(EXIT_FAILURE);
	}
	/* Load server Keys */
	//funciton to use server private key
	WolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* in, long sz, int format);


	if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,"../certs/server-key.pem",SSL_FILETYPE_PEM) != SSL_SUCCESS)
	{
	    fprintf(stderr, "Error loading ../certs/server-key.pem, please check the file.\n");
	    exit(EXIT_FAILURE);
	}

	/*--------NONE OF THE FOLLOWING CODE IS NEEDED IN THE INIT FUNCTION--------*/


	//somewhere i will need to create a ssl object like this prolly when we get a new connection
	/* Create the WOLFSSL Object */
	if (( ssl = wolfSSL_new(ctx) ) == NULL)
	{
	    printf("wolfSSL_new error.\n");
	    cleanup = 1;
	}
	//listenfd will need to be changed to the cipherrecieved buffer somehow.
	wolfSSL_set_fd(ssl, listenfd);

	//this is if the listen function recieves a failiure, the server shuts down and cleans up. needs to be altered for my purpose
	if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
	    int err = wolfSSL_get_error(ssl, 0);
	    char buffer[80];
	    printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffe    r));
	    buffer[sizeof(buffer)-1]= 0;
	    printf("SSL_accept failed.\n");
	    cleanup = 1;
	}

	if (recvlen < 0) {
	    int readErr = wolfSSL_get_error(ssl, 0);
	    if(readErr != SSL_ERROR_WANT_READ) {
	    printf("SSL_read failed.\n");
	    cleanup = 1;
	    }
	}

	if (wolfSSL_write(ssl, ack, sizeof(ack)) < 0) {
	    printf("wolfSSL_write fail.\n");
	    cleanup = 1;
	}
	else
	    printf("lost the connection to client\n");
	    printf("reply sent \"%s\"\n", ack);


}

void dtlstunnelDeinit(void)
{
	//void wolfSSL_Cleanup(void); deinit wolfssl
}

static int dtlstunnelSetEnable(bool enable)
{
	return 0;
}

static int dtlstunnelReceiveCRTPPacket(CRTPPacket *p)
{
	/*
	 * receive packet it is p. remove only the data or message encrypt the living shit out of it and hanadle that shieeet?
	 */
	return 0;
}

static int dtlstunnelSendCRTPPacket(CRTPPacket *p)
{
	//
	return 0;
}
