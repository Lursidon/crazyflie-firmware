#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "config.h"
#include "usblink.h"
#include "crtp.h"
#include "configblock.h"
#include "ledseq.h"
#include "pm.h"
#include "queue.h"
#include "syslink.h"
#include "crtp.h"
#include "radiolink.h"
#include "console.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "queuemonitor.h"
#include "semphr.h"

#include "aeslink.h"
#include "ssl.h"
#include "aes.h"
//#include "rng_interface.h"

#define AD_START					0
#define IV_START					2
#define TAG_START					6
#define DATA_START					10
#define HEADER_POSITION				0
#define PID_POSITION				1

#define ADDITIONAL_BYTES  			10
#define AUTH_DATA_SIZE				2
#define AUTH_TAG_SIZE 				4
#define INIT_VECTOR_SIZE			4
#define MAX_DATA_IN_FIRST_PACKET 	20

#define PID_BYTE					1
#define HEADER_BYTE					1
#define FIRST_OF_MULTI_PACKET_MASK	0x80u
#define MULTI_PACKET_BIT_MASK		0x80u
#define PID_NBR_MASK				0x60
#define PACKET_DATA_LENGTH_MASK		0x1F
#define HEADER_PORT_MASK			0xF0u
#define HEADER_CHANNEL_MASK			0x03

#define MAX_FIRST_DATA_LENGTH		0x15

#define CIPHERED_PORT				0x0Bu
#define CIPHERED_CHANNEL			0x03
#define CHIPHERED_HEADER			0xB3u

//#define MULTIBYTE_FIRST_PACKET 0x01
//#define MULTIBYTE_NOT_FIRST_PACKET 0x00

static xQueueHandle crtpPacketDelivery;

static int aeslinkSendCRTPPacket(CRTPPacket *p);
static int aeslinkSetEnable(bool enable);
static int aeslinkReceiveCRTPPacket(CRTPPacket *p);
static void aeslinkTask(void *param);

static bool isInit = false;

static int nopFunc(void);
static struct crtpLinkOperations nopLink = {
  .setEnable         = (void*) nopFunc,
  .sendPacket        = (void*) nopFunc,
  .receivePacket     = (void*) nopFunc,
};

static struct crtpLinkOperations *link = &nopLink;

struct crtpLinkOperations aeslinkOp =
{
  .setEnable         = aeslinkSetEnable,
  .sendPacket        = aeslinkSendCRTPPacket,
  .receivePacket     = aeslinkReceiveCRTPPacket,
};

static CRTPPacket p;
//static CRTPPacket nopPacket;

static const byte key[] = {0x57, 0x01, 0x2A, 0x12, 0xA7, 0x7A, 0x12, 0xBA, 0x57, 0x01, 0x2A, 0x12, 0xA7, 0x7A, 0x12, 0xBA};
static byte sendInitVector[] = {0x00, 0x00, 0x00, 0x00};
static Aes enc;
static Aes dec;
static byte sendPlainPackageData[CRTP_MAX_DATA_SIZE];
static byte sendCipherPackageData[CRTP_MAX_DATA_SIZE];
static byte sendAuthData[AUTH_DATA_SIZE];
static byte sendAuthTag[AUTH_TAG_SIZE];
static byte recPlainPackageData[CRTP_MAX_DATA_SIZE];
static byte recInitVector[INIT_VECTOR_SIZE];
static byte recCipherPackageData[CRTP_MAX_DATA_SIZE];
static byte recAuthData[AUTH_DATA_SIZE];
static byte recAuthTag[AUTH_TAG_SIZE];
//static byte packetDataBuffer[CRTP_MAX_DATA_SIZE];
static CRTPPacket sp;
static CRTPPacket rp;
//static CRTPPacket mp;
//static bool crtpPacketReceived = false;
static bool messageComplete = false;
static bool splitMessage = false;
static byte recPid = 100;

static void aeslinkTask(void *param){
	while (true)
	  {
	    if (link != &nopLink)
	    {
	      if (!link->receivePacket(&p))
	      {
	       if(p.size > 2)
	       {
			   if((p.data[PID_POSITION] & PID_NBR_MASK) != recPid)
			   {

				   //rp.channel = (p.data[HEADER_POSITION] & HEADER_CHANNEL_MASK);
				   //rp.port = (p.data[HEADER_POSITION] & HEADER_PORT_MASK) >> 4;
				   //rp.size = p.size;

				   byte datalength = 0;

				   if((p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK) <= MAX_DATA_IN_FIRST_PACKET)
				   {
					   datalength = p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK;
					   messageComplete = true;
				   } else
				   {
					   datalength = MAX_DATA_IN_FIRST_PACKET;
				   }

					recAuthData[HEADER_POSITION] = p.data[HEADER_POSITION] & (HEADER_CHANNEL_MASK | HEADER_PORT_MASK);
					recAuthData[PID_POSITION] = p.data[PID_POSITION];

					memcpy(&recInitVector, &p.data[IV_START], INIT_VECTOR_SIZE);
					memcpy(&recAuthTag, &p.data[TAG_START], AUTH_TAG_SIZE);
					memcpy(&recCipherPackageData, &p.data[DATA_START], datalength);

					//memcpy(&rp.data[AD_START], &recAuthData, AUTH_DATA_SIZE);
					//memcpy(&rp.data[IV_START], &recInitVector, INIT_VECTOR_SIZE);
					//memcpy(&rp.data[TAG_START], &recAuthTag, AUTH_TAG_SIZE);
					//memcpy(&rp.data[DATA_START], &recCipherPackageData, datalength);

					//link->sendPacket(&rp);
			   }


			   if((p.data[PID_POSITION] & PID_NBR_MASK) == recPid)
			   {
				   byte datalength = 0;
				   datalength = (p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK) - MAX_DATA_IN_FIRST_PACKET;
				   if(datalength <= 10){
					   memcpy(&recCipherPackageData[MAX_DATA_IN_FIRST_PACKET], &p.data[2], datalength);
					   messageComplete = true;
				   }

			   }
			   if(messageComplete)
			   {
				   /*
				   byte datalength = 0;

				   if((p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK) <= MAX_DATA_IN_FIRST_PACKET)
				   {
					   datalength = p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK;
				   } else
				   {
					   datalength = MAX_DATA_IN_FIRST_PACKET;
				   }*/

				   //rp.channel = (p.data[HEADER_POSITION] & HEADER_CHANNEL_MASK);
				   //rp.port = (p.data[HEADER_POSITION] & HEADER_PORT_MASK) >> 4;
				   //rp.size = AUTH_DATA_SIZE + INIT_VECTOR_SIZE + AUTH_TAG_SIZE;

				   //memcpy(&rp.data[AD_START], &recAuthData, AUTH_DATA_SIZE);
				   //memcpy(&rp.data[IV_START], &recInitVector, INIT_VECTOR_SIZE);
				   //memcpy(&rp.data[TAG_START], &recAuthTag, AUTH_TAG_SIZE);
				   //memcpy(&rp.data[DATA_START], &recCipherPackageData, datalength);

				   //link->sendPacket(&rp);



				   int failedDecrypt = 0;
				   failedDecrypt = wc_AesGcmDecrypt(&dec,
						   recPlainPackageData,
						   recCipherPackageData,
						   p.data[PID_BYTE] & PACKET_DATA_LENGTH_MASK,
						   recInitVector,
						   INIT_VECTOR_SIZE,
						   recAuthTag,
						   AUTH_TAG_SIZE,
						   recAuthData,
						   AUTH_DATA_SIZE);

				   if(failedDecrypt)
				   {
					   byte datalength = 0;
					   if((p.data[PID_BYTE] & PACKET_DATA_LENGTH_MASK) > MAX_DATA_IN_FIRST_PACKET){
						   datalength = MAX_DATA_IN_FIRST_PACKET;
					   } else {
						   datalength = p.data[PID_BYTE] & PACKET_DATA_LENGTH_MASK;
					   }

					   rp.port = (p.data[HEADER_POSITION] & HEADER_PORT_MASK) >> 4;
					   rp.channel = p.data[HEADER_POSITION] & HEADER_CHANNEL_MASK;
					   rp.size = datalength + ADDITIONAL_BYTES;

					   memcpy(&rp.data[AD_START], &recAuthData, AUTH_DATA_SIZE);
					   memcpy(&rp.data[IV_START], &recInitVector, INIT_VECTOR_SIZE);
					   memcpy(&rp.data[TAG_START], &recAuthTag, AUTH_TAG_SIZE);
					   memcpy(&rp.data[DATA_START], &recCipherPackageData, datalength);

					   link->sendPacket(&rp);
				   } else
				   {
					   rp.port = (p.data[HEADER_POSITION] & HEADER_PORT_MASK) >> 4;
					   rp.channel = p.data[HEADER_POSITION] & HEADER_CHANNEL_MASK;
					   rp.size = p.data[PID_BYTE] & PACKET_DATA_LENGTH_MASK;

					   memcpy(&rp.data, &recPlainPackageData, p.data[PID_BYTE] & PACKET_DATA_LENGTH_MASK);
					   //link->sendPacket(&rp);
					   xQueueSend(crtpPacketDelivery, &rp, 0);
				   }
				   messageComplete = false;
				   recPid = 100;
			   }

	    	 //link->sendPacket(&p);
	    	 //rp.size = p.size;
	    	 //rp.channel = p.channel;
	    	 //rp.port = p.port;
		     //memcpy(&rp.data, &p.data, AUTH_DATA_SIZE);
			   /*
		    	 rp.channel = (p.data[HEADER_POSITION] & HEADER_CHANNEL_MASK);
		    	 rp.port = (p.data[HEADER_POSITION] & HEADER_PORT_MASK) >> 4;
		    	 rp.size = p.size-1;
		    	 memcpy(&rp.data, &p.data[1], rp.size);

		     link->sendPacket(&rp);*/

	    	  /*
	    	  //byte datalength = 0;
			  if(((p.data[PID_POSITION] & PID_NBR_MASK) != recPid) && ((p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK) > 0))
			  {
				  if((p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK)>MAX_DATA_IN_FIRST_PACKET){
					  datalength = MAX_DATA_IN_FIRST_PACKET;
				  } else {
					  datalength = p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK;
					  messageComplete = true;
				  }

				  recPid = p.data[PID_POSITION] & PID_NBR_MASK;

				  bzero(&recAuthData, AUTH_DATA_SIZE);
				  bzero(&recInitVector, INIT_VECTOR_SIZE);
				  bzero(&recAuthTag, AUTH_TAG_SIZE);
				  bzero(&recCipherPackageData, CRTP_MAX_DATA_SIZE);

				  recAuthData[0] = p.data[0] & (HEADER_PORT_MASK | HEADER_CHANNEL_MASK);
				  recAuthData[1] = p.data[PID_POSITION];
				  //memcpy(&recAuthData, &p.data[AD_START], AUTH_DATA_SIZE);
				  memcpy(&recInitVector, &p.data[IV_START], INIT_VECTOR_SIZE);
				  memcpy(&recAuthTag, &p.data[TAG_START], AUTH_TAG_SIZE);
				  memcpy(&recCipherPackageData, &p.data[DATA_START], datalength);*/
				  /*
				  memcpy(&mp.data[AD_START], &p.data[AD_START], AUTH_DATA_SIZE);
				  memcpy(&mp.data[IV_START], &p.data[IV_START], INIT_VECTOR_SIZE);
				  memcpy(&mp.data[TAG_START], &p.data[TAG_START], AUTH_TAG_SIZE);
				  memcpy(&mp.data[DATA_START], &p.data[DATA_START], datalength);

				  rp.port = 0x01;
				  rp.channel = 0x00;

				  //link->sendPacket(&p);*/

	    	   /*
			  } else if(((p.data[PID_BYTE] & PID_NBR_MASK) == recPid) && (p.data[PID_POSITION] & MULTI_PACKET_BIT_MASK))
			  { // only be done if this is the second package


				  memcpy(
						  &recCipherPackageData[MAX_DATA_IN_FIRST_PACKET],
						  &p.data[2],
						  (p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK)-MAX_DATA_IN_FIRST_PACKET);

				  messageComplete = true;
				  */
	    	   /*
			  }
			  if(messageComplete)
			  {

				  int decrypted;

				  decrypted = wc_AesGcmDecrypt(&dec,
						  recPlainPackageData,
						  recCipherPackageData,
						  p.data[PID_BYTE] & PACKET_DATA_LENGTH_MASK,
						  recInitVector,
						  INIT_VECTOR_SIZE,
						  recAuthTag,
						  AUTH_TAG_SIZE,
						  recAuthData,
						  AUTH_DATA_SIZE);
				  rp.port = (recAuthData[HEADER_POSITION] & HEADER_PORT_MASK) >> 4;
				  rp.channel = (recAuthData[HEADER_POSITION] & HEADER_CHANNEL_MASK);

				  if(decrypted){
					  memcpy(&rp.data[IV_START], &recInitVector, INIT_VECTOR_SIZE);
					  memcpy(&rp.data[TAG_START], &recAuthTag, AUTH_TAG_SIZE);
					  memcpy(&rp.data[DATA_START], &recCipherPackageData, MAX_DATA_IN_FIRST_PACKET);
					  link->sendPacket(&rp);
				  } else {
					  memcpy(&rp.data, &recPlainPackageData, (p.data[PID_POSITION] & PACKET_DATA_LENGTH_MASK));
					  xQueueSend(crtpPacketDelivery, &rp, 0);
				  }

				  recPid = 100;
				  messageComplete = false;
				  */
			   //}
		  }
	    }
	  }
	    else
	    {
	      vTaskDelay(M2T(10));
	    }
	  }
}

static int aeslinkReceiveCRTPPacket(CRTPPacket *p)
{

	if (xQueueReceive(crtpPacketDelivery, p, M2T(100)) == pdTRUE)
	{

		return 0;
	}

	return -1;
}

static int aeslinkSendCRTPPacket(CRTPPacket *p)
{
	static byte sendPid = 0;
	byte dataLength = 0;



	if((p->channel | p->port) == 0xF3){
		link->sendPacket(p);
		return 1;
	}

	if(sendPid >3){
		sendPid = 0;
	}

	if((p->size)>MAX_DATA_IN_FIRST_PACKET){
		dataLength = MAX_DATA_IN_FIRST_PACKET;
		splitMessage = true;
	} else {
		dataLength = p->size;
	}

	//byte dataLength = ((p->size)>MAX_DATA_IN_FIRST_PACKET)?MAX_DATA_IN_FIRST_PACKET:p->size;

	sp.size = dataLength + ADDITIONAL_BYTES;
	sp.port = CIPHERED_PORT;
	sp.channel = CIPHERED_CHANNEL;

	//removing the reserved requirement | (p->reserved<<2)
	sendAuthData[HEADER_POSITION] = ((p->port<<4) | (p->channel));
	if(splitMessage){
		sendAuthData[PID_POSITION] = FIRST_OF_MULTI_PACKET_MASK | ((sendPid<<5)&PID_NBR_MASK) | (p->size);
	} else {
		sendAuthData[PID_POSITION] = ((sendPid<<5)&PID_NBR_MASK) | (p->size);
	}

	memcpy(&sendPlainPackageData, p->data, p->size);

	int failedEncrypt;

	failedEncrypt = wc_AesGcmEncrypt(&enc,
				sendCipherPackageData,
				sendPlainPackageData,
				p->size,
				sendInitVector,
				INIT_VECTOR_SIZE,
				sendAuthTag,
				AUTH_TAG_SIZE,
				sendAuthData,
				AUTH_DATA_SIZE);
	if(failedEncrypt){

		sp.size = CRTP_MAX_DATA_SIZE;
		bzero(sp.data, CRTP_MAX_DATA_SIZE);
		memcpy(&sp.data[AD_START], &sendAuthData, AUTH_DATA_SIZE);
		memcpy(&sp.data[IV_START], &sendInitVector, INIT_VECTOR_SIZE);
		memcpy(&sp.data[TAG_START], &sendAuthTag, AUTH_TAG_SIZE);
		strcpy((char*)&sp.data[DATA_START], "fail enc");
		sp.port = CIPHERED_PORT;
		sp.channel = CIPHERED_CHANNEL;

		link->sendPacket(&sp);

		sp.size = CRTP_MAX_DATA_SIZE;
		  bzero(&sp.data, CRTP_MAX_DATA_SIZE);
		  memcpy(&sp.data, &sendPlainPackageData, p->size);
		  sp.port = CIPHERED_PORT;
		  sp.channel = CIPHERED_CHANNEL;

		  link->sendPacket(&sp);


		return 0;
	}

	memcpy(&sp.data[AD_START], &sendAuthData, AUTH_DATA_SIZE);
	memcpy(&sp.data[IV_START], &sendInitVector, INIT_VECTOR_SIZE);
	memcpy(&sp.data[TAG_START], &sendAuthTag, AUTH_TAG_SIZE);
	memcpy(&sp.data[DATA_START], &sendCipherPackageData, dataLength);

	link->sendPacket(&sp);


	if(splitMessage){
		dataLength = (p->size)-MAX_DATA_IN_FIRST_PACKET;
		sp.size = dataLength + PID_BYTE + HEADER_BYTE;

		memcpy(&sp.data[AD_START], &sendAuthData, AUTH_DATA_SIZE);
		memcpy(&sp.data[IV_START], &sendCipherPackageData[MAX_DATA_IN_FIRST_PACKET], dataLength);
		link->sendPacket(&sp);
	}

	if(sendInitVector[0] == 0xFF){
		sendInitVector[0] = 0;
		sendInitVector[1]++;
	}else {
		sendInitVector[0]++;
	}
	if(sendInitVector[1] == 0xFF){
		sendInitVector[1] = 0;
		sendInitVector[2]++;
	}
	if(sendInitVector[2] == 0xFF){
		sendInitVector[2] = 0;
		sendInitVector[3]++;
	}
	if(sendInitVector[3] == 0xFF){
		sendInitVector[3] = 0;
	}
	/*
	mp.size = CRTP_MAX_DATA_SIZE;
	bzero(mp.data, CRTP_MAX_DATA_SIZE);
	memcpy(&mp.data[AD_START], &sendAuthData, AUTH_DATA_SIZE);
	memcpy(&mp.data[IV_START], &sendInitVector, INIT_VECTOR_SIZE);
	memcpy(&mp.data[TAG_START], &sendAuthTag, AUTH_TAG_SIZE);
	strcpy((char*)&mp.data[DATA_START], "post send");
	mp.port = CIPHERED_PORT;
	mp.channel = CIPHERED_CHANNEL;

	link->sendPacket(&mp);
	*/

	//return link->sendPacket(p);

	sendPid++;
	splitMessage = false;
	return 1;
}

static int aeslinkSetEnable(bool enable)
{
	return 0;
}

//public functions
void aeslinkInit()
{
	//ledseqRun(LINK_LED, seq_bootloader);
	if(isInit)
		return;

	crtpPacketDelivery = xQueueCreate(5, sizeof(CRTPPacket));
	DEBUG_QUEUE_MONITOR_REGISTER(crtpPacketDelivery);

	xTaskCreate(aeslinkTask, AESLINK_TASK_NAME ,
	            AESLINK_TASK_STACKSIZE, NULL, AESLINK_TASK_PRI, NULL);

	//rngInit();
	wc_AesGcmSetKey(&dec, key, sizeof(key));
	wc_AesGcmSetKey(&enc, key, sizeof(key));

	isInit = true;
}

bool aeslinkTest()
{
	return isInit;
}
/*
crtpLinkOperations * aeslinkGetLink()
{
	return &aeslinkOp;
}
*/
void aesEnableTunnel(){
	//ledseqRun(LINK_LED, seq_bootloader);
	//crtpGetLink(link);
	link = radiolinkGetLink();
	//crtpSetLink(&aeslinkOp);
	aeslinkInit();
}

static int nopFunc(){
	return 0;
}







//aeslink0p->receivePacket(&packet)
//recieve packet
//unsplit | encrypt
//decrypt | split
//push to buffer send | receive
/*
 * simply push packets through do nothing but count.
 * */
