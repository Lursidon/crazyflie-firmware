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

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "queuemonitor.h"
#include "semphr.h"

#include "aeslink.h"
#include "ssl.h"
#include "aes.h"
//#include "rng_interface.h"

#define ADDITIONAL_BYTES  			9
#define AUTH_DATA_SIZE				2
#define AUTH_TAG_SIZE 				4
#define INIT_VECTOR_SIZE			4
#define MAX_DATA_IN_FIRST_PACKET 	21

#define PID_BYTE					1
#define FIRST_OF_MULTI_PACKET_MASK	0x80u
#define PID_NBR_MASK				0x60
#define PACKET_DATA_LENGTH_MASK		0x1F
#define MAX_FIRST_DATA_LENGTH		0x15

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

static struct crtpLinkOperations aeslinkOp =
{
  .setEnable         = aeslinkSetEnable,
  .sendPacket        = aeslinkSendCRTPPacket,
  .receivePacket     = aeslinkReceiveCRTPPacket,
};

static CRTPPacket p;

static const byte key[] = {0x57, 0x01, 0x2A, 0x12, 0xA7, 0x7A, 0x12, 0xBA, 0x57, 0x01, 0x2A, 0x12, 0xA7, 0x7A, 0x12, 0xBA};
static const byte initVector[] = {0x40, 0x41, 0x42, 0x43};
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
//static bool crtpPacketReceived = false;
static bool messageComplete = false;
static byte recPid = 0xF0u;



/*
 * same task to send and receive? that seems weird. unlikley
 * */

static void aeslinkTask(void *param){
	while (true)
	  {
	    if (link != &nopLink)
	    {
	      if (!link->receivePacket(&p))
	      {
	    	  byte datalength = 0;

	    	  if(((p.data[0] & PID_NBR_MASK) != recPid) && ((p.data[0] & PACKET_DATA_LENGTH_MASK) > 0)){

	    		  datalength = ((p.data[0] & PACKET_DATA_LENGTH_MASK)>21)?
	    				  21:p.data[0] & PACKET_DATA_LENGTH_MASK;

	    		  recAuthData[0] = p.header;
	    		  recAuthData[1] = p.data[0];

	    		  recPid = p.data[0] & PID_NBR_MASK;

	    		  bzero(&recInitVector, sizeof(initVector));
	    		  bzero(&recAuthTag, AUTH_TAG_SIZE);
	    		  bzero(&recCipherPackageData, datalength);

	    		  memcpy(&recInitVector, &p.data[1], sizeof(initVector));
	    		  memcpy(&recAuthTag, &p.data[5], AUTH_TAG_SIZE);
	    		  memcpy(&recCipherPackageData, &p.data[9], datalength);

	    		  messageComplete = ((p.data[0] & PACKET_DATA_LENGTH_MASK)>datalength)?
	    				  false:true;//inverted of implicit

	    	  } else if((p.data[0] & PID_NBR_MASK) == recPid){ // only be done if this is the second package

	    		  //might crash if packet length in PID byte is 0
	    		  memcpy(&recCipherPackageData[21], &p.data[1], (p.data[0] & PACKET_DATA_LENGTH_MASK)-21);

	    		  messageComplete = true;
	    	  }
	    	  if(messageComplete){

	    		  wc_AesGcmDecrypt(&dec, recPlainPackageData, recCipherPackageData, (p.data[0] & PACKET_DATA_LENGTH_MASK),
	    				  recInitVector, sizeof(initVector), recAuthTag, AUTH_TAG_SIZE, recAuthData, AUTH_DATA_SIZE);

	    		  rp.header = p.header;
	    		  memcpy(&rp.data[0], recPlainPackageData, (p.data[0] & PACKET_DATA_LENGTH_MASK));

	    		  xQueueSend(crtpPacketDelivery, &rp, 0);

	    		  messageComplete = false;
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
	if(sendPid >3){
		sendPid = 0;
	}
	byte dataLength = (sizeof(p->data)>MAX_DATA_IN_FIRST_PACKET)?
			MAX_DATA_IN_FIRST_PACKET:sizeof(p->data);

	sp.size = dataLength + ADDITIONAL_BYTES;
	//sp.port = p->port;
	//sp.channel = p->channel;
	sp.header = p->header;

	bzero(&sendPlainPackageData, sizeof(sendPlainPackageData));
	bzero(&sendAuthData, sizeof(sendAuthData));
	bzero(&sp.data, CRTP_MAX_DATA_SIZE);


	sendAuthData[0] = ((p->channel<<4) + (p->reserved<<2) + (p->port));
	sendAuthData[1] = (sizeof(p->data)>MAX_DATA_IN_FIRST_PACKET)?
			FIRST_OF_MULTI_PACKET_MASK | ((sendPid<<5)&PID_NBR_MASK) | ((p->size) & PACKET_DATA_LENGTH_MASK)
			:((sendPid<<5)&PID_NBR_MASK) | ((p->size) & PACKET_DATA_LENGTH_MASK);


	memcpy(sendPlainPackageData, p->data, sizeof(p->data));
	wc_AesGcmEncrypt(&enc, sendCipherPackageData, sendPlainPackageData, sizeof(sendPlainPackageData), initVector
			, sizeof(initVector), sendAuthTag, sizeof(sendAuthTag), sendAuthData, sizeof(sendAuthData));

	memcpy(&sp.data[0], &sendPid, 1);
	memcpy(&sp.data[1], &initVector, sizeof(initVector));
	memcpy(&sp.data[5], &sendAuthTag, sizeof(sendAuthTag));
	memcpy(&sp.data[9], &sendCipherPackageData, dataLength);

	link->sendPacket(&sp);


	if(sizeof(p->data) > 21){
		dataLength = sizeof(p->data)-dataLength;
		sp.size = dataLength + PID_BYTE;
		bzero(&sp.data, sp.size);

		sp.data[0] = ((sendPid<<5)&0x60) | (dataLength & 0x1f);
		memcpy(&sp.data[1], &sendCipherPackageData[21], dataLength);
		link->sendPacket(&sp);
	}


	//return link->sendPacket(p);
	sendPid++;
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
struct crtpLinkOperations * aeslinkGetLink()
{
	return &aeslinkOp;
}
*/
void aesEnableTunnel(){
	ledseqRun(LINK_LED, seq_bootloader);
	//crtpGetLink(link);
	link = radiolinkGetLink();
	crtpSetLink(&aeslinkOp);
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
