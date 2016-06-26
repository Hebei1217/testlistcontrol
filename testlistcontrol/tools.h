#include "file.h"
#include "resource.h"
struct IPDATAINFO
{
	CHAR	    Source_IP[50];
	CHAR		Destination_IP[50];
	CHAR		ip_protocol_tryp[100];
	CHAR	    UDP_source_Port[50];
	CHAR		UDP_destination_Port[50];
	CHAR	    UDP_protocol_tryp[100];
	CHAR	    TCP_source_Port[50];
	CHAR		TCP_destination_Port[50];
};

void SetTHEDatainfoTEXT(HWND ,IPDATAINFO* );

//int CALLBACK  SendmessageDialog(HWND hwnd, UINT uint, WPARAM wparam, LPARAM lparam);
void GetSendMessageText(HWND,CHAR [],int ID,int length);
void SetSendMessageText(HWND hwnd,int ID);