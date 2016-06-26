#include "tools.h"



void SetTHEDatainfoTEXT(HWND hwnd ,IPDATAINFO* buf)
{
	HWND IPDATAINFO= GetDlgItem(hwnd,IDC_IPDATAINFO);
	SendMessage(IPDATAINFO,WM_SETTEXT,0,(LPARAM)"");
	CHAR theinfo[512];
	ZeroMemory(theinfo,512);
	if(strlen(buf->Destination_IP)>0)
	{
		strcat(theinfo,"Destination IP:");
		strcat(theinfo,buf->Destination_IP);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->Source_IP)>0)
	{
		strcat(theinfo,"Source IP:");
		strcat(theinfo,buf->Source_IP);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->ip_protocol_tryp)>0)
	{
	//	strcat(theinfo,"Source IP:");
		strcat(theinfo,buf->ip_protocol_tryp);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->UDP_source_Port)>0)
	{
		strcat(theinfo,"UDP source Port:");
		strcat(theinfo,buf->UDP_source_Port);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->UDP_destination_Port)>0)
	{
		strcat(theinfo,"UDP destination Port:");
		strcat(theinfo,buf->UDP_destination_Port);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->UDP_protocol_tryp)>0)
	{
	//	strcat(theinfo,"Source IP:");
		strcat(theinfo,buf->UDP_protocol_tryp);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->TCP_source_Port)>0)
	{
		strcat(theinfo,"TCP source Port:");
		strcat(theinfo,buf->TCP_source_Port);
		strcat(theinfo,"\r\n");
	}
	if(strlen(buf->TCP_destination_Port)>0)
	{
		strcat(theinfo,"TCP destination Port:");
		strcat(theinfo,buf->TCP_destination_Port);
		strcat(theinfo,"\r\n");
	}
	SendMessage(IPDATAINFO,WM_SETTEXT,0,(LPARAM)theinfo);
}

void GetSendMessageText(HWND hwnd,CHAR buf[],int ID,int length)
{
		HWND thehwnd=GetDlgItem(hwnd,ID);
		GetWindowText(thehwnd,buf,length);
}
void SetSendMessageText(HWND hwnd,int ID)
{
	HWND thehwnd=GetDlgItem(hwnd,ID);
	SendMessage(hwnd,WM_SETTEXT,0,(LPARAM)"");
}