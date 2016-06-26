#include <vector>
using namespace std;


#include "pcap.h"
#include"process.h"

#include "file.h"
#include "tools.h"

struct ether_header
{
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};
struct arp_header
{
	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int8_t arp_hardware_length;
	u_int8_t arp_protocol_length;
	u_int16_t arp_operation_code;
	u_int8_t arp_source_ethernet_address[6];
	u_int8_t arp_source_ip_address[4];
	u_int8_t arp_destination_ethernet_address[6];
	u_int8_t arp_destination_ip_address[4];
};
struct ip_header
{
#if defined(WORDS_BIGENDIAN)
	u_int8_t ip_version:4,ip_header_length:4;
#else
	u_int8_t ip_header_length:4,ip_version:4;
#endif
	u_int8_t ip_tos;
	u_int16_t ip_length;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_protocol;
	u_int16_t ip_checksum;
	struct in_addr ip_souce_address;
	struct in_addr ip_destination_address;
};
struct udp_header
{
	u_int16_t udp_source_port;
	u_int16_t udp_destinanion_port;
	u_int16_t udp_length;
	u_int16_t udp_checksum;
};
struct tcp_header
{
	u_int16_t tcp_source_port;
	u_int16_t tcp_destinanion_port;
	u_int32_t tcp_sequence_num;
	u_int32_t tcp_acknowledgement;
#ifdef WORDS_BIGENDIAN
	u_int8_t tcp_offset:4,tcp_offset:4;
#else
	u_int8_t tcp_reserved:4,tcp_offset:4;
#endif
	u_int8_t tcp_flags;
	u_int16_t tcp_windows;
	u_int16_t tcp_checksum;
	u_int16_t tcp_urent_pointer;
};
struct icmp_header
{
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_checksum;
	u_int16_t icmp_id;
	u_int16_t icmp_sequence;
};




struct Adapterinfo
{
	CHAR    name[20];
    CHAR    info[100];
	CHAR    Error[50];
};

struct  Datainfo
{
	CHAR   protocol[20];
	CHAR   Source[50];
	CHAR  Destination[50];

};

struct Hwndinfo
{
	HWND hwnd;
	WPARAM wparam;
	LPARAM lparam;
	int index;
};

//struct IPDATAINFO
//{
//	CHAR	    Source_IP[15];
//	CHAR		Destination_IP[15];
//	CHAR		ip_protocol_tryp[25];
//	CHAR	    UDP_source_Port[15];
//	CHAR		UDP_destination_Port[15];
//	CHAR	    UDP_protocol_tryp[25];
//	CHAR	    TCP_source_Port[15];
//	CHAR		TCP_destination_Port[15];
//};

struct Datapackagestruct
{
	const u_char       *  point;
};
/////////
//全局变量 信号量
//////////////////////////////////////////////////////////////////////////
HANDLE  Semaphore;
BOOL flag=FALSE;
BOOL getend=FALSE;
HINSTANCE allhin; 
Hwndinfo  thecontrolinfo;
vector<Datapackagestruct> Datapackage;
	pcap_if_t * allAdapters;//适配器列表
	pcap_t           * adapterHandle;
//////////////////////////////////////////////////////////////////////////
//界面初始化所以的函数    ok
//////////////////////////////////////////////////////////////////////////
void initall(HWND hwnd);
//////////////////////////////////////////////////////////////////////////
//初始化网络适配器列表标题的主函数  ok
//////////////////////////////////////////////////////////////////////////
void initlistadaptertitle(HWND hwnd);

//////////////////////////////////////////////////////////////////////////
//初始化网络适配器列表内容的主函数   ok
//////////////////////////////////////////////////////////////////////////
void initlistadapter(HWND hwnd);


//////////////////////////////////////////////////////////////////////////
//获取网络适配器    ok
//////////////////////////////////////////////////////////////////////////
int getadpater(Adapterinfo  infoadapter[]);


//////////////////////////////////////////////////////////////////////////
//解析数据包     ok
//////////////////////////////////////////////////////////////////////////
void Packetanalyse(const u_char* temp_data,Datainfo* );

//////////////////////////////////////////////////////////////////////////
//初始化选中适配器的数据包列表标题的主函数ok
//////////////////////////////////////////////////////////////////////////
void initlistdatatitle(HWND hwnd);

//////////////////////////////////////////////////////////////////////////
//初始化选中适配器的数据包列表内容的主函数 ok
//////////////////////////////////////////////////////////////////////////
DWORD  WINAPI initlistdata(LPVOID  lpParam);

//////////////////////////////////////////////////////////////////////////
//数据添加进入数据包列表 ok
//////////////////////////////////////////////////////////////////////////
void AddListdata(HWND hwnd,Datainfo * thenodehead ,int index);
//////////////////////////////////////////////////////////////////////////
//控制信号量的函数 ok
//////////////////////////////////////////////////////////////////////////
void Addsemapore();


//////////////////////////////////////////////////////////////////////////
//获取选中的适配器ID并放在EDITID上
//////////////////////////////////////////////////////////////////////////
int getSelectadapter(HWND);



//////////////////////////////////////////////////////////////////////////
//改变 当前操作 的text内容
//////////////////////////////////////////////////////////////////////////
void setoptext(HWND hwnd,CHAR buf[]);

//////////////////////////////////////////////////////////////////////////
//解析IP包
//////////////////////////////////////////////////////////////////////////
void AnalyseUDP(const u_char *temp_data_udp,IPDATAINFO *infobuf);
void AnalyseIP(const u_char *temp_data_ip,IPDATAINFO *infobuf);
void AnalyseTCP(const u_char *temp_data_tcp,IPDATAINFO* infobuf);
void AnalyseIP(const u_char *temp_data_ip,IPDATAINFO* infobuf)
{
    struct ip_header* ip_protocol;//ip头
    ip_protocol=(ip_header*)(temp_data_ip+14);//去掉以太网头
     unsigned char* p = (unsigned char*)&ip_protocol->ip_souce_address;
    // printf("Source IP\t: %u.%u.%u.%u\n",p[0],p[1],p[2],p[3]);
	 CHAR tmpbuf[5];
	 ZeroMemory(tmpbuf,5);
	 for(int i=0;i<4;i++)
	 {
		
		 sprintf_s(tmpbuf,"%d",p[i]);
		 strcat(infobuf->Source_IP,tmpbuf);
		 if(i<3)
			 strcat(infobuf->Source_IP,".");
		 
		
	 }
     p = (unsigned char*)&ip_protocol->ip_destination_address;
  //   printf("Destination IP\t: %u.%u.%u.%u\n",p[0],p[1],p[2],p[3]);
	 for(int i=0;i<4;i++)
	 {
		
			 sprintf_s(tmpbuf,"%d",p[i]);
			 strcat(infobuf->Destination_IP,tmpbuf);
			 if(i<3)
				 strcat(infobuf->Destination_IP,".");
		 
		
	 }
     switch(ip_protocol->ip_protocol)
   {
	 case 1:
		{ //	  printf("The ip_protocol is ICMP\n");
		 strcpy(infobuf->ip_protocol_tryp,"The ip_protocol is ICMP");
		 //	  AnalyseICMP(temp_data_ip);
		 break;
		}
	 case 6: 
		 { // printf("The ip_protocol is TCP\n");
			 strcpy(infobuf->ip_protocol_tryp,"The ip_protocol is TCP");
			 AnalyseTCP(temp_data_ip,infobuf);
			 break;
		 }
	 case 17:
		 {
			 strcpy(infobuf->ip_protocol_tryp,"The ip_protocol is UDP");
			 //printf("The ip_protocol is UDP\n");
			 AnalyseUDP(temp_data_ip,infobuf);
			 break;
		 }

	 default:
		 {// printf("The ip_protocol is unknown!\n");
			 strcpy(infobuf->ip_protocol_tryp,"The ip_protocol is unknown!");
			 break;
		 }
   } 
}

void AnalyseUDP(const u_char *temp_data_udp,IPDATAINFO* infobuf)
{
	struct udp_header* udp_protocol;//UDP头
	udp_protocol=(udp_header*)(temp_data_udp+14+20);//去掉以太网头和ip头
	//printf("UDP source Port\t: %u\r\n",ntohs(udp_protocol->udp_source_port));
	sprintf_s(infobuf->UDP_source_Port,"%d",ntohs(udp_protocol->udp_source_port));
	//printf("UDP destination Port\t: %u\r\n",ntohs(udp_protocol->udp_destinanion_port));
	sprintf_s(infobuf->UDP_destination_Port,"%d",ntohs(udp_protocol->udp_destinanion_port));
	u_short udp_destinanion_port=ntohs(udp_protocol->udp_destinanion_port);
	switch(udp_destinanion_port)
	{
	case 138:
		//printf("UDP::NetBIOS数据报服务\n");
		strcpy(infobuf->UDP_protocol_tryp,"UDP::NetBIOS数据报服务");
		break;
	case 137:
		//printf("UDP::NetBIOS名字服务\n");
		strcpy(infobuf->UDP_protocol_tryp,"UDP::NetBIOS名字服务");
		break;
	case 139:
		//	printf("UDP::NetBIOS会话服务\n");
		strcpy(infobuf->UDP_protocol_tryp,"UDP::NetBIOS会话服务");
		break;
	case 53:
		//	printf("UDP::DNS服务\n");
		strcpy(infobuf->UDP_protocol_tryp,"UDP::DNS服务");
		break;
	default:
		//printf("UDP::Others\n");
		strcpy(infobuf->UDP_protocol_tryp,"UDP::Others");
	}
}

void AnalyseTCP(const u_char *temp_data_tcp,IPDATAINFO* infobuf)
{
	struct tcp_header* tcp_protocol;//TCP头
	tcp_protocol=(tcp_header*)(temp_data_tcp+14+20);//去掉以太网头和ip头
	//printf("TCP source Port\t: %u\r\n",ntohs(tcp_protocol->tcp_source_port));
	sprintf_s(infobuf->TCP_source_Port,"%d",ntohs(tcp_protocol->tcp_source_port));
	//printf("TCP destination Port\t: %u\r\n",ntohs(tcp_protocol->tcp_destinanion_port));
	sprintf_s(infobuf->TCP_destination_Port,"%d",ntohs(tcp_protocol->tcp_destinanion_port));
}






//////////////////////////////////////////////////////////////////////////
//对ip层进行操作
//////////////////////////////////////////////////////////////////////////
void  getselectListdatainfo(HWND hwnd,WPARAM wparam,LPARAM lparam);

void  getselectListdatainfo(HWND hwnd,WPARAM wparam,LPARAM lparam)
{
	//LV_ITEM lvi;
	HWND  Listdata= GetDlgItem(hwnd,IDC_LIST1);
    int select=SendMessage(Listdata,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	Datapackagestruct tmp= Datapackage.at(select);
	IPDATAINFO *tmppoint=(IPDATAINFO*)malloc(sizeof(IPDATAINFO));
	ZeroMemory(tmppoint,sizeof(IPDATAINFO));
	if(tmp.point!=NULL)
	{
	AnalyseIP(tmp.point,tmppoint);
	SetTHEDatainfoTEXT(hwnd,tmppoint);
	}
}




void setoptext(HWND hwnd,CHAR buf[])
{
	HWND  optext=GetDlgItem(hwnd,IDC_opinfo);
	SendMessage(optext,WM_SETTEXT,0,(LPARAM)buf);
}



int getSelectadapter(HWND hwnd)
{
	HWND hListview;
	CHAR adapterID[10];
	ZeroMemory(adapterID,10);
	hListview = GetDlgItem(hwnd, IDC_apdpter);
	HWND ID= GetDlgItem(hwnd,IDC_adapterID);
	SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)adapterID);
	int select=SendMessage(hListview,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	sprintf_s(adapterID,"%d",select+1);
	SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)adapterID);
	return select;
}

void AddListdata(HWND hwnd,Datainfo * thenodehead,int index)
{
	        HWND hListView;
		    char buf[10];
			hListView = GetDlgItem(hwnd, 1001);
			LV_ITEM lvI;
			ZeroMemory(&lvI,sizeof(LV_ITEM));
			lvI.mask = LVIF_TEXT;
       
				lvI.iItem = index;
			//	wsprintf(itembuffer, _T(" %d"), index+1);
				lvI.iSubItem=0;
				sprintf_s(buf,"%d",index);
				lvI.pszText =buf ;
				SendMessage(hListView,LVM_INSERTITEM,0,(DWORD)&lvI);
					//添加子项
				lvI.iItem = index;
				//	wsprintf(itembuffer, _T(" %d"), index+1);
				lvI.iSubItem=1;
				lvI.pszText = thenodehead->Source;
				ListView_SetItem(hListView, &lvI);
			
				lvI.iItem = index;
				lvI.iSubItem = 2;
				lvI.pszText =thenodehead->Destination;
				ListView_SetItem(hListView, &lvI);

				lvI.iItem = index;
				lvI.iSubItem = 3;
				lvI.pszText = thenodehead->protocol;
				ListView_SetItem(hListView, &lvI);
			
			

}
void Addsemapore()
{
	if(flag)
	{
     ReleaseSemaphore(Semaphore, 1, NULL);
	}
	else
	{
	
	}
}
DWORD WINAPI initlistdata(LPVOID lpParam)
{
	Hwndinfo  myhwnd=*(Hwndinfo*)lpParam;

	HWND hListview;
	hListview = GetDlgItem(myhwnd.hwnd, IDC_apdpter);
	CHAR name[100];
	CHAR errorbuf[100];
	const u_char       * packetData;
	LV_ITEM lv;
	pcap_if_t * tmp;
	
	struct pcap_pkthdr * packetHeader;
	CHAR adapterID[10];
	ZeroMemory(name,100);
	ZeroMemory(&lv,sizeof(lv));
	//ZeroMemory(adapterID,10);
	//HWND ID= GetDlgItem(myhwnd.hwnd,IDC_adapterID);
 //   SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)adapterID);
	//int select=SendMessage(hListview,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
 //   sprintf_s(adapterID,"%d",select+1);
	//SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)adapterID);

	lv.iSubItem=1;
	lv.pszText=name;
	lv.cchTextMax=100;
	SendMessage(hListview,LVM_GETITEMTEXT,myhwnd.index-1,(DWORD)&lv);



	adapterHandle = pcap_open(name , // name of the adapter
		65536,         // 部分数据包捕获
		// 65536 保证整个包将被捕获
		// 
		PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
		1000,             // 读取超时时间设置
		NULL,          // authentication on the remote machine
		errorbuf    // error buffer
		);

	if( adapterHandle == NULL )
	{//指定适配器打开失败
		//fprintf( stderr, "\nUnable to open the adapter\n", adapter->name );
		// 释放适配器列表
		MessageBox(myhwnd.hwnd,"打开适配器失败！","ERROR",0);
		//pcap_freealldevs( allAdapters );
		return -1;
	}


	int retValue;
	int i=0;
	//Datainfo* next;
	Datainfo *first;
	int  index=0;
	//Datainfo *tmppoint;
    //first=(Datainfo*)malloc(sizeof(Datainfo));
	//tmppoint=first;

    //Datapackage.resize(50);
	Datapackagestruct * tmpstruct;
	while( ( retValue = pcap_next_ex( adapterHandle, 
		&packetHeader, 
		&packetData ) ) >= 0 )
	{
		// timeout elapsed if we reach this point
		if(!getend)
		{
			WaitForSingleObject(Semaphore, INFINITE);
			Addsemapore();
			if( retValue == 0 )
			{
				continue;
			}
			//打印捕获数据包的信息
			if(Datapackage.size()==index)
				Datapackage.resize(index*2);
			first=(Datainfo*)malloc(sizeof(Datainfo));
			Packetanalyse(packetData,first);
			tmpstruct=(Datapackagestruct*)malloc(sizeof(Datapackagestruct));
			tmpstruct->point=packetData;
			Datapackage.push_back(*tmpstruct);
			AddListdata(myhwnd.hwnd,first,index);
			index++;
		}
		else
		{
			Datapackage.clear();
			vector<Datapackagestruct >().swap(Datapackage);
			break;
		}
	}
	
//	AddListdata(myhwnd.hwnd,tmppoint);

	return 1;
}

void Packetanalyse(const u_char* temp_data,Datainfo* datainfo)
{
	u_char* mac_string;
	CHAR tmpbuf[50];
	CHAR tmp[10];
	ZeroMemory(tmpbuf,50);
	ZeroMemory(tmp,10);
	struct ether_header* ether_protocol;//以太网头
	ether_protocol=(ether_header*)temp_data;
	u_short ether_type;
	ether_type=ntohs(ether_protocol->ether_type);///ntohs 主机到网络
	//printf("------------------------------数据链路层 start---------------------------------\n");
	mac_string=ether_protocol->ether_shost;
	//printf("Source MAC\t:%u.%u.%u.%u.%u.%u\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	
	
	for(int i=0;i<6;i++)
	{
	sprintf(tmp,"%X",*(mac_string+i));
	strcat(tmpbuf,tmp);
	if(i<5)
		strcat(tmpbuf,"-");
	ZeroMemory(tmp,10);
	}

	strcpy(datainfo->Source,tmpbuf);
	mac_string=ether_protocol->ether_dhost;
	//printf("Destination MAC\t:%u.%u.%u.%u.%u.%u\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	ZeroMemory(tmpbuf,50);
	for(int i=0;i<6;i++)
	{
		sprintf(tmp,"%X",*(mac_string+i));
		strcat(tmpbuf,tmp);
		if(i<5)
			strcat(tmpbuf,"-");
		ZeroMemory(tmp,10);
	}
	strcpy(datainfo->Destination,tmpbuf);

	switch(ether_type)
	{
	case 0x0800:
		//printf("------------------------------IP Start---------------------------------\n");
		//AnalyseIP(temp_data);
		strcpy(datainfo->protocol,"IP协议");
		//printf("------------------------------IP End---------------------------------\n");
		break;
	case 0x0806:///protocol 协议
		//printf("ARP!协议\n");
		strcpy(datainfo->protocol,"ARP协议");
		break;
	case 0x0835:
		//printf("RARP协议!\n");
		strcpy(datainfo->protocol,"RARP协议");
		break;
	default:
		strcpy(datainfo->protocol,"其他协议");
		break;
	}     
}


void initlistadapter(HWND hwnd)
{
	HWND hListView;
	hListView = GetDlgItem(hwnd, IDC_apdpter);
	//LVCOLUMN lvc;
	LV_ITEM lvI;

	CHAR  itembuffer[10];
	Adapterinfo infoadapter[50];
	int code=getadpater(infoadapter);
	switch (code)
	{
	case -1:
		MessageBox(hwnd,infoadapter[0].Error,"ERROR",0);
		break;
	case -2:
 		MessageBox(hwnd,infoadapter[0].Error,"ERROR",0);
	    break;
	default:
		{
			ZeroMemory(&lvI,sizeof(LV_ITEM));
			lvI.mask = LVIF_TEXT;
		   


			for (int index = 0; index < code; index++)
			{
				lvI.iItem = index;
				wsprintf(itembuffer, _T(" %d"), index+1);
				lvI.iSubItem=0;
				lvI.pszText = itembuffer;
				SendMessage(hListView,LVM_INSERTITEM,0,(DWORD)&lvI);
				
				//添加子项
					lvI.iItem = index;
					lvI.iSubItem = 1;
					lvI.pszText = infoadapter[index].name;
					ListView_SetItem(hListView, &lvI);

					lvI.iItem = index;
					lvI.iSubItem = 2;
					lvI.pszText = infoadapter[index].info;
					ListView_SetItem(hListView, &lvI);
			}
			
		break;
		}
	}

}

int getadpater(Adapterinfo  infoadapter[])
{

	pcap_if_t * adapter;
	pcap_t           * adapterHandle;//适配器句柄
	struct pcap_pkthdr * packetHeader;
	const u_char       * packetData;
	//u_char         packet[ 20 ]; //待发送的数据封包
	char errorBuffer[ PCAP_ERRBUF_SIZE ];//错误信息缓冲区
	if( pcap_findalldevs_ex( PCAP_SRC_IF_STRING, NULL, 
		&allAdapters, errorBuffer ) == -1 )
	{//检索机器连接的所有网络适配器
		strcpy(infoadapter[0].Error,"Error in pcap_findalldevs_ex function:\n");
		strcat(infoadapter[0].Error,errorBuffer );
		return -1;
	}
	if( allAdapters == NULL )
	{//不存在任何适配器
	  //  infoadapter= _T("\nNo adapters found! Make sure WinPcap is installed.\n" );
		strcpy(infoadapter[0].Error,"No adapters found! Make sure WinPcap is installed");
		return -2;
	}
	int crtAdapter = 0;
	int i=0;
	for( adapter = allAdapters; adapter != NULL; adapter = adapter->next,i++)
	{//遍历输入适配器信息(名称和描述信息)  
	//	memcpy(&(infoadapter[i].info),(adapter->description),strlen(adapter->description)) ;
		strcpy(infoadapter[i].info,(adapter->description)) ;
		strcpy(infoadapter[i].name,(adapter->name)) ;
	}
	return i-1;
}


void initall(HWND hwnd)
{
	HICON ico=LoadIcon(allhin,MAKEINTRESOURCE(IDI_ICON1));
	SendMessage(hwnd,WM_SETICON,ICON_BIG,(long)ico);
	initlistadaptertitle(hwnd);
	initlistdatatitle(hwnd);

}


void initlistadaptertitle(HWND hwnd)
{
	HWND hListView;
	LVCOLUMN lvc;
	LVITEM lvI;
	LVITEM lvSub;
	WCHAR Num[10];

	int xBorder;

	memset(&hListView,0,sizeof(HWND));
	hListView = GetDlgItem(hwnd, IDC_apdpter);

	//设置整行选中
	SendMessage(hListView,LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_CENTER;
	lvc.cx = 30;
	lvc.iSubItem=0;
	lvc.pszText=_T("ID");
    ListView_InsertColumn(hListView, 0,&lvc);
	lvc.cx = 274;
	lvc.iSubItem=1;
	lvc.pszText=_T("name");
	ListView_InsertColumn(hListView, 1,&lvc);
	
	lvc.cx = 274;
	lvc.iSubItem=2;
	lvc.pszText=_T("description");
	ListView_InsertColumn(hListView, 2,&lvc);
	initlistadapter(hwnd);
}

void initlistdatatitle(HWND hwnd)
{
	HWND hListView;
	LVCOLUMN lvc;
	LVITEM lvI;
	LVITEM lvSub;
	WCHAR Num[10];

	int xBorder;

	hListView = GetDlgItem(hwnd, 1001);
	SendMessage(hListView,LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_CENTER;
	lvc.cx = 85;
	lvc.iSubItem=0;
	lvc.pszText=_T("ID");
	ListView_InsertColumn(hListView, 0,&lvc);
	lvc.cx = 120;
	lvc.iSubItem=1;
	lvc.pszText=_T("Source  MAC");
	ListView_InsertColumn(hListView, 1,&lvc);

	lvc.cx = 120;
	lvc.iSubItem=2;
	lvc.pszText=_T("Destination MAC");
	ListView_InsertColumn(hListView, 2,&lvc);

	lvc.cx = 120;
	lvc.iSubItem=3;
	lvc.pszText=_T("Address_protocol");
	ListView_InsertColumn(hListView, 3,&lvc);
}


int CALLBACK  SendmessageDialog(HWND hwnd, UINT uint, WPARAM wparam, LPARAM lparam)
{

	switch (uint)
	{
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	case WM_COMMAND:
		{
			switch (LOWORD(wparam))
			{
			case IDC_send:
				{
					int tmp;
					int i;
					     CHAR Destination[6][5];
					     CHAR  Sourcebuf[6][5];
						 /*	 CHAR  Destination2[5];
						 CHAR  Sourcebuf2[5];
						 CHAR  Destination3[5];
						 CHAR  Sourcebuf3[5];
						 CHAR  Destination4[5];
						 CHAR  Sourcebuf4[5];
						 CHAR  Destination5[5];
						 CHAR  Sourcebuf5[5];
						 CHAR  Destination6[5];
						 CHAR  Sourcebuf6[5];		*/
						 CHAR DATA[100];
					     u_char packet[112];

						 ZeroMemory(Destination,30);
						 ZeroMemory(Sourcebuf,30);
						 ZeroMemory(DATA,100);
						 ZeroMemory(packet,112);
						 if(adapterHandle!=NULL)
						 {
							 GetSendMessageText(hwnd,Sourcebuf[0],IDC_source1,5);
							 GetSendMessageText(hwnd,Destination[0],IDC_destination1,5);
							 GetSendMessageText(hwnd,Sourcebuf[1],IDC_source2,5);
							 GetSendMessageText(hwnd,Destination[1],IDC_destination2,5);
							 GetSendMessageText(hwnd,Sourcebuf[2],IDC_source3,5);
							 GetSendMessageText(hwnd,Destination[2],IDC_destination3,5);
							 GetSendMessageText(hwnd,Sourcebuf[3],IDC_source4,5);
							 GetSendMessageText(hwnd,Destination[3],IDC_destination4,5);
							 GetSendMessageText(hwnd,Sourcebuf[4],IDC_source5,5);
							 GetSendMessageText(hwnd,Destination[4],IDC_destination5,5);
							 GetSendMessageText(hwnd,Sourcebuf[5],IDC_source6,5);
							 GetSendMessageText(hwnd,Destination[5],IDC_destination6,5);

							 GetSendMessageText(hwnd,DATA,IDC_SendMessage,100);
							 for( i=0;i<6;i++)
							 {
								 sscanf_s(Sourcebuf[i],"%d",&tmp);
								 if(tmp>0xFF)
								 {
									 MessageBox(hwnd,"MAC地址有误","Warning",0);
									 goto  Break;
								 }
								 packet[i]=tmp;
							 }
							 for( i=0;i<6;i++)
							 {
								 sscanf_s(Destination[i],"%d",&tmp);
								 if(tmp>0xFF)
								 { 
									 MessageBox(hwnd,"MAC地址有误","Warning",0);
									 goto  Break;
								 }
								 packet[i+6]=tmp;

							 }
							 memcpy(&packet[12],DATA,100);

							 if (pcap_sendpacket(adapterHandle, packet, 112 /* size */) != 0)
							 {
								 MessageBox(hwnd,pcap_geterr(adapterHandle),"Error sending the packet:",0);
								 // SetSendMessageText(hwnd,IDC_source);
								 // SetSendMessageText(hwnd,IDC_destination);
								 SetSendMessageText(hwnd,IDC_SendMessage);


								 MessageBox(hwnd,"send Success!","",0);
							 }
							 else
							 {
								  MessageBox(hwnd,"send fail!","",0);
							 }
						 }
							 else
							 {

								 MessageBox(hwnd,"请先选择适配器\n并点击开始!","ERROR",0);
								 EndDialog(hwnd,0);
							 }
						 
Break:
					break;
				}
			default:
				break;
			}
			break;
		}
	default:
		break;
	}
	return 0;
}
int  CALLBACK  func(HWND hwnd, UINT uint, WPARAM wparam, LPARAM lparam)
{
	switch (uint)
	{

	case WM_NOTIFY:
		{
			NMHDR * ptin=(NMHDR *)lparam;
			if(wparam==IDC_apdpter&&ptin->code==NM_CLICK)
			{
				
				int selectindex=	getSelectadapter(hwnd);
				if(thecontrolinfo.index!=-1&&thecontrolinfo.index!=selectindex+1)
				{
					CHAR thecontrolinfoIDbuf[10];
					ZeroMemory(thecontrolinfoIDbuf,10);
					HWND ID= GetDlgItem(hwnd,IDC_adapterID);
				//	SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)adapterID);
				//	int select=SendMessage(hListview,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
					sprintf_s(thecontrolinfoIDbuf,"%d",thecontrolinfo.index);
					SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)thecontrolinfoIDbuf);
					MessageBox(hwnd,"想改变当前选中适配器\n请点击重新开始\n并重新选择适配器选择","Warning",0);

				}
	
			}
			if(wparam==IDC_LIST1&&ptin->code==NM_CLICK)
			{
		         getselectListdatainfo(hwnd,wparam,lparam);
			}
			break;
		}
	case WM_COMMAND:
		{
			switch (LOWORD(wparam))
			{
			case start:
				{
					//////////////////////////////////////////////////////////////////////////
					//开始button ok
					//////////////////////////////////////////////////////////////////////////
					CHAR  buttoninfobuf[10];
					ZeroMemory(buttoninfobuf,10);
					HWND startbutton=GetDlgItem(hwnd,start);
					GetWindowText(startbutton,buttoninfobuf,10);

					if(!strcmp(buttoninfobuf,"开始"))
					{

					SendMessage(startbutton,WM_SETTEXT,0,(LPARAM)"结束");
				setoptext(hwnd,"开始");
				Semaphore= CreateSemaphore(NULL, 0, 1, NULL);
				Hwndinfo * gethwnd=&thecontrolinfo;//(Hwndinfo*)malloc(sizeof(Hwndinfo));
				gethwnd->hwnd=hwnd;
				gethwnd->wparam=wparam;
				gethwnd->lparam=lparam;
				HWND ID= GetDlgItem(hwnd,IDC_adapterID);
				CHAR GETID[10];
				GetWindowText(ID,GETID,10);
				sscanf_s(GETID,"%d",&gethwnd->index);
				flag=TRUE;
				getend=FALSE;
				Addsemapore();
				CreateThread(NULL,0,initlistdata,(void *)gethwnd,0,NULL);
					}
					else if(!strcmp(buttoninfobuf,"结束"))
					{
						HWND listview=GetDlgItem(hwnd,IDC_LIST1);
						SendMessage(listview,LVM_DELETEALLITEMS,0,0);
						SendMessage(startbutton,WM_SETTEXT,0,(LPARAM)"开始");
						setoptext(hwnd,"");
						getend=TRUE;
					}
			    } 
				break;
			case pum:
				{
					//////////////////////////////////////////////////////////////////////////
					//暂停butto
					//////////////////////////////////////////////////////////////////////////
					CHAR  buttoninfobuf[10];
					ZeroMemory(buttoninfobuf,10);
					HWND pumbutton=GetDlgItem(hwnd,pum);
					GetWindowText(pumbutton,buttoninfobuf,10);
					if(!strcmp(buttoninfobuf,"暂停"))
					{
						setoptext(hwnd,"暂停");
						flag=false;
						SendMessage(pumbutton,WM_SETTEXT,0,(LPARAM)"继续");
					}
					else  if(!strcmp(buttoninfobuf,"继续"))
					{
						setoptext(hwnd,"继续");
						flag=true;
						Addsemapore();
						SendMessage(pumbutton,WM_SETTEXT,0,(LPARAM)"暂停");
					//////////////////////////////////////////////////////////////////////////
						SendMessage(pumbutton,BN_DISABLE,0,0);
					}
				}
				break;
			case Rstart:
				{
				setoptext(hwnd,"");
				HWND startbutton=GetDlgItem(hwnd,start);
				SendMessage(startbutton,WM_SETTEXT,0,(LPARAM)"开始");
				HWND pumbutton=GetDlgItem(hwnd,pum);
				SendMessage(pumbutton,WM_SETTEXT,0,(LPARAM)"暂停");
				HWND ID= GetDlgItem(hwnd,IDC_adapterID);
				SendMessage(ID,WM_SETTEXT,0,(LPARAM)(LPCSTR)"");

				HWND listview=GetDlgItem(hwnd,IDC_LIST1);
				SendMessage(listview,LVM_DELETEALLITEMS,0,0);
				HWND IPDATAINFO= GetDlgItem(hwnd,IDC_IPDATAINFO);
				SendMessage(IPDATAINFO,WM_SETTEXT,0,(LPARAM)"");
				getend=TRUE ;
				ZeroMemory(&thecontrolinfo,sizeof(thecontrolinfo));
				thecontrolinfo.index=-1;
					break;
				}
			case senddata:
				{
					DialogBox(allhin,MAKEINTRESOURCE(IDD_SendMessage),NULL,SendmessageDialog);
				break;
				}
			default:
				break;
			}
			break;
		}
	case  WM_INITDIALOG:
		{
			initall(hwnd);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
		    pcap_freealldevs( allAdapters );
			ExitProcess(0);
			break;
		}
	default:
		break;
	}
 return 0;
} 
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
					   _In_opt_ HINSTANCE hPrevInstance,
					   _In_ LPTSTR    lpCmdLine,
					   _In_ int       nCmdShow)
{
	allhin=hInstance;
	INITCOMMONCONTROLSEX ico;
	ico.dwSize=sizeof(INITCOMMONCONTROLSEX);
    ico.dwICC=ICC_WIN95_CLASSES;   ///包含所有的通用控件
	InitCommonControlsEx(&ico);
	thecontrolinfo.index=-1;

	DialogBox(hInstance,MAKEINTRESOURCE(IDD_mydialog),NULL,func);

}