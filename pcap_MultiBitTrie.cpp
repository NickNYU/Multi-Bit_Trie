#include<iostream>
#include<list>
#include<fstream>
#include<stdio.h>
#include <stdlib.h>
#include<math.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define ETHER_ADDR_LEN 6
struct ethernet_header
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct ip_header
{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff 
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src,ip_dst;

    #define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip) (((ip)->ip_vhl) >> 4)
  
};

typedef u_int tcp_seq;
struct tcp_header
{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >>4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
    
};
    


static int stride=3;
static int Eachtablelength=pow(2,stride);
using namespace std;



void * rt_ptr;
void * st_ptr;


struct multi_table
{
	int * port;
    
    multi_table **nextp;
    multi_table()
	{
		port=NULL;
		nextp=NULL;
	}
	
};

struct routing_table
{
       char dadr[33];
       int  prefix;
       int  port;
};

char *binary_decimal(int n,char *b)
{
	static int LEN=8;
	for(int i=LEN-1;i>=0;i--,n>>=1)
		b[i]=(01&n)+'0';
	b[LEN]='\0';
	return b;
}
unsigned int GetNextIP (char * d_adr)
{
         
         routing_table R_T;
         unsigned int ip_adr;
         int v[4];
         unsigned int i,pre_ip;
         string str; 
         char temp[50],dadr[32],byte[8];
         
         
         for(i=0;i<3;i++)
         {
             strcpy(temp,strstr(d_adr,"."));
             v[i]=atoi(d_adr);
             d_adr[strstr(d_adr,".")-d_adr]=0;
             strcpy(d_adr,temp+1); 
             strcpy(&(R_T.dadr[i*8]),binary_decimal(v[i],byte));               
         }
         v[3]=atoi(d_adr);
         strcpy(&(R_T.dadr[24]),binary_decimal(v[3],byte));
         R_T.dadr[32]='\0';
         
         ip_adr=strtoul(R_T.dadr,0,2);
         
         return ip_adr;
}

list<routing_table> Rule;


void * ParseRoutingTable (const char * path_of_file)
{

     ifstream file(path_of_file);
     int i;
     char ip[100],temp[50],byte[8];
     int v[4];
     routing_table R_T;
     

     while(file.getline(ip,100))
    {
         
         
         
         for(i=0;i<3;i++)
         {
             strcpy(temp,strstr(ip,"."));
			 
             v[i]=atoi(ip);
			 
             ip[strstr(ip,".")-ip]=0;
             strcpy(ip,temp+1); 
			
             strcpy(&(R_T.dadr[i*8]),binary_decimal(v[i],byte));               
         }
		
         v[3]=atoi(ip);
         
         strcpy(&(R_T.dadr[24]),binary_decimal(v[3],byte));
         
         R_T.dadr[32]='\0';
                
         strcpy(temp,strstr(ip,"/"));
         R_T.prefix=atoi(temp+1);
	
         R_T.port=atoi(temp+3);    
     
         Rule.push_back(R_T);

    }
     

   
return &Rule;

}

///////////////////////

int GetFwdPort (void *ptr, unsigned int ip)
{
   
   int i,j,arry_num,port_num=0,pre_ip;
   
   
   multi_table *MB_ptr=(multi_table *) ptr;
   
   if(32%stride==0)
   {
       arry_num=(32/stride);
   }
   if(32%stride!=0)
   {
       arry_num=(32/stride+1);
   }
   
   int *ip_store=new int[arry_num];//得到stride为步长数组
   
   for(i=0;i<arry_num;i++)
   {
       ip_store[i]=(ip>>(32-stride*(i+1)));
       ip_store[i]=(7&ip_store[i]);

   }

   int remain=32%stride;
   if(remain!=0)
   {
	   ip_store[arry_num-1]=ip_store[arry_num-1]<<(stride-remain);
   }
   
   
   
   
   for(i=0;i<arry_num;i++)
   {
	   
	   if(MB_ptr->port[ip_store[i]]!='\0')
	   {
		   port_num=MB_ptr->port[ip_store[i]];
	   }


       if(MB_ptr->nextp[ip_store[i]]==NULL)
	   {
		   break;
                  
	   }
       if(MB_ptr->nextp[ip_store[i]]!=NULL)
       {
                  MB_ptr=MB_ptr->nextp[ip_store[i]];
              
       }
   }
   
   return port_num;                     
                  
}


///////////////////////

multi_table EntryTable;
void  * ConstructStructure (void  * rtptr) 
{
	list<routing_table> * ptr=(list<routing_table> *) rtptr;
	int plength=0;
	int  depth=0;
	int rdepth=0;
	int ipseg=0;
	int segp=0;
    
    list <routing_table>::iterator pointer=ptr->begin();
    
	int extendnum=0;
    string tempstring;
	string substring;

    multi_table Mta;
	

	multi_table *CurrentTable;
    multi_table *NextTable;
	

	EntryTable.port=new int[Eachtablelength];
	EntryTable.nextp=new multi_table *[Eachtablelength];
	
	for(int m=0;m<Eachtablelength;m++)
	{
		EntryTable.port[m]=NULL;
        EntryTable.nextp[m]=NULL;

	}




while(pointer!=ptr->end())
    {
	substring="";
	ipseg=0;
	NextTable=&EntryTable;
	plength=(*pointer).prefix;
    depth=plength/stride;
	rdepth=plength%stride;
	tempstring=(*pointer).dadr;
	while(depth>0||(depth==0&&rdepth>0))
	{
		segp=0;
	CurrentTable=NextTable;

	substring=tempstring.substr(ipseg,stride);

	for(int j=0;j<stride;++j)
	segp=segp+(pow(2,j)*(substring[stride-1-j]-'0'));
	
	if(plength-ipseg<stride)
	{
		
	extendnum=pow(2,stride+ipseg-plength);
	for(int k=0;k<extendnum;k++)
	{
		if(CurrentTable->port[segp+k]==NULL)
    CurrentTable->port[segp+k]=(*pointer).port;
   
	}
	}
	
    if(plength-ipseg==stride)
    
		CurrentTable->port[segp]=(*pointer).port;
    //

	if(plength-ipseg>stride)
	{
	
	if(CurrentTable->nextp[segp]!=NULL)
	{NextTable=CurrentTable->nextp[segp];}	
	
	else
	{NextTable= new multi_table ;
     
	
    NextTable->port=new int[Eachtablelength];
	NextTable->nextp=new multi_table *[Eachtablelength];
	
	for(int m=0;m<Eachtablelength;m++)
	{
		NextTable->port[m]=NULL;
        NextTable->nextp[m]=NULL;

	}
    CurrentTable->nextp[segp]=NextTable;
	}
	
	}



	ipseg+=stride;
	depth--;
	}
           
	pointer++;
	ptr->pop_front();
	
	
	
	

    }
return &EntryTable;
}


void my_callback (u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    /*Dissect packet to get headers and payload*/

    static int count = 1;
    #define SIZE_ETHERNET 14
    const struct ethernet_header* ethernet;
    const struct ip_header* ip;
    const struct tcp_header* tcp;
    const u_char* payload;
    int size_ip;
    int size_tcp;
    int size_payload;
    ethernet = (struct ethernet_header*)(packet);
    ip = (struct ip_header*)(packet + SIZE_ETHERNET);
    size_ip = (IP_HL(ip)*4);
    if (size_ip < 20)
    {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return; 
    }
    tcp = (struct tcp_header*) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = (TH_OFF(tcp)*4);
    if (size_tcp < 20)
    {
        printf("Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char*) (packet+SIZE_ETHERNET+size_ip+size_tcp);
    printf ("Src IP: %s\n", inet_ntoa (ip->ip_src));
    printf ("Dst IP: %s\n", inet_ntoa (ip->ip_dst));
    printf (" Src port: %d\n", ntohs (tcp->th_sport));
    printf (" Dst port: %d\n", ntohs (tcp->th_dport));
    size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
    cout<<" The size of payload is :  "<<size_payload<<endl;

    /*Call function to do IP lookup for destination IP address*/
    char *dadr = inet_ntoa (ip->ip_dst);

    int port;
    unsigned int dadr_unsigned_int;
    dadr_unsigned_int=GetNextIP(inet_ntoa (ip->ip_dst));
    port = GetFwdPort(st_ptr,dadr_unsigned_int);
    cout<<"Forwarding port for "<< dadr <<" is "<<port<<endl;
    cout<<"Number of packets read "<<count<<endl;
    count++;

}


int main(int argc, char** argv)
{
	
   
    char routing_file_path[200];
      
    cout<<"Please type in the path of the routing table file"<<endl;
    cin>>routing_file_path;




    rt_ptr=ParseRoutingTable(routing_file_path);
    

    st_ptr=ConstructStructure(rt_ptr);

    char errbuf [PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* device="eth0";
    handle = pcap_open_live(device,1600,1,1000,errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(0);
    }
    bpf_u_int32 net, mask;
    int err = pcap_lookupnet(device,&net,&mask,errbuf);
    if(pcap_datalink(handle)!=DLT_EN10MB)
    {
	cout<<"Incorrect DataLink Layer"<<endl;
	exit(0);
    }

    pcap_loop (handle, -1, my_callback, NULL);

    pcap_close (handle);

 
//



    return 0;
}
