#include<iostream>
#include<list>
#include<fstream>
#include<stdio.h>
#include<cstring>
#include <stdlib.h>
#include<math.h>

#define DEBUG

static int stride=3;
static int Eachtablelength=pow(2,stride);
using namespace std;
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
unsigned int GetNextIP (const char * path_of_file)
{
         ifstream file(path_of_file);
         routing_table R_T;
         unsigned int ip;
         int v[4];
         unsigned int i,pre_ip;
         string str; 
         char line[100],temp[50],dadr[32],byte[8];
         while(!file.eof())
         {
               file.getline(line,100);
         
         for(i=0;i<3;i++)
         {
             strcpy(temp,strstr(line,"."));
             v[i]=atoi(line);
             line[strstr(line,".")-line]=0;
             strcpy(line,temp+1); 
             strcpy(&(R_T.dadr[i*8]),binary_decimal(v[i],byte));               
         }
         v[3]=atoi(line);
         strcpy(&(R_T.dadr[24]),binary_decimal(v[3],byte));
         R_T.dadr[32]='\0';
         }
         ip=strtoul(R_T.dadr,0,2);
         
         return ip;
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

int GetFwdPort (void *st_ptr, unsigned int ip)
{
   
   int i,j,arry_num,port_num=0,pre_ip;
   
   
   multi_table *MB_ptr=(multi_table *) st_ptr;
   
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
	   
	   if(MB_ptr->port[ip_store[i]]!=NULL)
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
void  * ConstructStructure (void  * rt_ptr) 
{
	list<routing_table> * ptr=(list<routing_table> *) rt_ptr;
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





int main()
{
	
   

char routing_file_path[200] ;
char dest_file_path[200];
    unsigned int ip;
    int port;
    char line[100];
    cout<<"Please type in the path of the routing table file"<<endl;
   cin>>routing_file_path;



    void * rt_ptr=ParseRoutingTable(routing_file_path);
    

   cout<<"Please type in the destination address file path"<<endl;
   cin>>dest_file_path;
   
    void * st_ptr=ConstructStructure(rt_ptr);

     ifstream file(dest_file_path);
     while(file.getline(line,100))
	{
		
	}


    ip=GetNextIP(dest_file_path);

    port=GetFwdPort(st_ptr,ip);

    

cout<<port<<endl;
//



    return 0;
}
