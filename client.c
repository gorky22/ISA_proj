// project for ISA
// author: Damian Gorcak
// date: 21.10.2021

#include <stdio.h>
#include<stdlib.h>           // for exit()
#include<string.h>           //for memset
#include<unistd.h>         
#include<openssl/aes.h>     //// for making AES cipher
#include<sys/socket.h>      // for creating socket and addrinfo
#include <sys/types.h>      // addr info
#include <netdb.h>          // addr info
#include<net/ethernet.h>    // ethernet layer
#include<netinet/ip_icmp.h>	// icmp header
#include<netinet/icmp6.h>	// icmp6 header
#include <sys/types.h>
#include <netdb.h>

#include "structs.h"        // own created structures

const int SEND_BY_ME_WITHOUT_DATA = -2;
const int SEND_BY_ME_WITH_DATA = -1;
const int IP6 = 10;
bool can_print ;

// 	this function is taken from
//	SOURCE: https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array
//	AUTHOR: NateS
//  DATE: 13.1.2020

// this takes as an input file and finds out how many bytes it has
int find_size_of_file(FILE *file) {  
  int filelen;
  fseek(file, 0, SEEK_END);          // jump to the end of file
  filelen = ftell(file);             // reading size  
  rewind(file);                      // jump back to the start
  return filelen;
}

unsigned short checksum(void *b, int len)
{    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
  
    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


// this function create and send first and last custom packet for icmp

void create_and_send_first_or_last_icmp(char filename[],int last_packet_size,struct addrinfo *addrinfo,int client_socket) {
  
  struct my_icmp_pckt icmp_custom;              /// create custom packet
  
  icmp_custom.hdr.type = ICMP_ECHO;                              //    **** intersting is that program fill code part with -2 (SEND_BY_ME_WITHOUT_DATA)        
  icmp_custom.hdr.code = SEND_BY_ME_WITHOUT_DATA;                //    **** or -1 so server will know that this packet was sent by me
  strcpy(icmp_custom.pckt.file_name,filename);                   //  
      
  icmp_custom.pckt.file_size =  last_packet_size;     //
  if(last_packet_size == 0) {                         //
        icmp_custom.pckt.type = 1;                    //   here we decide id this packet is first or last if first type is 1
  } else {                                            //   if last type is 2
        icmp_custom.pckt.type = 2;                    //   - in first is important name of file which we want to send
        if(can_print) {
                    printf("last packet appropriate size is %d\n",last_packet_size);          //   - in last is important in which byte is EOF 
        }
  }

  if ( sendto(client_socket, &icmp_custom, sizeof(icmp_custom), 0, addrinfo->ai_addr, addrinfo->ai_addrlen) <= 0) {  // sending packet to 
        if (can_print){
        printf("Packet sent failed\n");                                                                              // appropriate adress
        }
    }

}

void create_and_send_first_or_last_icmp6(char filename[],int last_packet_size,struct addrinfo *addrinfo,int client_socket) {   /// this function creates custpm packet 
  
  struct my_icmp_pckt6 icmp_custom;                         /// create custom packet

  icmp_custom.hdr.icmp6_type = ICMP6_ECHO_REQUEST;          //    **** intersting is that program fill code part with -2 (SEND_BY_ME_WITHOUT_DATA)
  icmp_custom.hdr.icmp6_code = SEND_BY_ME_WITHOUT_DATA;     //    **** or -1 so server will know that this packet was sent by me
  strcpy(icmp_custom.pckt.file_name,filename);              //
      
  icmp_custom.pckt.file_size =  last_packet_size;     //
  if(last_packet_size == 0) {                         //
        icmp_custom.pckt.type = 1;                    //   here we decide id this packet is first or last if first type is 1
  } else {                                            //   if last type is 2
        icmp_custom.pckt.type = 2;                    //   - in first is important name of file which we want to send
  }                                                   //   - in last is important in which byte is EOF 


    if ( sendto(client_socket, &icmp_custom, sizeof(icmp_custom), 0, addrinfo->ai_addr, addrinfo->ai_addrlen) <= 0) {  // sending packet to 
        if(can_print){
            printf("Packet sent failed\n");                                                                                // appropriate adress
        }
    } 

}

char *make_cypher(char *message){

AES_KEY AESkey;
char buffer[16];            // storing each 16 bytes from 1424 which has data
unsigned char cypher[16];   // cypher

unsigned char *key = (unsigned char*)malloc(16* sizeof(char)); // key for cipher --> alocating memory

memset(key,0,16);           // making sure that there will be nothing in memory 
memcpy(key,"xgorca00",8);   // adding loggin as a key
 
AES_set_encrypt_key((const unsigned char *) key, 128, &AESkey);  /// setting key for encryption

for (int i = 0; i < 1424; i ++) {    /// separeating message which is 1424 bytest long into 16 bytes blocks which are encrypted and after that giving back to message

    if(i%16 == 15) {    // if buffer is full encrypring this block
        buffer[i%16] = message[i];

        AES_encrypt((const unsigned char *) buffer,cypher, (const AES_KEY *) &AESkey);

        for(int j = 0; j < 16 ; j++) {
            message[i - 15 + j] = cypher[j];    //save cipher to the message
        }
        
    } else {

        buffer[i%16] = message[i];
    
    }
    
}

return message;
free(key);

}



// this function send file when using IPv4
void send_file_via_icmp(struct addrinfo *addrinfo,int client_socket, char *buffer, int how_many_packets,int filelen){

    int counter = 0;                    /// counting alll bytes which we will be sending ---- because of buffer where whole file is loaded
    int counter_for_icmp_data = 0;      /// only 1424 each time -----> icmp packet data has size 1424 bytes
    int flag = 1;   //maybe will use in future
    int sent_messages = 0;
 
    int max_for_one_packet = 0;                       // in for loop for max size (each iteration counter + 1423)

    char packet[1432];                  // packet
    memset(packet,0,1432);              // clearing packet
    char data[1424];                    // data where file-bytes will be sent
    struct icmphdr *icmp = (struct icmphdr*)(packet);   // icmp header

///////////////////////////////////////sending file in iterations//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
while(how_many_packets != 0) {
    
        if (flag == 1) {                /////////   when flag is set to one everithing is goood but when flag is set to 0 then is problme with packet 
        how_many_packets--;

        icmp->type = ICMP_ECHO;
        counter_for_icmp_data = 0;
        max_for_one_packet = counter + 1423;

    for (counter; counter <= max_for_one_packet; counter++) {  //// filling packet with each iteration in while cycle with 1424 bytes of file 
         if(counter == filelen){
            data[counter_for_icmp_data] = EOF;
            create_and_send_first_or_last_icmp("last_packet",counter_for_icmp_data,addrinfo,client_socket); // last packet dont have to has full 1424 bytes so we send packet which tell server that it should write not 1424 bytes but only how many it counts
        } else if(counter > filelen) {
            data[counter_for_icmp_data] = 0;
        } else {
            data[counter_for_icmp_data] = buffer[counter];
        }

        counter_for_icmp_data ++ ;
    }
   
    memcpy(data,make_cypher(data),1424); // creating cypher
         
    
    }

   
    icmp->code = SEND_BY_ME_WITH_DATA;  
    memcpy(packet + sizeof(struct icmphdr),data,1424);  /// fill packet with data
    icmp->checksum = checksum(packet,sizeof(struct icmphdr) + sizeof(data));
    
    if ( sendto(client_socket,packet, sizeof(struct icmphdr) + 1424, 0, addrinfo->ai_addr, addrinfo->ai_addrlen) <= 0) {
        if(can_print){
                    printf("Packet sent failed\n");
        }
        flag=0; //send again
    } else {
        flag = 1;
       // printf("sent\n");
    }

    usleep(10000); // sleeep when sending

  }




}


void send_file_via_icmpv6(struct addrinfo *addrinfo,int client_socket, char *buffer, int how_many_packets,int filelen){

    int counter = 0;                    /// counting alll bytes which we will be sending ---- because of buffer where whole file is loaded
    int counter_for_icmp_data = 0;      /// only 1424 each time -----> icmp packet data has size 1424 bytes
    int flag = 1;   //maybe will use in future
    int sent_messages = 0;
 
    int max_for_one_packet = 0;                       // in for loop for max size (each iteration counter + 1423)

    char packet[1500];                  // packet
    memset(packet,0,1500);              // clearing packet
    char data[1424];                    // data where file-bytes will be sent

    struct icmp6_hdr *icmp = (struct icmp6_hdr*)(packet);

    icmp->icmp6_code = SEND_BY_ME_WITH_DATA;


/////////////////////////////////sending data//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
while(how_many_packets != 0) {
    
    if (flag == 1) {                /////////   when flag is set to one everithing is goood but when flag is set to 0 then is problme with packet 
        
        how_many_packets--;
        icmp->icmp6_type = ICMP6_ECHO_REQUEST;
        counter_for_icmp_data = 0;
        max_for_one_packet = counter + 1423;

    for (counter; counter <= max_for_one_packet; counter++) {  //// filling packet with each iteration in while cycle with 1424 bytes of file 
        
        if(counter == filelen){
         data[counter_for_icmp_data] = EOF;
         create_and_send_first_or_last_icmp6("last_packet",counter_for_icmp_data,addrinfo,client_socket); // last packet dont have to has full 1424 bytes so we send packet which tell server that it should write not 1424 bytes but only how many it counts
        } else if(counter > filelen) {
            data[counter_for_icmp_data] = 0;
        } else {
            data[counter_for_icmp_data] = buffer[counter];
        }
     
        counter_for_icmp_data ++ ;
    }
       memcpy(data,make_cypher(data),1424);         
    }
     icmp->icmp6_cksum = checksum(&icmp,sizeof(icmp) + sizeof(data));
    memcpy(packet + sizeof(struct icmp6_hdr),data,1424);
     
    if ( sendto(client_socket,packet, sizeof(struct icmp6_hdr) + 1424, 0, 
       addrinfo->ai_addr, addrinfo->ai_addrlen) <= 0)
    {
        if(can_print){
            printf("Packet sent failed\n");
        }
        flag=0; //send again
    } else {
        flag = 1;
       // printf("sent\n");
    }
    
    usleep(10000);
  }

}


int client(char *filename, char *ip_adress,bool print_datas){
    can_print = print_datas;
    int client_socket; /// socket for connecting
    
    struct addrinfo *result = NULL;  ///    |
    struct addrinfo *addrinfo;       ///    | 
    struct sockaddr_in addr_to_send; ///    |   ------> THIS variables will be used in getting adress info in function getaddrinfo()
    struct addrinfo hints;           ///    |
    int controll = 0;                ///    |         for result of getaddrinfo()

   // struct icmp_pckt  icmp_packet;   /// icmp packet structure 

    long filelen;

    ///// Initialization *addr info for IPv4 and IPv6
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    if (getaddrinfo(ip_adress, NULL, &hints, &result) != 0 ) {
        fprintf(stderr,"problem with getting adress\n");
        return 1;
    }


    ///// getaddrinfo can return more than one structure in the last parameter thats why we need to find first which is appropriate

    for (addrinfo = result; addrinfo != NULL; addrinfo->ai_next) {
        if(addrinfo->ai_family == 10){
            addrinfo->ai_protocol = IPPROTO_ICMPV6;
        } else{
            addrinfo->ai_protocol = IPPROTO_ICMP;
        }
        client_socket = socket(addrinfo->ai_family,addrinfo->ai_socktype,addrinfo->ai_protocol);

        if (client_socket < 0) {
            continue;
        } else {
            if(can_print) {
                printf("succes socket created\n");
            }
            break;
        }
    }

if(client_socket <= 0){
  fprintf(stderr,"socket failed\n");
  return 1;
}

char *buffer;

FILE *file_to_send;
file_to_send = fopen(filename, "rb");  // Open the file in binary mode

if(file_to_send == NULL){
    fprintf(stderr,"Error with opening file\n");
    return 1;
}

filelen = find_size_of_file(file_to_send); // find filelen
   
buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
fread(buffer, filelen, 1, file_to_send); // get file to the buffer
fclose(file_to_send); 

int max_for_one_packet= 0;
    int how_many_packets  = filelen / 1424; /// count in how many iterations should be packet sent
    if (filelen % 1424 != 0) {
        how_many_packets += 1;
    }

if(addrinfo->ai_family == IP6) {
    struct my_icmp_pckt6 icmp_custom;
    bzero(&icmp_custom,sizeof(icmp_custom));
    create_and_send_first_or_last_icmp6(filename,0,addrinfo,client_socket);
 
} else {
    struct my_icmp_pckt icmp_custom;
    bzero(&icmp_custom,sizeof(icmp_custom));
    create_and_send_first_or_last_icmp(filename,0,addrinfo,client_socket);
  
}
  
if(addrinfo->ai_family != IP6){
    send_file_via_icmp(addrinfo,client_socket,buffer,how_many_packets,filelen);
} else {
    send_file_via_icmpv6(addrinfo,client_socket,buffer,how_many_packets,filelen);
}

freeaddrinfo(addrinfo);

return 0;
      
}