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
#include<pcap.h>
#include <signal.h>

#include "structs.h"        // own created structures


const int IPv4 = 0x0800;
const int IPv6 = 0x86DD;

const int FIRST = 1;
const int LAST = 2;

const int FIRST_LAST = 255;
const int PACKET_WITH_DATA = 254;
bool can_print ;

const int PACKET_DATA_SIZE = 1424;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

char filename[100];               // name of file where data will be stored
int last_packet_size = 0;		  // last packet doesnt have to has full PACKET_DATA_SIZE bytes so we send packet which tell server that it should write not PACKET_DATA_SIZE bytes but only how many it counts
pcap_t *handle; //Handle of the interface on what we will be waitnig for our packet
			
void sigintHandler(int sig_num)
{
    pcap_breakloop(handle);
    printf("\nprogram was stopped\n");
}


char *decrypt(char *message){

   AES_KEY AESkey;
   unsigned char buffer[16];  // storing each 16 bytes from PACKET_DATA_SIZE which has data
   unsigned char cypher[16]; // cypher
   
   unsigned char *key = (unsigned char*)malloc(16* sizeof(char));  /// key for cipher --> alocating memory
   memset(key,0,16);				// making sure that there will be nothing in memory 
   memcpy(key,"xgorca00",8);		// adding loggin as a ke

  AES_set_decrypt_key((const unsigned char *) key, 128, &AESkey);   /// setting key for decryption

for (int i = 0; i < PACKET_DATA_SIZE; i ++) {				/// separeating message which is PACKET_DATA_SIZE bytest long into 16 bytes blocks which are encrypted and after that giving back to message
    if(i%16 == 15) {
        buffer[i%16] = message[i];				 // if buffer is full encrypring this block
        AES_decrypt((const unsigned char *) buffer,cypher, (const AES_KEY *) &AESkey);

        for(int j = 0; j < 16 ; j++) {
            message[i - 15 + j] = cypher[j];     //save decrypted text to the message
			//printf("%d ",cypher[j]);
        }
       //printf("\n");
        
    } else { 
        buffer[i%16] = message[i];
    }

    
}
return message;
free(key);
}

/// this funtion proccess first and last packet ---> in first name of file in last packet size of last packet 
void proccess_first_and_last(int ip_version,const unsigned char *buffer) {

	if(ip_version == IPv6) {  /// first decide if ip version is 6 or 4 (because of different struct for icmp header)
		struct my_icmp_pckt6 *icmph = (struct my_icmp_pckt6*) (buffer);
		
		if(icmph->pckt.type == LAST) {							/// IF packet is first we set up filename if last size of last packet
			last_packet_size = icmph->pckt.file_size;
			if(can_print){
				printf("last packet data approptiate size is (%d)\n",icmph->pckt.file_size);
			}
			
		} else {
  			const char * tmp_name = strrchr(icmph->pckt.file_name, '/');
			if(tmp_name != NULL){
				tmp_name++; /// remove / char
			}

			memcpy(filename,icmph->pckt.file_name,sizeof(icmph->pckt.file_name));
			remove(filename);	// remove file because we appending to it
			if(can_print){
				printf("name of file is(%s)\n",icmph->pckt.file_name);
			}
		
		}
		
	} else {
		struct icmp_pckt2 *icmph = (struct icmp_pckt2*) (buffer);  
		if(icmph->pckt.type == LAST) {              /// IF packet is first we set up filename if last size of last packet
			last_packet_size = icmph->pckt.file_size;
			if(can_print) {
				printf("last packet data approptiate size is (%d)\n",icmph->pckt.file_size);
			}
		
		} else {
			const char * tmp_name = strrchr(icmph->pckt.file_name, '/');
			if(tmp_name != NULL){
				tmp_name++; /// remove / char
			}
			memcpy(filename,icmph->pckt.file_name,sizeof(icmph->pckt.file_name));
			remove(filename); // remove file because we appending to it
			if(can_print){
				printf("name of file is(%s)\n",icmph->pckt.file_name);
			}
			
		}
	}
}

int server(bool print_datas)
{
	can_print = print_datas;
	pcap_if_t *all_interfaces;      // for stiring interface where we will be listening -> in our case it is interface "any"  
	bool is_sending_file; // for knowing that we are sending file 

	char errbuf[100] , *devname;
	int count = 1 , n;

	struct in_addr a,b;				//
	bpf_u_int32 netaddr;            //  -----> this lines of code was taken and modificated from lectures at BUT in subject ISA
  	bpf_u_int32 mask;               // 
  	struct bpf_program fp;          // 
	// for cathing ctrl + c signal
	signal(SIGINT, sigintHandler);

	// looking for all interfaces and find one
	if( pcap_findalldevs( &all_interfaces, errbuf) )
	{
		fprintf(stderr,"Error finding interfaces : %s" , errbuf);
		return 1;
	} else {
		if(can_print) {
			printf("Done finding interfaces\n");
		}
	}



	devname = all_interfaces->next->next->name; // temporary because we need any interface now 
	if(can_print){
		printf("waiting on %s interface\n",devname);
	}



	// get IP address and mask of the sniffing interface
  if (pcap_lookupnet(devname,&netaddr,&mask,errbuf) == -1) {
	  fprintf(stderr,"Error pcap_lookupnet : %s" , errbuf);
		return 1;
  }

  a.s_addr=netaddr;	
  if(can_print){
	   printf("Opening interface \"%s\" with net address %s,",devname,inet_ntoa(a));
  }																  						 //
         																				//
  b.s_addr=mask;  																		//
  if(can_print){																		//
	    printf("mask %d for listening...\n",b.s_addr); 									//
  }	                                                                     				//
                                       													// -----> this lines of code was taken and modificated from lectures at BUT in subject ISA
																					   //
	//waiting for packets															   //
	handle = pcap_open_live(devname , 65536 , 1 , 1000 , errbuf);          			
	
	if (handle == NULL) 																
	{
	
		fprintf(stderr,"problem with opening interface %s : %s\n" , devname , errbuf);
		return 1;
	}

	  // compile the filter
  if (pcap_compile(handle,&fp,"icmp6||icmp",0,netaddr) == -1){		//
	  fprintf(stderr,"Error: pcap compile failed\n");                       //
	  return 1;													//
  }																	//
																	//
																	//
  // set the filter to the packet capture handle					// -----> this lines of code was taken and modificated from lectures at BUT in subject ISA
  if (pcap_setfilter(handle,&fp) == -1){							//
	  fprintf(stderr,"Error: pcap_setfilter failed\n");						//
		return 1;													//
  }																	//
																	//
																	//
	//now we can loop and handle our packet							
	pcap_loop(handle , -1 , process_packet , NULL);
	
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	
	int size = header->len;
	

	struct ethhdr *ethernet_layer = (struct ethhdr *)(buffer + 2); // ethernet layer because som casse in any interface we must add 2 bytes ofsett
	

	if(ntohs(ethernet_layer->h_proto) == IPv6){			// find if packet is ipv6 or ipv4

	struct my_icmp_pckt6 *icmph = (struct my_icmp_pckt6*) (buffer + sizeof(struct ethhdr) + sizeof(struct ipv6_header) + 2);

	if(icmph->hdr.icmp6_type == ICMP6_ECHO_REQUEST && (icmph->hdr.icmp6_code == PACKET_WITH_DATA || icmph->hdr.icmp6_code == FIRST_LAST)) {
		if(icmph->hdr.icmp6_code == PACKET_WITH_DATA){   /// first we proceed first packet where client sent us filename and filesize
				proccess_first_and_last(IPv6,(buffer + sizeof(struct ethhdr) + sizeof(struct ipv6_header) + 2));
		} else {
		//	printf("here\n");
				FILE *file ;
				char buff[PACKET_DATA_SIZE];
				memcpy(buff,(char*)(buffer + sizeof(struct ethhdr) + sizeof(struct ipv6_header) + sizeof(struct icmp6_hdr) + 2),PACKET_DATA_SIZE);
				file = fopen(filename,"ab");		/// open file for appending bytes 
				if(file == NULL) {
					fprintf(stderr,"ERORR with opening file\n");
					exit(1);
				}
				    memcpy(buff,decrypt(buff),PACKET_DATA_SIZE); // decrypting data
				    if(last_packet_size == 0) { // if zero then we know that this is not the last packet and write data size
						fwrite(buff,PACKET_DATA_SIZE, 1, file);
					} else {
						fwrite(buff,last_packet_size, 1, file);  // if last packet write just size of last packet and break
						last_packet_size = 0;
						//pcap_breakloop(handle);
					}
                    
                fclose(file);
		}
	}

	} else {    /// is IPv4
		
		struct icmp_pckt *icmph = (struct icmp_pckt*) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + 2);
		
		if(icmph->hdr.type == ICMP_ECHO && (icmph->hdr.code == PACKET_WITH_DATA || icmph->hdr.code == FIRST_LAST)) {
			if(icmph->hdr.code == PACKET_WITH_DATA){
				proccess_first_and_last(IPv4,buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + 2);
			
			} else {

				FILE *file ;
				file = fopen(filename,"ab");			/// open file for appending bytes 
				if(file == NULL) {
					fprintf(stderr,"ERROR with opening file\n");
					exit(1);
				}
				    memcpy(icmph->data,decrypt(icmph->data),PACKET_DATA_SIZE); // decrypting packet data

                    if(last_packet_size == 0) {					// if zero then we know that this is not the last packet and write data size
						fwrite(icmph->data,PACKET_DATA_SIZE, 1, file);
					} else {
						fwrite(icmph->data,last_packet_size, 1, file); // if last packet write just size of last packet and break
						last_packet_size = 0;
						//pcap_breakloop(handle);
					}
                fclose(file);
			}
		} 
		
	}

	
}
