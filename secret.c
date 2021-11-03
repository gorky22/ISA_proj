#include <stdio.h>
#include <getopt.h>  //for handling options
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int client(char *filename, char *ip_adress,bool print_datas);
int server(bool print_datas);



void file_handle(char name_of_file[],char *ip_adress,bool print_datas) {
    
    FILE *file;

        if ((file = fopen(name_of_file, "r")) == NULL)
            {
                printf("Can't open %s\n", name_of_file);  ////// TODO HERE WEW WILL WRITE IT ON STDERR
                exit(1);
            } else {
                client(name_of_file,ip_adress,print_datas);
            }
    
        }


int main(int argc, char **argv)
{
    int opt;
    bool is_set_file_to_transfer_name = false;
    char file_to_transfer_name[100] ;
    bool is_set_ip = false;
    char ip_to_send[100] ;
    bool is_this_server_listening = false;
    bool print_datas = false;
    

   while ((opt = getopt(argc, argv, "r:ls:v")) != -1)  {                               /// handling arguments

       switch (opt) {
        case 0:
                break;
        case 'r':
            is_set_file_to_transfer_name = true;
            strcpy(file_to_transfer_name, optarg);
            break;
        case 's':
            is_set_ip = true;
            strcpy(ip_to_send,optarg);
            break;
        case 'l':
            is_this_server_listening = true;
            break;
        case 'v':
            print_datas = true;
            break;
        case '?': 
                printf("unknown option: %c\n", optopt);
                break; 
               
        }

    }


    if(is_set_file_to_transfer_name && is_set_ip && !is_this_server_listening) {
        file_handle(file_to_transfer_name,ip_to_send,print_datas);
    } else if (is_this_server_listening && (!is_set_file_to_transfer_name && !is_set_ip)) {
        server(print_datas);
    } else {
        if(is_set_file_to_transfer_name && !is_set_ip && !is_this_server_listening) {
             fprintf(stderr,"ERROR missing ip\n");
        return 1;
        } else if(!is_set_file_to_transfer_name && is_set_ip && !is_this_server_listening) {
             fprintf(stderr,"ERROR missing file\n");
        return 1;
        } else if((is_set_file_to_transfer_name || is_set_ip) && is_this_server_listening) {
             fprintf(stderr,"too much arguments\n");
        return 1;
        }
        
    }



	return 0;
}