/*
 * A simple program that trys to detect port scanning
 * using raw sockets
 *
 * Matthew Todd Geiger
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 65536

#define ERROR(str, ...) fprintf(stderr, "ERROR: " str "\n", ##__VA_ARGS__)
#define UNUSED_PARAMETER(var) ((void)(var))

volatile char quit = 0;

void handle_sigint(int sig) {
   UNUSED_PARAMETER(sig);
   printf("Interrupt captured, shutting down\n");
   quit = 1;
}

int main() {

   int index = 0;   
   int sockfd = -1;
   int ret = EXIT_SUCCESS;
   struct sockaddr_in addr;
   socklen_t addr_size = sizeof(addr);
   char buffer[BUFFER_SIZE];

   // Confirm the user is root
   if(getuid()) {
      ERROR("Root required for raw sockets");
      ret = EXIT_FAILURE;
      goto END;
   }

   // Create raw socket
   if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
      ERROR("Failed to create raw socket");
      ret = EXIT_FAILURE;
      goto END;
   }

   // Set non blocking
   if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
      ERROR("Failed to set non blocking socket");
      ret = EXIT_FAILURE;
      goto END;
   }

   // Set socket option to receive all packets
   int enable = 1;
   if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == -1) {
      ERROR("Failed to set socket option");
      ret = EXIT_FAILURE;
      goto END;
   }

   // Set sigint handler
   if(signal(SIGINT, handle_sigint) == SIG_ERR) {
      ERROR("Failed to create signal handler");
      ret = EXIT_FAILURE;
      goto END;
   }

   while(!quit) {
      // Recieve but dont block
      int len = recvfrom(sockfd, buffer + index, BUFFER_SIZE - index, MSG_DONTWAIT, (struct sockaddr *)&addr, &addr_size);
      if(len == -1) {
         if(errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
   
         ERROR("Failed to recvfrom (%s)", strerror(errno));
         ret = EXIT_FAILURE;
         goto END;
      }

      index += len;

      // If you dont have the IP packet continue
      if(index < 20)
         continue;

      // Extract IP Header
      struct iphdr *ip_header = (struct iphdr *)buffer;
      unsigned short ip_header_length = ip_header->ihl * 4;

      // If the packet is not fully recieved continue
      if(index < ntohs(ip_header->tot_len))
         continue; 

      // Reset index so that the next packet can processed properly
      index = 0;

      // Extract TCP header
      struct tcphdr *tcp_header = (struct tcphdr *)(buffer + ip_header_length);

      // Is the packet trying to connect to a TCP port?
      if(tcp_header->syn && !tcp_header->ack) {
         char source_ip[INET_ADDRSTRLEN];
         char dest_ip[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
         inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
         
         printf("TCP SYN packet received from %s:%d to %s:%d\n",
               source_ip,
               ntohs(tcp_header->source),
               dest_ip,
               ntohs(tcp_header->dest));

         // Implement more logic here if desired
      }
   }

END:
   if(sockfd != -1)
      close(sockfd);

   return ret;
}
