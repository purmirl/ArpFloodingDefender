
/*
 * 2017 November 
 * (c) PeTrA. All rights reserved.
 */

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>


int main(void){
	int 			res;
	char 			gatewayMac[18];
	char 			dev[10];
	char 			gatewayIp[16];
	char*			myIp;
	char			myMac[18];
	char 			errbuf[PCAP_ERRBUF_SIZE];
	char			tempStr[256];
	char			command[256];
	const u_char* 		packet;

	pcap_t*			handle;
	bpf_u_int32 		mask;
	bpf_u_int32 		net;
	struct pcap_pkthdr* 	header;
	FILE*			fp;
	u_char			mypacket[42];

	struct ether_header* 	eth;
	struct ether_arp*	arp;
	int			i;
	
	for(i = 0; i < 10; i++){
		dev[i] = '\0';
	}	
	
	// find gateway ip address 
	fp = popen("netstat -rn | grep 0.0.0.0 | sed -n 1p | awk '{print $2}'", "r");
	if(fp == NULL){
		perror("popen is failed");
		return -1;
	}
	fscanf(fp, "%s", gatewayIp);
	pclose(fp);

	// find device name
	fp = popen("route | grep 0.0.0.0 | sed -n 1p | awk '{print $8}'", "r");
	if(fp == NULL){
		perror("popen is failed");
		return -1;
	}
	fscanf(fp, "%s", dev);
	pclose(fp);

	// find my mac address
	fp = popen("ifconfig | grep HWaddr | awk '{print $5'}", "r");
	if(fp == NULL){
		perror("popen is failed");
		return -1;
	}
	fscanf(fp, "%s", myMac);
	pclose(fp);

	// find my ip address
	fp = popen("ifconfig | grep addr: | sed -n 1p | awk '{print $2'}", "r");
	if(fp == NULL){
		perror("popen is failed");
		return -1;
	}
	fscanf(fp, "%s", tempStr);
	pclose(fp);
	myIp = strtok(tempStr, ":");
	myIp = strtok(NULL, ":");

	// pcap ready
	if(dev == NULL){
		fprintf(stderr, "COULDN'T FIND DEFAULT DEVICE : %s\n", errbuf);
		return -1;
	}
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "COULDN'T GET NETMASK FOR DEVICE %s : %s\n", dev, errbuf);
		net = 0;
		mask = 0;
		return -1;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "COULDN'T OPEN DEVICE %s : %s\n", dev, errbuf);
		return -1;
	}

	// find gateway mac address
	eth = (struct ether_header *)mypacket;
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)eth->ether_dhost);
	ether_aton_r(myMac, (struct ether_addr *)eth->ether_shost);
	eth->ether_type = htons(ETHERTYPE_ARP);
	arp = (struct ether_arp *)(mypacket + ETH_HLEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETHER_ADDR_LEN;
	arp->arp_pln = sizeof(struct in_addr);
	arp->arp_op = htons(ARPOP_REQUEST);
	ether_aton_r(myMac, (struct ether_addr *)arp->arp_sha);
	inet_pton(AF_INET, myIp, arp->arp_spa);
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)arp->arp_tha);
	inet_pton(AF_INET, gatewayIp, arp->arp_tpa);
	if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
		printf("ERROR : FAILED TO SEND THE ARP REQUEST\n");
		return -1;
	}
	while(1){
		res = pcap_next_ex(handle, &header, &packet);
		
		if(res == 0){
			continue;
		}else if(res == -1){
			printf("ERROR : FAILED TO READ THE PACKET\n");
			continue;
		}
		eth = (struct ether_header *)packet;
		arp = (struct ether_arp *)(packet + ETH_HLEN);

		if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
			sprintf(gatewayMac, "%s", ether_ntoa(((struct ether_addr *)arp->arp_sha)));
			break;
		}
	}

	for(i = 0; i < 256; i++){
		command[i] = '\0';
	}
	/* arp -s [gateway ip address] [gateway mac address] */
	sprintf(command, "sudo arp -s %s %s", gatewayIp, gatewayMac);
	system(command);
	return 0;
}
