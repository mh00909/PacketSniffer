#ifndef PACKETSNIFFER_PACKET_HANDLER_H
#define PACKETSNIFFER_PACKET_HANDLER_H

#include <pcap.h>
#include <gtk/gtk.h>
#include "gui.h"
#include "app_data.h"

void update_text_view(AppData *app_data, const char *text);
void update_detail_view(AppData *app_data, const char *text);
void update_stats_view(AppData *app_data);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void save_packet_to_file(const struct pcap_pkthdr *pkthdr, const u_char *packet, FILE *file);
gpointer capture_packets(gpointer data);


#endif //PACKETSNIFFER_PACKET_HANDLER_H
