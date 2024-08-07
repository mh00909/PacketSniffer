#ifndef PACKETSNIFFER_APP_DATA_H
#define PACKETSNIFFER_APP_DATA_H

#include <gtk/gtk.h>
#include <pcap.h>

typedef struct {
    GtkWidget *window; // główne okno aplikacji
    GtkWidget *start_button;
    GtkWidget *stop_button;
    GtkWidget *interface_entry; // wprowadzana nazwa interfejsu sieciowego
    GtkWidget *filter_entry; // wprowadzana nazwa filtru
    GtkWidget *filter_combobox; // lista rozwijana dla wyboru filtra
    GtkWidget *output_textview; // wyświetlane pakiety
    GtkWidget *detail_textview;
    GtkWidget *stats_textview; // wyświetlane statystyki
    pcap_t *handle; // do zarządzania sesją
    FILE *file; // zapisywane pakiety
    gboolean is_capturing;
    guint packet_count;
    guint tcp_count;
    guint udp_count;
    guint icmp_count;
    guint other_count;
} AppData;


#endif //PACKETSNIFFER_APP_DATA_H
