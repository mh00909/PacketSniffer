#include "packet_handler.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <time.h>
#include <glib.h>
#include "gui.h"
#include "app_data.h"

typedef struct { // do aktualizacji widoku tekstowego
    AppData *app_data;
    char *text;
} UpdateTextViewData;

gboolean update_text_view_idle(gpointer user_data) {
    UpdateTextViewData *data = (UpdateTextViewData *)user_data;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(data->app_data->output_textview));
    if (buffer == NULL) {
        g_free(data->text);
        g_free(data);
        return FALSE;
    }
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert(buffer, &end, data->text, -1); // wstawia tekst na koniec bufora
    g_free(data->text);
    g_free(data);
    return FALSE; // nie powinna być ponownie wywoływana
}
// alokuje pamięć dla UpdateTextViewData, dodaje update_text_view_idle do głównej pętli
void update_text_view(AppData *app_data, const char *text) {
    UpdateTextViewData *data = g_malloc(sizeof(UpdateTextViewData));
    data->app_data = app_data;
    data->text = g_strdup(text);
    g_idle_add(update_text_view_idle, data);
}

gboolean update_detail_view_idle(gpointer user_data) {
    UpdateTextViewData *data = (UpdateTextViewData *)user_data;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(data->app_data->detail_textview));
    if (buffer == NULL) {
        g_free(data->text);
        g_free(data);
        return FALSE;
    }
    gtk_text_buffer_set_text(buffer, data->text, -1);
    g_free(data->text);
    g_free(data);
    return FALSE;
}

void update_detail_view(AppData *app_data, const char *text) {
    UpdateTextViewData *data = g_malloc(sizeof(UpdateTextViewData));
    data->app_data = app_data;
    data->text = g_strdup(text);
    g_idle_add(update_detail_view_idle, data);
}

gboolean update_stats_view_idle(gpointer user_data) {
    UpdateTextViewData *data = (UpdateTextViewData *)user_data;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(data->app_data->stats_textview));
    if (buffer == NULL) {
        g_free(data->text);
        g_free(data);
        return FALSE;
    }
    gtk_text_buffer_set_text(buffer, data->text, -1);
    g_free(data->text);
    g_free(data);
    return FALSE;
}

void update_stats_view(AppData *app_data) {
    char stats_buffer[256];
    snprintf(stats_buffer, sizeof(stats_buffer),
             "TCP: %u\nUDP: %u\nICMP: %u\nOther: %u\n",
             app_data->tcp_count,
             app_data->udp_count,
             app_data->icmp_count,
             app_data->other_count);
    UpdateTextViewData *data = g_malloc(sizeof(UpdateTextViewData));
    data->app_data = app_data;
    data->text = g_strdup(stats_buffer);
    g_idle_add(update_stats_view_idle, data);
}

// Funkcja zapisująca przechwycone pakiety do pliku
void save_packet_to_file(const struct pcap_pkthdr *pkthdr, const u_char *packet, FILE *file) {
    fwrite(&pkthdr->ts, sizeof(struct timeval), 1, file);
    fwrite(&pkthdr->caplen, sizeof(pkthdr->caplen), 1, file);
    fwrite(&pkthdr->len, sizeof(pkthdr->len), 1, file);
    fwrite(packet, pkthdr->caplen, 1, file);
}



// Funkcja obsługująca przechwycone pakiety
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    AppData *app_data = (AppData *)user_data;

    if (pkthdr->len < 14) {
        update_text_view(app_data, "Packet too short to contain an Ethernet header\n");
        return;
    }

    struct ip *iph = (struct ip *)(packet + 14); // nagłówek Ethernet - 14 bajtów

    // czy wystarczająca długość pakietu
    if (pkthdr->len < (14 + sizeof(struct ip))) {
        return;
    }
    if (iph->ip_hl < 5) { // czy odpowiednia długość nagłówka
        update_text_view(app_data, "Invalid IP header length\n");
        return;
    }
    // sprawdzenie wersji IP
    if (iph->ip_v != 4) {
        update_text_view(app_data, "Not an IPv4 packet\n");
        return;
    }
    // walidacja długości pakietu
    unsigned short iphdr_len = iph->ip_hl * 4;
    unsigned short total_len = ntohs(iph->ip_len);
    if (total_len < iphdr_len || pkthdr->len < (14 + total_len)) { // całkowita długość < długość nagłówka
        update_text_view(app_data, "Invalid IP packet length\n");
        return;
    }

    char buffer[256];
    snprintf(buffer, sizeof(buffer), "\nPacket captured:\nTimestamp: %sSource IP: %s\nDestination IP: %s\n",
             ctime((const time_t *)&pkthdr->ts.tv_sec), inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));
    update_text_view(app_data, buffer);


    // sprawdzenie protokołu
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
        snprintf(buffer, sizeof(buffer), "Protocol: TCP\nSource Port: %d\nDestination Port: %d\n",
                 ntohs(tcph->source), ntohs(tcph->dest));
        app_data->tcp_count++;
    } else if (iph->ip_p == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);
        snprintf(buffer, sizeof(buffer), "Protocol: UDP\nSource Port: %d\nDestination Port: %d\n",
                 ntohs(udph->source), ntohs(udph->dest));
        app_data->udp_count++;
    } else if (iph->ip_p == IPPROTO_ICMP) {
        snprintf(buffer, sizeof(buffer), "Protocol: ICMP\n");
        app_data->icmp_count++;
    } else {
        snprintf(buffer, sizeof(buffer), "Protocol: Other (%d)\n", iph->ip_p);
        app_data->other_count++;
    }
    update_text_view(app_data, buffer);

    // wyświetlenie pierwszych 16 bajtów danych
    update_text_view(app_data, "Payload:\n");
    for (int i = 0; i < 16 && (14 + iph->ip_hl * 4 + i) < pkthdr->len; i++) {
        snprintf(buffer, sizeof(buffer), "%02x ", packet[14 + iph->ip_hl * 4 + i]);
        update_text_view(app_data, buffer);
    }
    update_text_view(app_data, "\n");

    // Zapis pakietu do pliku
    if (app_data->file) {
        save_packet_to_file(pkthdr, packet, app_data->file);
    }

    // Aktualizacja licznika pakietów
    app_data->packet_count++;
    snprintf(buffer, sizeof(buffer), "Total packets captured: %u\n", app_data->packet_count);
    update_text_view(app_data, buffer);


    // Aktualizacja szczegółowego widoku pakietu
    char detail_buffer[1024];
    snprintf(detail_buffer, sizeof(detail_buffer),
             "Full Packet Details:\n"
             "Timestamp: %.24s\n"
             "Source IP: %s\n"
             "Destination IP: %s\n"
             "Protocol: %s\n"
             "IP Header Length: %d bytes\n"
             "Total Length: %d bytes\n"
             "Time To Live: %d\n"
             "Checksum: %d\n",
             ctime((const time_t *)&pkthdr->ts.tv_sec),
             inet_ntoa(iph->ip_src),
             inet_ntoa(iph->ip_dst),
             iph->ip_p == IPPROTO_TCP ? "TCP" :
             iph->ip_p == IPPROTO_UDP ? "UDP" :
             iph->ip_p == IPPROTO_ICMP ? "ICMP" : "Other",
             iph->ip_hl * 4,
             ntohs(iph->ip_len),
             iph->ip_ttl,
             ntohs(iph->ip_sum));


    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
        int len = snprintf(detail_buffer + strlen(detail_buffer), sizeof(detail_buffer) - strlen(detail_buffer),
                           "Source Port: %d\n"
                           "Destination Port: %d\n"
                           "Sequence Number: %u\n"
                           "Acknowledgment Number: %u\n"
                           "TCP Header Length: %d bytes\n"
                           "Flags: %d\n"
                           "Window Size: %d\n"
                           "Checksum: %d\n"
                           "Urgent Pointer: %d\n",
                           ntohs(tcph->source),
                           ntohs(tcph->dest),
                           ntohl(tcph->seq),
                           ntohl(tcph->ack_seq),
                           tcph->doff * 4,
                           tcph->th_flags,
                           ntohs(tcph->window),
                           ntohs(tcph->check),
                           ntohs(tcph->urg_ptr));
        if (len < 0 || len >= (sizeof(detail_buffer) - strlen(detail_buffer))) {
            // Błąd lub przekroczenie bufora
            return;
        }
    } else if (iph->ip_p == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);
        int len = snprintf(detail_buffer + strlen(detail_buffer), sizeof(detail_buffer) - strlen(detail_buffer),
                           "Source Port: %d\n"
                           "Destination Port: %d\n"
                           "Length: %d bytes\n"
                           "Checksum: %d\n",
                           ntohs(udph->source),
                           ntohs(udph->dest),
                           ntohs(udph->len),
                           ntohs(udph->check));
        if (len < 0 || len >= (sizeof(detail_buffer) - strlen(detail_buffer))) {
            return;
        }
    }


    update_detail_view(app_data, detail_buffer);
    update_stats_view(app_data);
}
gpointer capture_packets(gpointer data) { // uruchamiana w osobnym wątku
    AppData *app_data = (AppData *)data;
    pcap_loop(app_data->handle, 0, packet_handler, (u_char *)app_data);
    return NULL;
}