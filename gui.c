#include "gui.h"
#include <pcap.h>
#include <glib.h>
#include <string.h>
#include "packet_handler.h"
#include "app_data.h"

#define MAX_FILTER_LEN 256


void on_start_button_clicked(GtkButton *button, AppData *app_data) {
    if (app_data->is_capturing) {
        update_text_view(app_data, "Already capturing packets\n");
        return;
    }

    // Pobieranie danych z interfejsu użytkownika
    const char *device = gtk_entry_get_text(GTK_ENTRY(app_data->interface_entry));
    const char *filter_type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox));
    const char *filter_value = gtk_entry_get_text(GTK_ENTRY(app_data->filter_entry));

    // tworzenie wyrażenia filtra
    char filter_exp[MAX_FILTER_LEN] = "";
    if (filter_type != NULL) {
        if (strlen(filter_value) > 0) {
            snprintf(filter_exp, sizeof(filter_exp), "%s %s", filter_type, filter_value);
        } else if (strcmp(filter_type, "udp") == 0 || strcmp(filter_type, "tcp") == 0 || strcmp(filter_type, "icmp") == 0 ||
                   strcmp(filter_type, "broadcast") == 0 || strcmp(filter_type, "multicast") == 0) {
            snprintf(filter_exp, sizeof(filter_exp), "%s", filter_type);
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    // Pobieranie adresu i maski
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        snprintf(errbuf, sizeof(errbuf), "Can't get netmask for device %s\n", device);
        update_text_view(app_data, errbuf);
        net = 0;
        mask = 0;
    }

    // Otwarcie sesji przechwytywania pakietów
    app_data->handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (app_data->handle == NULL) {
        snprintf(errbuf, sizeof(errbuf), "Couldn't open device %s\n", device);
        update_text_view(app_data, errbuf);
        return;
    }



    // Kompilacja i zastosowanie filtra
    if (strlen(filter_exp) > 0) {
        if (pcap_compile(app_data->handle, &fp, filter_exp, 0, net) == -1) {
            snprintf(errbuf, sizeof(errbuf), "Couldn't parse filter: %.200s\n", filter_exp);
            update_text_view(app_data, errbuf);
            return;
        }
        if (pcap_setfilter(app_data->handle, &fp) == -1) {
            snprintf(errbuf, sizeof(errbuf), "Couldn't install filter: %.200s\n", filter_exp);
            update_text_view(app_data, errbuf);
            return;
        }
    }

    // Otwarcie pliku do zapisu pakietów
    app_data->file = fopen("captured_packets.pcap", "wb");
    if (!app_data->file) {
        update_text_view(app_data, "Could not open file to save packets\n");
        return;
    }



    // Resetowanie liczników
    app_data->packet_count = 0;
    app_data->tcp_count = 0;
    app_data->udp_count = 0;
    app_data->icmp_count = 0;
    app_data->other_count = 0;


    // Przechwytywanie pakietów
    app_data->is_capturing = TRUE;
    app_data->packet_count = 0;
    g_thread_new("packet_capture_thread", capture_packets, app_data);
}


void on_stop_button_clicked(GtkButton *button, AppData *app_data) {
    if (app_data->is_capturing) {
        pcap_breakloop(app_data->handle); // przerywa pętlę przechwytywania pakietów
        pcap_close(app_data->handle);
        fclose(app_data->file);
        app_data->is_capturing = FALSE;
        update_text_view(app_data, "Stopped capturing packets\n");
    } else {
        update_text_view(app_data, "Not currently capturing packets\n");
    }
}

// Funkcja inicjalizująca interfejs graficzny
void activate(GtkApplication *app, AppData *app_data) {
    // Utworzenie głównego okna aplikacji
    app_data->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(app_data->window), "Packet Sniffer");
    gtk_window_set_default_size(GTK_WINDOW(app_data->window), 600, 400);

    // Utworzenie siatki układu
    GtkWidget *grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(app_data->window), grid);

    // Dodanie pola tekstowego do wprowadzania interfejsu sieciowego
    GtkWidget *interface_label = gtk_label_new("Interface:");
    gtk_grid_attach(GTK_GRID(grid), interface_label, 0, 0, 1, 1);
    app_data->interface_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), app_data->interface_entry, 1, 0, 1, 1);

    // Dodanie listy rozwijanej do wyboru typu filtra
    GtkWidget *filter_type_label = gtk_label_new("Filter Type:");
    gtk_grid_attach(GTK_GRID(grid), filter_type_label, 0, 1, 1, 1);
    app_data->filter_combobox = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox), "tcp");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox), "udp");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox), "icmp");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox), "port");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox), "host");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_data->filter_combobox), "net");
    gtk_grid_attach(GTK_GRID(grid), app_data->filter_combobox, 1, 1, 1, 1);

    // Dodanie pola tekstowego do wprowadzania wartości filtra
    GtkWidget *filter_value_label = gtk_label_new("Filter Value:");
    gtk_grid_attach(GTK_GRID(grid), filter_value_label, 0, 2, 1, 1);
    app_data->filter_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), app_data->filter_entry, 1, 2, 1, 1);

    // przyciski "Start", "Stop"
    app_data->start_button = gtk_button_new_with_label("Start");
    gtk_grid_attach(GTK_GRID(grid), app_data->start_button, 0, 3, 1, 1);
    g_signal_connect(app_data->start_button, "clicked", G_CALLBACK(on_start_button_clicked), app_data);
    app_data->stop_button = gtk_button_new_with_label("Stop");
    gtk_grid_attach(GTK_GRID(grid), app_data->stop_button, 1, 3, 1, 1);
    g_signal_connect(app_data->stop_button, "clicked", G_CALLBACK(on_stop_button_clicked), app_data);

    // pole tekstowe do wyświetlania wyników
    app_data->output_textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_data->output_textview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app_data->output_textview), FALSE);
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(scrolled_window, TRUE); // Rozszerzenie w pionie
    gtk_widget_set_hexpand(scrolled_window, TRUE); // Rozszerzenie w poziomie
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolled_window), 600);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled_window), 400);
    gtk_container_add(GTK_CONTAINER(scrolled_window), app_data->output_textview);
    gtk_grid_attach(GTK_GRID(grid), scrolled_window, 0, 4, 2, 1);

    // pole tekstowe do wyświetlania szczegółów pakietów
    app_data->detail_textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_data->detail_textview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app_data->detail_textview), FALSE);
    GtkWidget *detail_scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(detail_scrolled_window, TRUE);
    gtk_widget_set_hexpand(detail_scrolled_window, TRUE);
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(detail_scrolled_window), 600);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(detail_scrolled_window), 400);
    gtk_container_add(GTK_CONTAINER(detail_scrolled_window), app_data->detail_textview);
    gtk_grid_attach(GTK_GRID(grid), detail_scrolled_window, 0, 5, 2, 1);


    // pole tekstowe do wyświetlania statystyk
    app_data->stats_textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_data->stats_textview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app_data->stats_textview), FALSE);
    GtkWidget *stats_scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(stats_scrolled_window, TRUE);
    gtk_widget_set_hexpand(stats_scrolled_window, TRUE);
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(stats_scrolled_window), 200);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(stats_scrolled_window), 400);
    gtk_container_add(GTK_CONTAINER(stats_scrolled_window), app_data->stats_textview);
    gtk_grid_attach(GTK_GRID(grid), stats_scrolled_window, 2, 0, 1, 6);


    // Wyświetlenie wszystkich elementów
    gtk_widget_show_all(app_data->window);
}

