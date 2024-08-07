#ifndef PACKETSNIFFER_GUI_H
#define PACKETSNIFFER_GUI_H

#include <gtk/gtk.h>
#include <pcap.h>
#include "packet_handler.h"
#include "app_data.h"

void activate(GtkApplication *app, AppData *app_data);
void on_start_button_clicked(GtkButton *button, AppData *app_data);
void on_stop_button_clicked(GtkButton *button, AppData *app_data);


#endif //PACKETSNIFFER_GUI_H
