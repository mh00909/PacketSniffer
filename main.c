#include <string.h>
#include <gtk/gtk.h>
#include "packet_handler.h"
#include "gui.h"
#include "app_data.h"

#define MAX_FILTER_LEN 256

struct AppData ;

int main(int argc, char **argv) {
    GtkApplication *app;
    int status; // kod zakończenia aplikacji
    AppData app_data = {0};

    app = gtk_application_new("com.example.PacketSniffer", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), &app_data); // łączy sygnał activate z funkcją activate
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app); // zwolnienie zasobów

    return status;
}
