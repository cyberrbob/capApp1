#ifndef IFSELECTDIALOG_H
#define IFSELECTDIALOG_H

#include <QDialog>
#include "pcap.h"

namespace Ui {
class IfSelectDialog;
}

class IfSelectDialog : public QDialog
{
    Q_OBJECT

public:
    static IfSelectDialog& getInstance()
    {
        static IfSelectDialog dlg;
        return dlg;
    }

    const char *Selected();

private slots:
    void on_IfSelectComboBox_currentIndexChanged( const QString& );

private:
    IfSelectDialog();
    ~IfSelectDialog();

    Ui::IfSelectDialog *ui;

    pcap_if_t *alldevs;
    pcap_if_t *dSelected;

    void ifprint(pcap_if_t *d);
    char* iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
};

#endif // IFSELECTDIALOG_H
