#include "ifselectdialog.h"
#include "ui_ifselectdialog.h"

#include <QMessageBox>


#include <stdio.h>

#include "pcap.h"

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
    #include <ws2tcpip.h>
#endif

IfSelectDialog::IfSelectDialog() :
    QDialog( 0, Qt::WindowTitleHint | Qt::WindowSystemMenuHint),
    ui(new Ui::IfSelectDialog),
    dSelected(0)
{
    ui->setupUi(this);

    /* Retrieve the device list */
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        QMessageBox mb(QMessageBox::Critical,
                       QString::fromLocal8Bit("Критическая ошибка"),
                       QString::fromLocal8Bit("Ошибка при вызове pcap_findalldevs: %1").arg(errbuf),
                       QMessageBox::Ok);
        mb.exec();

        //fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    pcap_if_t *d;
    for(d=alldevs; d; d=d->next)
    {
        char *info = (d->description) ? d->description : d->name;
        ui->IfSelectComboBox->addItem(info, d->name);
    }

    if (ui->IfSelectComboBox->count())
        ui->IfSelectComboBox->setCurrentIndex(0);

    // Инициируем выбор интерфейса при первоначальном запуске
    //exec();
}

IfSelectDialog::~IfSelectDialog()
{
    delete ui;

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
}

const char* IfSelectDialog::Selected()
{
    return (dSelected) ? (dSelected->name) : 0;
}

void IfSelectDialog::on_IfSelectComboBox_currentIndexChanged(const QString &)
{
    QString selected;
    if (ui->IfSelectComboBox->currentData().isValid())
        selected = ui->IfSelectComboBox->currentData().toString();

    ui->aboutIfBox->clear();

    pcap_if_t *d;
    for(d=alldevs; d; d=d->next)
    {
        if (selected == d->name)
        {
            dSelected = d;
            ifprint(d);
            break;
        }
    }
}


/* Print all the available information on the given interface */
void IfSelectDialog::ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];

  /* Name */
  ui->aboutIfBox->appendPlainText(d->name);

  /* Description */
  if (d->description)
    ui->aboutIfBox->appendPlainText(QString("\tdescription: %1").arg(d->description));

  /* Loopback Address*/
  ui->aboutIfBox->appendPlainText(QString("\tLoopback: ") + ((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no"));

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    ui->aboutIfBox->appendPlainText(QString("\n\tAddress Family: #%1").arg(a->addr->sa_family));

    switch(a->addr->sa_family)
    {
      case AF_INET:
        ui->aboutIfBox->appendPlainText("\tAddress Family Name: AF_INET");
        if (a->addr)
          ui->aboutIfBox->appendPlainText(QString("\tAddress: ") + iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          ui->aboutIfBox->appendPlainText(QString("\tNetmask: ") + iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          ui->aboutIfBox->appendPlainText(QString("\tBroadcast Address: ") + iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          ui->aboutIfBox->appendPlainText(QString("\tDestination Address: ") + iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

      case AF_INET6:
        ui->aboutIfBox->appendPlainText("\tAddress Family Name: AF_INET6");
        if (a->addr)
          ui->aboutIfBox->appendPlainText(QString("\tAddress: ") + ip6tos(a->addr, ip6str, sizeof(ip6str)));
       break;

      default:
        ui->aboutIfBox->appendPlainText("\tAddress Family Name: Unknown");
        break;
    }
  }
}



/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char* IfSelectDialog::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which], sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* IfSelectDialog::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif


    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        addrlen,
        NULL,
        0,
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}

