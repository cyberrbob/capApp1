#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "ui_filterdialog.h"

#include "ifselectdialog.h"
#include <QMessageBox>
#include <QTimer>
#include <type_traits>
#include <thread>
#include <QVBoxLayout>
#include <QDockWidget>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QTimer *refreshTim = new QTimer(this);
    connect(refreshTim, &QTimer::timeout, this, &MainWindow::checkQueue);
    refreshTim->start(10);

    QDockWidget *pDockLogView = new QDockWidget("Экран сообщений", this);
    pLogView = new QTextEdit(this);
    pLogView->setReadOnly(true);
    pDockLogView->setWidget(pLogView);
    QAction *pToggleLogView = pDockLogView->toggleViewAction();
    pToggleLogView->setIcon(QIcon(QStringLiteral(":/icons/log.png")));
    ui->mainToolBar->addAction(pToggleLogView);
    addDockWidget(Qt::RightDockWidgetArea, pDockLogView);

    qplot = new QwtPlot;
    setCentralWidget(qplot);

    //qplot->setTitle("A-Scan demo");
    qplot->setCanvasBackground( Qt::black );
    qplot->setAxisTitle( QwtPlot::yLeft, "Амплитуда,АЦП");
    qplot->setAxisTitle( QwtPlot::xBottom, "Время,мС");
    qplot->setAxisScale( QwtPlot::yLeft, 0, 255);
    //qplot->setAxisScale( QwtPlot::xBottom, 0, 200);

    curve = new QwtPlotCurve;
    curve->setPen( Qt::blue, 1 ); // цвет и толщина кривой
    curve->setRenderHint( QwtPlotItem::RenderAntialiased, true ); // сглаживание

//    QPolygonF points;
//    points << QPoint(10, 10) << QPoint(50, 50) << QPoint(60, 80) << QPoint(80, 200) << QPoint( 150, 80) << QPoint(190, 20);
//    curve->setSamples(points);

    curve->setSamples(&curve_provider);
    curve->attach(qplot);

    // Хватать пакеты только с нулевым заголовком
    filterString = "ether proto 0x0000";

    ui->statusBar->showMessage("Application started", 2000);
}

MainWindow::~MainWindow()
{
    stopCapture();
    delete ui;
}

void MainWindow::LogMessage(QString msg)
{
    pLogView->append(msg);
    //ui->logView->verticalScrollBar()->setValue(this->verticalScrollBar()->maximum());
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    Q_UNUSED(event);

    if (width() > 100)
    {
        qplot->setAxisScale( QwtPlot::xBottom, 0, width() - 100);
        qplot->replot();
    }
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /*
     * unused parameters
     */
    //(void)(param);
    (void)(pkt_data);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);


    //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    std::string str = timestr;
    str += ", " + std::to_string(header->ts.tv_usec) + " len:" + std::to_string(header->len);

    std::vector<u_char> data;
    data.resize(header->len);
    memcpy(data.data(), pkt_data, header->len);

    MainWindow *pMainWnd = reinterpret_cast<MainWindow*>(param);
    if (pMainWnd)
    {
        pMainWnd->msgQueueMutex.lock();
        pMainWnd->dataQueue.push(data);
        //pMainWnd->msgQueue.push(str);
        pMainWnd->msgQueueMutex.unlock();
    }
}

void startcap_thread( const char* device, u_char *userParam)
{
    MainWindow *pMainWnd = reinterpret_cast<MainWindow*>(userParam);
    if (nullptr == pMainWnd)
        return;

    char errbuf[PCAP_ERRBUF_SIZE] = "\0";
    pcap_t *adhandle= pcap_open_live(device,65536, 1, 1000, errbuf);
    if (NULL == adhandle)
    {
        QMessageBox mb(QMessageBox::Critical, QString::fromLocal8Bit("Ошибка запуска"),
                       QString::fromLocal8Bit("Ошибка при запуске драйвера: %1").arg(errbuf),
                       QMessageBox::Ok);
        mb.exec();
        return;
    }

    if (! pMainWnd->filterString.isEmpty())
    {
        const char *sFilter = pMainWnd->filterString.toLocal8Bit().data();
        //pMainWnd->msgQueue.push(std::string("Trying to set filter: ") + sFilter);

        bpf_program filter;
        if (0 > pcap_compile( adhandle,
                      &filter, //out
                      sFilter, //filter string (not ip)
                      1, //optimization enabled
                      0))
        {
            pMainWnd->msgQueue.push("pcap_compile ret error!");
        }

        if (pcap_setfilter(adhandle, &filter) < 0)
        {
            pMainWnd->msgQueue.push("Error setting the filter!");
            /* Free the device list */
            pcap_close(adhandle);
            return;
        }
    }

    pMainWnd->adhandle = adhandle;
    pMainWnd->msgQueue.push("packet capture started.");

    /* Starts loop to recieve data*/
    pcap_loop(adhandle, 0, packet_handler, userParam);

    pcap_close(adhandle);

    pMainWnd->msgQueue.push("packet capture stopped.");
}

void MainWindow::on_actionInterfaceSelect_triggered()
{
    if (QDialog::Accepted == IfSelectDialog::getInstance().exec())
    {
        stopCapture();
        startCapture();
    }
}

bool MainWindow::stopCapture()
{
    if (capThread.joinable())
    {
        pcap_breakloop(adhandle);
        capThread.detach();
        return true;
    }
    return false;
}

bool MainWindow::startCapture()
{
    const char *device = IfSelectDialog::getInstance().Selected();
    if (device)
    {
        /* start the capture */
        capThread = std::thread(startcap_thread, device, reinterpret_cast<u_char*>(this));
        ui->statusBar->showMessage(QString("capture started:") + device, 10000);
        return true;
    }
    return false;
}

void MainWindow::on_actionSetFilter_triggered()
{
    Ui::FilterDialog filterUi;
    QDialog filterDlg(0, Qt::WindowTitleHint | Qt::WindowSystemMenuHint);
    filterUi.setupUi(&filterDlg);
    filterUi.lineEdit->setText(filterString);

    if (filterDlg.exec() == QDialog::Accepted)
    {
        filterString = filterUi.lineEdit->text();
        if (stopCapture())
            startCapture();
    }
}

void MainWindow::checkQueue()
{
    std::string msg;
    std::vector<u_char> data;

    msgQueueMutex.lock();
    if (! msgQueue.empty())
    {
        msg = msgQueue.front();
        msgQueue.pop();
    }
    if (! dataQueue.empty())
    {
        data.swap(dataQueue.front());
        dataQueue.pop();
    }
    msgQueueMutex.unlock();

    if (! msg.empty())
        LogMessage(QString::fromStdString(msg));

    if (! data.empty())
    {
        curve_provider.setSamples(data);
        //qplot->replot();
        QMetaObject::invokeMethod( qplot->canvas(), "replot", Qt::QueuedConnection );
    }
}


