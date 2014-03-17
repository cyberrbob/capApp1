#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "pcap.h"
#include <QMainWindow>
#include <QTextEdit>
#include <QLineEdit>
#include <QVector>

#include <thread>
#include <mutex>
#include <queue>
#include <string>

#include "qwt_plot.h"
#include "qwt_plot_curve.h"

#include "CurveDataProvider.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void LogMessage( QString );

    std::queue<std::string> msgQueue;
    std::queue<std::vector<u_char>> dataQueue;
    std::mutex msgQueueMutex;
    pcap_t *adhandle;
    QString filterString;

protected:
    void closeEvent(QCloseEvent *event);
    void resizeEvent( QResizeEvent *event);

private slots:
    void on_actionInterfaceSelect_triggered();
    void on_actionSetFilter_triggered();

private:
    void checkQueue();
    bool stopCapture();
    bool startCapture();

private:
    Ui::MainWindow *ui;
    QTextEdit *pLogView;
    QLineEdit filterView;
    std::thread capThread;
    QwtPlot *qplot;
    QwtPlotCurve *curve;
    curveProvider curve_provider;
};

#endif // MAINWINDOW_H
