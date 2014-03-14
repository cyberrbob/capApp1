#-------------------------------------------------
#
# Project created by QtCreator 2014-03-10T10:07:42
#
#-------------------------------------------------

QT       += core gui

QMAKE_CXXFLAGS += -std=c++11

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = capApp1
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    ifselectdialog.cpp

HEADERS  += mainwindow.h \
    ifselectdialog.h \
    CurveDataProvider.h

FORMS    += mainwindow.ui \
    ifselectdialog.ui \
    filterdialog.ui

unix:!macx|win32: LIBS += -L$$PWD/libs/winpcap/ -lwpcap

INCLUDEPATH += $$PWD/libs/winpcap/Include
DEPENDPATH += $$PWD/libs/winpcap

RESOURCES += \
    actionIcons.qrc

LIBS += -lWs2_32

INCLUDEPATH += $$PWD/libs/qwt/inc

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/libs/qwt/ -lqwt
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/libs/qwt/ -lqwtd
else:unix:!macx: LIBS += -L$$PWD/libs/qwt/ -lqwt

INCLUDEPATH += $$PWD/libs/qwt
DEPENDPATH += $$PWD/libs/qwt

win32:DEFINES += WIN32
