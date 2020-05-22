TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    cmdline.c

HEADERS += \
    cmdline.h \
    dns_client.h
