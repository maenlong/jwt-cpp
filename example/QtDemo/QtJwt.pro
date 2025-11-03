#-------------------------------------------------
#
# Project created by QtCreator 2018-09-25T10:03:26
#
#-------------------------------------------------

QT += core network
QT -= gui

TEMPLATE = app

#-----------------------------------------------------------------------

HEADERS  += \
    include/jwt-cpp/base.h \
    include/jwt-cpp/jwt.h \
    include/picojson/picojson.h \
    qjwt.h
	

SOURCES += \
    main.cpp \
    qjwt.cpp

FORMS += \

#-----------------------------------------------------------------------

win32:{

    QMAKE_CXXFLAGS += /utf-8

    CONFIG(debug, debug|release) {
        DESTDIR =$$PWD/build_debug/
    } else {
        DESTDIR =$$PWD/build_release/
    }

# 定义文件或文件夹路径
LIB_FILE_PATH = $$PWD/lib/VC/x86/MD/libcrypto.lib

# 检查文件或文件夹是否存在
exists($$LIB_FILE_PATH) {
    # 如果存在，包含相应的 .pri 文件
    message("Tips: Find the file or folder '$$LIB_FILE_PATH' include it!")
    DEFINES += HAVE_OPENSSL_LIB
} else {
    # 如果不存在，打印错误信息
    message("Error: The file or folder '$$LIB_FILE_PATH' does not exist!")
    DEFINES -= HAVE_OPENSSL_LIB
}

contains(DEFINES, HAVE_OPENSSL_LIB) {
    CONFIG(release, debug|release): {
        INCLUDEPATH += $$PWD/include
        DEPENDPATH += $$PWD/lib/VC/x86/MD

        LIBS += -L$$PWD/lib/VC/x86/MD/ -llibssl
        LIBS += -L$$PWD/lib/VC/x86/MD/ -llibcrypto

        dstDir = $$PWD/build_release/
        dstDir = $$replace(dstDir, /, \\)

        sdkdir = $$PWD/bin/
        sdkdir = $$replace(sdkdir, /, \\)

        QMAKE_PRE_LINK  += xcopy $$sdkdir $$dstDir /e /r /q /y
        message(COPY_FILE_SDK  $$sdkdir->$$dstDir)
    }
    else::CONFIG(debug, debug|release): {
        INCLUDEPATH += $$PWD/include
        DEPENDPATH += $$PWD/lib/VC/x86/MD

        LIBS += -L$$PWD/lib/VC/x86/MD/ -llibssl
        LIBS += -L$$PWD/lib/VC/x86/MD/ -llibcrypto

        dstDir = $$PWD/build_debug/
        dstDir = $$replace(dstDir, /, \\)

        sdkdir = $$PWD/bin/
        sdkdir = $$replace(sdkdir, /, \\)

        QMAKE_PRE_LINK  += xcopy $$sdkdir $$dstDir /e /r /q /y
        message(COPY_FILE_SDK  $$sdkdir->$$dstDir)
    }
}
}

