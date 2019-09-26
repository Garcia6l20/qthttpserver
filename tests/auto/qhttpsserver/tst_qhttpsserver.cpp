/****************************************************************************
**
** Copyright (C) 2019 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the Qthttpsserver module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:GPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3 or (at your option) any later version
** approved by the KDE Free Qt Foundation. The licenses are as published by
** the Free Software Foundation and appearing in the file LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include <QtHttpServer/qhttpserver.h>
#include <QtHttpServer/qhttpserverrequest.h>
#include <QtHttpServer/qhttpserverrouterrule.h>

#include <private/qhttpserverrouterrule_p.h>
#include <private/qhttpserverliterals_p.h>

#include <QtTest/qtest.h>
#include <QtTest/qsignalspy.h>

#include <QtCore/qurl.h>
#include <QtCore/qstring.h>
#include <QtCore/qlist.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qmetaobject.h>
#include <QtCore/qjsonobject.h>
#include <QtCore/qjsonvalue.h>
#include <QtCore/qjsonarray.h>

#include <QtNetwork/qnetworkaccessmanager.h>
#include <QtNetwork/qnetworkreply.h>
#include <QtNetwork/qnetworkrequest.h>

QT_BEGIN_NAMESPACE

static const char g_privateKey[] = R"(-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDykG51ZjNJra8iS27g3DJojH1qG8C3Z+Avo5U6Qz6NkOsjvr22
gXqOS4uwVUXdCAKxsP0Wwn2zGz5vxGpLPVKtbAmaqHYZuipMG/Qun3t+QYBgR+9t
lmHdI8TNP2Om8stDO5uQyBH7DcMjPyIgpfc8fBoNLhCn4oC2n6JK9EMuhQIDAQAB
AoGAUHTLzrEJjgTINI3kxz0Ck18WMl3mPG9+Ew8lbl/jnb1V4VNhReoIpq40NVbz
h28ixaG5MRVt8Dy3Jwd1YmOCylHSujdFQ2u0pcHFmERgDS2bOMwMTRoFOj2qgMGS
9SM+iXlPY5AQY8nEg7rLjMSfaC/8Hq4RXpkj4PeHh6N7AzkCQQD++HzM3xBr+Gvh
zco9Kt8IiKNlfeiA5gUQq1UPJzcWIEgW1Tgr5UzMUOcZ0HfYwhqL3+wMhzN4sba+
1plB1QRXAkEA84sfM0jm9BRSqtYTPlhsYAmuPjeo24Pxel8ijEkToAu0ppEC6AQ3
zfwZD0ISgaWQ7af5TN/RCsoNVX79twP6gwJBANbtB+Z6shERm38ARdZB6Tf8ViAb
fn4JZ4OhqVXYrKrOE3aLzYnTBGXGXMh53kytcksuOoBlB5JZ274Kj63arokCQFPo
9xMAZzJpXiImJ/MvHAfqzfH501/ukeCLrqeO9ggKgG9zPwEZkvCRj0DGjwHEPa7k
VOy7oJaLDxUJ7/iCkmkCQQCtTLsvDbGH4tyFK5VIPJbUcccIib+dTzSTeONdUxKL
Yk+C6o7OpaUWX+ikp4Ow/6iHOAgXaeA2OolDer/NspUy
-----END RSA PRIVATE KEY-----)";

static const char g_certificate[] = R"(-----BEGIN CERTIFICATE-----
MIICrjCCAhegAwIBAgIUcuXjCSkJ2+v/Rqv/UHThTRGFlpswDQYJKoZIhvcNAQEL
BQAwaDELMAkGA1UEBhMCRlIxDzANBgNVBAgMBkZyYW5jZTERMA8GA1UEBwwIR3Jl
bm9ibGUxFjAUBgNVBAoMDVF0Q29udHJpYnV0b3IxHTAbBgNVBAMMFHFodHRwc3Nl
cnZlcnRlc3QuY29tMCAXDTE5MDkyNjA4NTc1MloYDzIyNTUwMzEzMDg1NzUyWjBo
MQswCQYDVQQGEwJGUjEPMA0GA1UECAwGRnJhbmNlMREwDwYDVQQHDAhHcmVub2Js
ZTEWMBQGA1UECgwNUXRDb250cmlidXRvcjEdMBsGA1UEAwwUcWh0dHBzc2VydmVy
dGVzdC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPKQbnVmM0mtryJL
buDcMmiMfWobwLdn4C+jlTpDPo2Q6yO+vbaBeo5Li7BVRd0IArGw/RbCfbMbPm/E
aks9Uq1sCZqodhm6Kkwb9C6fe35BgGBH722WYd0jxM0/Y6byy0M7m5DIEfsNwyM/
IiCl9zx8Gg0uEKfigLafokr0Qy6FAgMBAAGjUzBRMB0GA1UdDgQWBBTDMYCcl2jz
UUWByEzTj5Ew/LWkeDAfBgNVHSMEGDAWgBTDMYCcl2jzUUWByEzTj5Ew/LWkeDAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAMNupAOXoBih6RvuAn3w
W8jOIZfkn5CMYdbUSndY/Wrt4p07M8r9uFPWG4bXSwG6n9Nzl75X9b0ka/jqPjQ3
X769simPygCblBp2xwE6w14aHEBx4kcF1p2QbC1vHynszJxyVLvHqUjuJwVAoPrM
Imy6LOiw2tRTHPsj7UH16M6C
-----END CERTIFICATE-----)";

class tst_QHttpsServer final : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void routeGet_data();
    void routeGet();
    void routePost_data();
    void routePost();

private:
    void checkReply(QNetworkReply *reply, const QString &response);

private:
    QHttpServer httpsserver;
    QString urlBase;
    QNetworkAccessManager networkAccessManager;
};

void tst_QHttpsServer::initTestCase()
{
    httpsserver.sslSetup(QSslCertificate(g_certificate), QSslKey(g_privateKey, QSsl::Rsa));

    QList<QSslError> expectedSslErrors;
    expectedSslErrors.append(QSslError(QSslError::SelfSignedCertificate, QSslCertificate(g_certificate)));
    expectedSslErrors.append(QSslError(QSslError::HostNameMismatch, QSslCertificate(g_certificate)));

    connect(&networkAccessManager, &QNetworkAccessManager::sslErrors, [expectedSslErrors](QNetworkReply *reply, const QList<QSslError>& errors) {
        for (const auto& error: errors) {
            for (const auto& expectedError: expectedSslErrors) {
                if (error.error() != expectedError.error() &&
                    error.certificate() != expectedError.certificate()) {
                    qCritical() << "Got unexpected ssl error:" << error << error.certificate();
                }
            }
        }
        reply->ignoreSslErrors(expectedSslErrors);
    });

    httpsserver.route("/test", [] (QHttpServerResponder &&responder) {
        responder.write("test msg",
                        QHttpServerLiterals::contentTypeTextHtml());
    });

    httpsserver.route("/", QHttpServerRequest::Method::Get, [] () {
        return "Hello world get";
    });

    httpsserver.route("/", QHttpServerRequest::Method::Post, [] () {
        return "Hello world post";
    });

    httpsserver.route("/post-and-get", "GET|POST", [] (const QHttpServerRequest &request) {
        if (request.method() == QHttpServerRequest::Method::Get)
            return "Hello world get";
        else if (request.method() == QHttpServerRequest::Method::Post)
            return "Hello world post";

        return "This should not work";
    });

    httpsserver.route("/any", "All", [] (const QHttpServerRequest &request) {
        static const int index = QHttpServerRequest::staticMetaObject.indexOfEnumerator("Method");
        if (index == -1)
            return "Error: Could not find enum Method";

        static const QMetaEnum en = QHttpServerRequest::staticMetaObject.enumerator(index);
        return en.valueToKey(static_cast<int>(request.method()));
    });

    httpsserver.route("/page/", [] (const qint32 number) {
        return QString("page: %1").arg(number);
    });

    httpsserver.route("/page/<arg>/detail", [] (const quint32 number) {
        return QString("page: %1 detail").arg(number);
    });

    httpsserver.route("/user/", [] (const QString &name) {
        return QString("%1").arg(name);
    });

    httpsserver.route("/user/<arg>/", [] (const QString &name, const QByteArray &ba) {
        return QString("%1-%2").arg(name).arg(QString::fromLatin1(ba));
    });

    httpsserver.route("/test/", [] (const QUrl &url) {
        return QString("path: %1").arg(url.path());
    });

    httpsserver.route("/api/v", [] (const float api) {
        return QString("api %1v").arg(api);
    });

    httpsserver.route("/api/v<arg>/user/", [] (const float api, const quint64 user) {
        return QString("api %1v, user id - %2").arg(api).arg(user);
    });

    httpsserver.route("/api/v<arg>/user/<arg>/settings", [] (const float api, const quint64 user,
                                                             const QHttpServerRequest &request) {
        const auto &role = request.query().queryItemValue(QString::fromLatin1("role"));
        const auto &fragment = request.url().fragment();

        return QString("api %1v, user id - %2, set settings role=%3#'%4'")
                   .arg(api).arg(user).arg(role, fragment);
    });

    urlBase = QStringLiteral("https://localhost:%1%2").arg(httpsserver.listen(QHostAddress::LocalHost, 4443));
}

void tst_QHttpsServer::routeGet_data()
{
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("code");
    QTest::addColumn<QString>("type");
    QTest::addColumn<QString>("body");

    QTest::addRow("hello world")
        << "/"
        << 200
        << "text/plain"
        << "Hello world get";

    QTest::addRow("test msg")
        << "/test"
        << 200
        << "text/html"
        << "test msg";

    QTest::addRow("not found")
        << "/not-found"
        << 404
        << "application/x-empty"
        << "";

    QTest::addRow("arg:int")
        << "/page/10"
        << 200
        << "text/plain"
        << "page: 10";

    QTest::addRow("arg:-int")
        << "/page/-10"
        << 200
        << "text/plain"
        << "page: -10";

    QTest::addRow("arg:uint")
        << "/page/10/detail"
        << 200
        << "text/plain"
        << "page: 10 detail";

    QTest::addRow("arg:-uint")
        << "/page/-10/detail"
        << 404
        << "application/x-empty"
        << "";

    QTest::addRow("arg:string")
        << "/user/test"
        << 200
        << "text/plain"
        << "test";

    QTest::addRow("arg:string")
        << "/user/test test ,!a+."
        << 200
        << "text/plain"
        << "test test ,!a+.";

    QTest::addRow("arg:string,ba")
        << "/user/james/bond"
        << 200
        << "text/plain"
        << "james-bond";

    QTest::addRow("arg:url")
        << "/test/api/v0/cmds?val=1"
        << 200
        << "text/plain"
        << "path: api/v0/cmds";

    QTest::addRow("arg:float 5.1")
        << "/api/v5.1"
        << 200
        << "text/plain"
        << "api 5.1v";

    QTest::addRow("arg:float 5.")
        << "/api/v5."
        << 200
        << "text/plain"
        << "api 5v";

    QTest::addRow("arg:float 6.0")
        << "/api/v6.0"
        << 200
        << "text/plain"
        << "api 6v";

    QTest::addRow("arg:float,uint")
        << "/api/v5.1/user/10"
        << 200
        << "text/plain"
        << "api 5.1v, user id - 10";

    QTest::addRow("arg:float,uint,query")
        << "/api/v5.2/user/11/settings?role=admin" << 200
        << "text/plain"
        << "api 5.2v, user id - 11, set settings role=admin#''";

    // The fragment isn't actually sent via HTTP (it's information for the user agent)
    QTest::addRow("arg:float,uint, query+fragment")
        << "/api/v5.2/user/11/settings?role=admin#tag"
        << 200 << "text/plain"
        << "api 5.2v, user id - 11, set settings role=admin#''";

    QTest::addRow("post-and-get, get")
        << "/post-and-get"
        << 200
        << "text/plain"
        << "Hello world get";

    QTest::addRow("invalid-rule-method, get")
        << "/invalid-rule-method"
        << 404
        << "application/x-empty"
        << "";

    QTest::addRow("any, get")
        << "/any"
        << 200
        << "text/plain"
        << "Get";
}

void tst_QHttpsServer::routeGet()
{
    QFETCH(QString, url);
    QFETCH(int, code);
    QFETCH(QString, type);
    QFETCH(QString, body);

    const QUrl requestUrl(urlBase.arg(url));
    auto reply = networkAccessManager.get(QNetworkRequest(requestUrl));

    QTRY_VERIFY(reply->isFinished());

    QCOMPARE(reply->header(QNetworkRequest::ContentTypeHeader), type);
    QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), code);
    QCOMPARE(reply->readAll().trimmed(), body);
}


void tst_QHttpsServer::routePost_data()
{
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("code");
    QTest::addColumn<QString>("type");
    QTest::addColumn<QString>("data");
    QTest::addColumn<QString>("body");

    QTest::addRow("hello world")
        << "/"
        << 200
        << "text/plain"
        << ""
        << "Hello world post";

    QTest::addRow("post-and-get, post")
        << "/post-and-get"
        << 200
        << "text/plain"
        << ""
        << "Hello world post";

    QTest::addRow("any, post")
        << "/any"
        << 200
        << "text/plain"
        << ""
        << "Post";
}

void tst_QHttpsServer::routePost()
{
    QFETCH(QString, url);
    QFETCH(int, code);
    QFETCH(QString, type);
    QFETCH(QString, data);
    QFETCH(QString, body);

    QNetworkRequest request(QUrl(urlBase.arg(url)));
    if (data.size()) {
        request.setHeader(QNetworkRequest::ContentTypeHeader,
                          QHttpServerLiterals::contentTypeTextHtml());
    }
    auto reply = networkAccessManager.post(request, data.toUtf8());

    QTRY_VERIFY(reply->isFinished());

    QCOMPARE(reply->header(QNetworkRequest::ContentTypeHeader), type);
    QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), code);
    QCOMPARE(reply->readAll(), body);
}

void tst_QHttpsServer::checkReply(QNetworkReply *reply, const QString &response) {
    QTRY_VERIFY(reply->isFinished());

    QCOMPARE(reply->header(QNetworkRequest::ContentTypeHeader), "text/plain");
    QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 200);
    QCOMPARE(reply->readAll(), response);
};

QT_END_NAMESPACE

QTEST_MAIN(tst_QHttpsServer)

#include "tst_qhttpsserver.moc"
