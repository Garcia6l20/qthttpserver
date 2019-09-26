/****************************************************************************
**
** Copyright (C) 2019 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtHttpServer module of the Qt Toolkit.
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

#include "qsslserver.h"

#include <QFile>
#include <QSslSocket>

QSslServer::QSslServer(QObject* parent):
    QTcpServer (parent)
{
}

void QSslServer::incomingConnection(qintptr handle) {
    QSslSocket * socket = new QSslSocket(this);
    connect(socket, QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors), this, &QSslServer::sslErrors);
    connect(socket, QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors),
            [](const QList<QSslError>& errors) {
        for (auto& err: errors) {
            qCritical() << err;
        }
    });
    socket->setSocketDescriptor(handle);
    socket->setLocalCertificate(m_certificate);
    socket->setPrivateKey(m_privateKey);
    socket->setProtocol(m_protocol);
    socket->startServerEncryption();

    addPendingConnection(socket);
}

void QSslServer::setLocalCertificate(const QSslCertificate &certificate)
{
    m_certificate = certificate;
}

bool QSslServer::setLocalCertificate(const QString &path, QSsl::EncodingFormat format)
{
    QFile certificateFile(path);

    if (!certificateFile.open(QIODevice::ReadOnly))
        return false;

    m_certificate = QSslCertificate(certificateFile.readAll(), format);
    return true;
}

void QSslServer::setPrivateKey(const QSslKey &key)
{
    m_privateKey = key;
}

bool QSslServer::setPrivateKey(const QString &fileName, QSsl::KeyAlgorithm algorithm, QSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    QFile keyFile(fileName);

    if (!keyFile.open(QIODevice::ReadOnly))
        return false;

    m_privateKey = QSslKey(keyFile.readAll(), algorithm, format, QSsl::PrivateKey, passPhrase);
    return true;
}

void QSslServer::setSslProtocol(QSsl::SslProtocol protocol)
{
    m_protocol = protocol;
}
