#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QJsonObject>
#include <QJsonDocument>
#include <QByteArray>
#include <QString>

//如果pro里找到了openssl库，则使用jtw-cpp，否则用qjwt
#ifdef HAVE_OPENSSL_LIB
#define USE_JWT_CPP
#endif

#ifdef USE_JWT_CPP
#include "include/jwt-cpp/jwt.h"
#else
#include "qjwt.h"
using namespace QJwt;
#endif

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ";

    // 密钥（UTF-8 原始字符串）
    QString secretStr = "h94oVoRkaD9XDoimr3asEHhXMhitpbe+0XQV2wUE9VQ=";
    QByteArray secret = secretStr.toUtf8();
    qDebug() << "Secret:" << secretStr;

    // 构造 payload 数据
    QJsonObject payload;
    payload.insert("iss", "dualstreamServer");
    payload.insert("aud", "dualstreamServer");
    payload.insert("exp", QDateTime::currentSecsSinceEpoch() + 180); // 当前时间 + 3分钟
    qDebug() << "Payload:" << payload;

    qDebug() << "----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ";

#ifdef USE_JWT_CPP
    // 使用 jwt-cpp 生成 token
    std::string secretStd = secret.toStdString();
    std::string issuer = payload.value("iss").toString().toStdString();
    std::string audience = payload.value("aud").toString().toStdString();
    qint64 exp = payload.value("exp").toVariant().toLongLong();
    auto expTime = std::chrono::system_clock::from_time_t(exp);

    std::string tokenStd = jwt::create()
        .set_type("JWT")
        .set_algorithm("HS256")
        .set_issuer(issuer)
        .set_audience(audience)
        .set_expires_at(expTime)
        .sign(jwt::algorithm::hs256{secretStd});

    QString token = QString::fromStdString(tokenStd);
    qDebug() << "[jwt-cpp] Token:" << token;

    qDebug() << "----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ";

    // 使用 jwt-cpp 验证 token
    try
    {
        auto decoded = jwt::decode(tokenStd);
        jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secretStd})
            .with_issuer(issuer)
            .with_audience(audience)
            .verify(decoded);

        qDebug() << "[jwt-cpp] Verification success.";

        // 使用 picojson 手动序列化 payload
        auto payloadObj = decoded.get_payload_json(); // 返回 picojson::object
        std::string payloadJsonStr = picojson::value(payloadObj).serialize();

        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(payloadJsonStr), &err);
        if (err.error == QJsonParseError::NoError)
        {
            QJsonObject parsedPayload = doc.object();
            for (const QString& key : parsedPayload.keys())
            {
                qDebug() << "[jwt-cpp] Claim:" << key << "=" << parsedPayload.value(key).toVariant();
            }
        }
        else
        {
            qDebug() << "[jwt-cpp] JSON parse error:" << err.errorString();
        }
    }
    catch (const std::exception& e)
    {
        qDebug() << "[jwt-cpp] Verification failed:" << e.what();
    }
    qDebug() << "----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ";


#else
    // 使用 QJwt 生成 token
    QJwtObject jwtOut(SAlgorithm::HS256, payload, secret);
    QByteArray tokenRaw = jwtOut.jwt();
    QString token = QString::fromUtf8(tokenRaw);
    qDebug() << "[QJwt] Token:" << token;

    qDebug() << "----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ";

    // 使用 QJwt 验证 token
    QJwtObject parsed = QJwtObject::decode(tokenRaw, SAlgorithm::HS256, secret);
    if (parsed.isValid())
    {
        qDebug() << "[QJwt] Verification success.";
        for (const QString& key : parsed.payload().keys())
        {
            qDebug() << "[QJwt] Claim:" << key << "=" << parsed.payload().value(key).toVariant();
        }
    }
    else
    {
        qDebug() << "[QJwt] Verification failed. Error:" << parsed.errorString();
    }

    qDebug() << "----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ";
#endif

    return 0;
}









