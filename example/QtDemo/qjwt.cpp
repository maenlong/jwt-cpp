#include "qjwt.h"
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QDateTime>
#include <QDebug>

using namespace QJwt;

QJwt::QJwtObject::QJwtObject(SAlgorithm alg, const QJsonObject& payload, const QByteArray& secret)
    : m_alg(alg)
    , m_secret(secret)
    , m_payloadJson(payload)
{
    m_headerJson.insert("alg", alg_to_str(alg));
    m_headerJson.insert("typ", "JWT");
}

QJwtObject& QJwt::QJwtObject::addClaim(QJwt::registered_claims claim, const QVariant& value)
{
    m_payloadJson.insert(QJwt::reg_claims_to_str(claim), value.toString());
    return *this;
}

QJwtObject& QJwt::QJwtObject::addClaim(QString claim, const QVariant& value)
{
    m_payloadJson.insert(claim, value.toString());
    return *this;
}

QJwtObject& QJwt::QJwtObject::removeClaim(QJwt::registered_claims claim)
{
    m_payloadJson.remove(QJwt::reg_claims_to_str(claim));
    return *this;
}

QJwtObject& QJwt::QJwtObject::removeClaim(QString claim)
{
    m_payloadJson.remove(claim);
    return *this;
}

bool QJwt::QJwtObject::hasClaim(QJwt::registered_claims claim)
{
    return m_payloadJson.contains(QJwt::reg_claims_to_str(claim));
}

bool QJwt::QJwtObject::hasClaim(QString claim)
{
    return m_payloadJson.contains(claim);
}

QJsonObject& QJwt::QJwtObject::header()
{
    return m_headerJson;
}

QJsonObject& QJwt::QJwtObject::payload()
{
    return m_payloadJson;
}

QByteArray toBase64Url(const QByteArray &input)
{
    return input.toBase64().replace('+', '-').replace('/', '_').replace("=", "");
}

QByteArray QJwt::QJwtObject::headerBase64() const
{
    return toBase64Url(QJsonDocument(m_headerJson).toJson(QJsonDocument::Compact));
}

QByteArray QJwt::QJwtObject::payloadBase64() const
{
    return toBase64Url(QJsonDocument(m_payloadJson).toJson(QJsonDocument::Compact));
}

QByteArray QJwtObject::signatureBase64() const
{
    return toBase64Url(signature());
}

QByteArray QJwtObject::signature() const
{
    // 构造签名输入：Base64Url(header) + "." + Base64Url(payload)
    QByteArray signingInput = headerBase64() + "." + payloadBase64();

    // 仅支持 HMAC 算法：HS256 / HS384 / HS512
    QCryptographicHash::Algorithm hashAlg;
    switch (m_alg) {
    case SAlgorithm::HS256: hashAlg = QCryptographicHash::Sha256; break;
    case SAlgorithm::HS384: hashAlg = QCryptographicHash::Sha384; break;
    case SAlgorithm::HS512: hashAlg = QCryptographicHash::Sha512; break;
    default:
        qWarning() << "Unsupported algorithm for HMAC signature:" << alg_to_str(m_alg);
        return QByteArray(); // 非 HMAC 算法暂不支持
    }

    // 使用 Qt 的 HMAC 实现进行签名
    QMessageAuthenticationCode mac(hashAlg, m_secret);
    mac.addData(signingInput);
    return mac.result(); // 返回原始二进制签名
}

QByteArray QJwt::QJwtObject::jwt()
{
    return headerBase64() + "." + payloadBase64() + "." + signatureBase64();
}

QJwtObject QJwt::QJwtObject::decode(const QByteArray& jwt, SAlgorithm alg, const QByteArray& secret)
{
    QJwtObject jwtObject;
    jwtObject.m_secret = secret;

    QByteArrayList list = jwt.split('.');
    if (list.size() != 3)
    {
        jwtObject.m_errorString = "jwt format error";
        jwtObject.m_status = Status::JwrFormatError;
        qWarning() << "jwt format error" << jwt;
        return jwtObject;
    }

    // 解析 header
    QJsonParseError err;
    auto jdoc = QJsonDocument::fromJson(QByteArray::fromBase64(list[0], QByteArray::Base64UrlEncoding), &err);
    if (err.error != QJsonParseError::NoError)
    {
        jwtObject.m_errorString = "header json error," + err.errorString();
        jwtObject.m_status = Status::Invalid;
        return jwtObject;
    }
    auto jheaderObj = jdoc.object();
    if (jheaderObj.value("typ").toString() != "JWT")
    {
        jwtObject.m_errorString = "jwt type error " + jheaderObj.value("typ").toString() + " need JWT";
        jwtObject.m_status = Status::Invalid;
        qWarning() << "jwt type error" << jheaderObj.value("typ").toString() << "need JWT";
        return jwtObject;
    }
    jwtObject.setHeader(jheaderObj);

    // 检查算法
    auto realAlg = str_to_alg(jheaderObj.value("alg").toString());
    if (realAlg == SAlgorithm::UNKN || alg != realAlg)
    {
        jwtObject.m_errorString = QString("jwt algorithm error, need ") + alg_to_str(alg) + ", now is " + alg_to_str(realAlg);
        jwtObject.m_status = Status::AlgorithmError;
        qWarning() << "jwt algorithm error" << jheaderObj.value("alg").toString() << "need " << alg_to_str(alg);
        return jwtObject;
    }
    jwtObject.setAlgorithm(realAlg);

    // 解析 payload
    err.error = QJsonParseError::NoError;
    jdoc = QJsonDocument::fromJson(QByteArray::fromBase64(list[1], QByteArray::Base64UrlEncoding), &err);
    if (err.error != QJsonParseError::NoError)
    {
        jwtObject.m_errorString = "payload json error," + err.errorString();
        jwtObject.m_status = Status::Invalid;
        return jwtObject;
    }
    jwtObject.setPayload(jdoc.object());

    // 检查过期时间
    if (jwtObject.payload().contains("exp"))
    {
        qint64 exp = jwtObject.payload().value("exp").toVariant().toLongLong();
        qint64 now = QDateTime::currentSecsSinceEpoch();
        if (exp < now) {
            jwtObject.m_errorString = "jwt is expired";
            jwtObject.m_status = Status::Expired;
            return jwtObject;
        }
    }

    //  修复：正确解码传入的签名（Base64Url → 二进制）
    QByteArray expectedSignature = list[2];
    expectedSignature = expectedSignature.replace('-', '+').replace('_', '/');
    int padding = 4 - (expectedSignature.size() % 4);
    if (padding < 4) expectedSignature.append(padding, '=');
    expectedSignature = QByteArray::fromBase64(expectedSignature);

    //  使用我们自己的 signature() 重新计算签名
    QByteArray actualSignature = jwtObject.signature();

    if (actualSignature != expectedSignature)
    {
        jwtObject.m_status = Status::Invalid;
        jwtObject.m_errorString = "signature verification failed";
        return jwtObject;
    }

    jwtObject.m_status = Status::Ok;
    return jwtObject;
}
