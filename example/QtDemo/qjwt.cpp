#include "qjwt.h"
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QDateTime>
#include <QDebug>

#ifdef HAVE_OPENSSL_LIB
// OpenSSL headers for EVP and PEM
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#endif

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
    QByteArray signingInput = headerBase64() + "." + payloadBase64();

    // HMAC signature (always supported)
    if (m_alg == SAlgorithm::HS256 ||
        m_alg == SAlgorithm::HS384 ||
        m_alg == SAlgorithm::HS512)
    {
        QCryptographicHash::Algorithm hashAlg;
        switch (m_alg)
        {
            case SAlgorithm::HS256:
                hashAlg = QCryptographicHash::Sha256; break;
            case SAlgorithm::HS384:
                hashAlg = QCryptographicHash::Sha384; break;
            case SAlgorithm::HS512:
                hashAlg = QCryptographicHash::Sha512; break;
            default:
                return QByteArray();
        }

        QMessageAuthenticationCode mac(hashAlg, m_secret);
        mac.addData(signingInput);
        return mac.result();
    }

    QString m_error; // 用于存储错误信息

    // Reject RSA/ECDSA if OpenSSL is not available
#ifndef HAVE_OPENSSL_LIB
    if (m_alg == SAlgorithm::RS256 ||
        m_alg == SAlgorithm::RS384 ||
        m_alg == SAlgorithm::RS512 ||
        m_alg == SAlgorithm::ES256 ||
        m_alg == SAlgorithm::ES384 ||
        m_alg == SAlgorithm::ES512) {
        m_error = QString("Algorithm %1 requires OpenSSL, but HAVE_OPENSSL_LIB is not defined.")
                      .arg(static_cast<int>(m_alg));
        return QByteArray();
    }
#else
    // RSA / ECDSA signature using OpenSSL
    if (m_alg == SAlgorithm::RS256 ||
        m_alg == SAlgorithm::RS384 ||
        m_alg == SAlgorithm::RS512 ||
        m_alg == SAlgorithm::ES256 ||
        m_alg == SAlgorithm::ES384 ||
        m_alg == SAlgorithm::ES512) {

        const EVP_MD* md = nullptr;
        switch (m_alg)
        {
            case SAlgorithm::RS256:
            case SAlgorithm::ES256:
                md = EVP_sha256(); break;
            case SAlgorithm::RS384:
            case SAlgorithm::ES384:
                md = EVP_sha384(); break;
            case SAlgorithm::RS512:
            case SAlgorithm::ES512:
                md = EVP_sha512(); break;
            default:
                return QByteArray();
        }

        BIO* bio = BIO_new_mem_buf(m_secret.data(), m_secret.size());
        if (!bio)
        {
            m_error = "Failed to create BIO from secret.";
            return QByteArray();
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey)
        {
            m_error = "Failed to parse private key from PEM.";
            return QByteArray();
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        QByteArray signature;

        if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey) == 1 &&
            EVP_DigestSignUpdate(ctx, signingInput.data(), signingInput.size()) == 1)
        {

            size_t sigLen = 0;
            EVP_DigestSignFinal(ctx, nullptr, &sigLen);
            signature.resize(sigLen);
            if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(signature.data()), &sigLen) == 1)
            {
                signature.resize(sigLen);
            }
            else
            {
                signature.clear();
                m_error = "EVP_DigestSignFinal failed.";
            }
        }
        else
        {
            m_error = "EVP_DigestSignInit or Update failed.";
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return signature;
    }
#endif

    // Unsupported or unknown algorithm
    m_error = QString("Unsupported algorithm: %1").arg(static_cast<int>(m_alg));
    return QByteArray();
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
