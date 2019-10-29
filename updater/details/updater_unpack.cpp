// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/details/updater_unpack.h"

#include "base/platform/base_platform_file_utilities.h"
#include "public_key.h"

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QByteArray>
#include <QtCore/QDataStream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#ifdef Q_OS_WIN // use Lzma SDK for win
#include <LzmaLib.h>
#else // Q_OS_WIN
#include <lzma.h>
#endif // else of Q_OS_WIN

namespace Updater::details {
namespace {

constexpr auto kHashSize = 32;
constexpr auto kSignatureSize = 256;
constexpr auto kPrivateKeySize = 256;

[[nodiscard]] bool CheckAndRemoveHash(QByteArray &data) {
	if (data.size() <= kHashSize) {
		return false;
	}
	const auto bytes = reinterpret_cast<const uint8_t*>(data.data());
	const auto size = data.size() - kHashSize;
	auto counted = std::array<uint8_t, kHashSize>{ { 0 } };
	SHA256(bytes, size, counted.data());
	if (memcmp(counted.data(), data.data() + size, kHashSize) != 0) {
		return false;
	}
	return true;
}

[[nodiscard]] bool CheckAndRemoveSignature(QByteArray &data) {
	if (data.size() <= kSignatureSize) {
		return false;
	}
	const auto bytes = reinterpret_cast<const uint8_t*>(data.data());
	const auto size = data.size() - kSignatureSize;

	const auto rsa = PEM_read_bio_RSAPublicKey(
		BIO_new_mem_buf(PublicKey, -1),
		nullptr,
		nullptr,
		nullptr);
	if (!rsa) {
		return false;
	} else if (RSA_size(rsa) != kSignatureSize) {
		return false;
	}

	const auto context = EVP_MD_CTX_new();
	const auto contextFree = gsl::finally([&] { EVP_MD_CTX_free(context); });
	const auto key = EVP_PKEY_new();
	const auto keyFree = gsl::finally([&] { EVP_PKEY_free(key); });
	EVP_PKEY_assign_RSA(key, rsa);

	const auto initResult = EVP_DigestVerifyInit(
		context,
		nullptr,
		EVP_sha256(),
		nullptr,
		key);
	const auto updateResult = EVP_DigestVerifyUpdate(context, bytes, size);
	if (initResult <= 0) {
		return false;
	} else if (updateResult <= 0) {
		return false;
	}
	const auto finalResult = EVP_DigestVerifyFinal(
		context,
		bytes + size,
		kSignatureSize);
	if (finalResult <= 0) {
		return false;
	}

	data.resize(data.size() - kSignatureSize);
	return true;
}

[[nodiscard]] QByteArray Decompress(const QByteArray &source) {
	const auto sourceLength = source.size();
	auto serializedLength = quint32();
	const auto serializedLengthSize = int(sizeof(serializedLength));
	memcpy(&serializedLength, source.data(), serializedLengthSize);
	if (serializedLength <= 0 || serializedLength > 1024 * 1024 * 1024) {
		return QByteArray();
	}

	auto result = QByteArray();
	result.resize(serializedLength);
	const auto resultBytes = reinterpret_cast<uint8_t*>(result.data());
	const auto sourceBytes = reinterpret_cast<const uint8_t*>(source.data());

#ifdef Q_OS_WIN // use Lzma SDK for win
	const auto headerLength = serializedLengthSize + int(LZMA_PROPS_SIZE);
	auto decompressedLength = size_t(serializedLength);
	auto compressedLength = SizeT(sourceLength - headerLength);
	const auto decompressResult = LzmaUncompress(
		resultBytes,
		&decompressedLength,
		sourceBytes + headerLength,
		&compressedLength,
		sourceBytes + serializedLengthSize,
		LZMA_PROPS_SIZE);
	if (decompressResult != SZ_OK) {
		return QByteArray();
	} else if (decompressedLength != serializedLength) {
		return QByteArray();
	}
#else // use liblzma for others
	const auto headerLength = serializedLengthSize;
	auto decompressedLength = size_t(serializedLength);
	auto compressedLength = sourceLength - headerLength;

	auto stream = lzma_stream(LZMA_STREAM_INIT);

	const auto initResult = lzma_ret(lzma_stream_decoder(
		&stream,
		UINT64_MAX,
		LZMA_CONCATENATED));
	if (initResult != LZMA_OK) {
		return QByteArray();
	}

	stream.avail_in = compressedLength;
	stream.next_in = sourceBytes + headerLength;
	stream.avail_out = decompressedLength;
	stream.next_out = resultBytes;

	const auto decompressResult = lzma_ret(lzma_code(&stream, LZMA_FINISH));
	if (stream.avail_in) {
		return QByteArray();
	} else if (stream.avail_out) {
		return QByteArray();
	}
	lzma_end(&stream);
	if (decompressResult != LZMA_OK && decompressResult != LZMA_STREAM_END) {
		return QByteArray();
	}
#endif

	return result;
}

[[nodiscard]] bool PrepareTempDirectory(const QString &tempPath) {
	base::Platform::DeleteDirectory(tempPath);
	return !QDir(tempPath).exists();
}

[[nodiscard]] QByteArray ReadAndValidateSource(const QString &path) {
	auto input = QFile(path);
	if (!input.open(QIODevice::ReadOnly)) {
		return QByteArray();
	}
	auto source = input.readAll();
	input.close();

	return (CheckAndRemoveSignature(source) && CheckAndRemoveHash(source))
		? source
		: QByteArray();
}

[[nodiscard]] bool WriteVersionFile(
		const QString &basePath,
		quint32 version) {
	//const auto major = version / 1000000;
	//const auto minor = (version % 1000000) / 1000;
	//const auto patch = version % 1000;
	//const auto versionString = patch
	//	? QString("%1.%2.%3").arg(major).arg(minor).arg(patch)
	//	: QString("%1.%2").arg(major).arg(minor);
	const auto content = QString::number(version).toLatin1();
	auto f = QFile(basePath + "_update_version.tmp");
	return f.open(QIODevice::WriteOnly)
		&& (f.write(content) == content.size());
}

[[nodiscard]] bool ExtractFiles(
		const QString &basePath,
		const QByteArray &data,
		quint32 currentVersion) {
	QDir().mkdir(QDir(basePath).absolutePath());

	auto stream = QDataStream(data);
	stream.setVersion(QDataStream::Qt_5_1);

	auto flags = quint32();
	auto version = quint32();
	auto count = quint32();
	stream >> flags >> version >> count;
	if (stream.status() != QDataStream::Ok
		|| (version <= currentVersion)
		|| !count) {
		return false;
	}
	for (auto i = quint32(0); i != count; ++i) {
		auto name = QString();
		auto flags = quint32();
		auto content = QByteArray();
		stream >> name >> flags >> content;
		if (stream.status() != QDataStream::Ok || name.indexOf("..") >= 0) {
			return false;
		}
		auto f = QFile(basePath + name);
		if (!QDir().mkpath(QFileInfo(f).absolutePath())) {
			return false;
		} else if (!f.open(QIODevice::WriteOnly)) {
			return false;
		}
		if (f.write(content) != content.size()) {
			return false;
		}
		f.close();
		if (flags & 0x01U) {
			f.setPermissions(f.permissions()
				| QFileDevice::ExeOwner
				| QFileDevice::ExeUser
				| QFileDevice::ExeGroup
				| QFileDevice::ExeOther);
		}
	}
	return WriteVersionFile(basePath, version);
}

[[nodiscard]] bool WriteReadyFile(const QString &basePath) {
	auto file = QFile(basePath + "ready");
	return file.open(QIODevice::WriteOnly) && file.write("1", 1);
}

} // namespace

bool Unpack(
		const QString &basePath,
		const QString &filePath,
		quint32 currentVersion) {
	const auto guard = gsl::finally([&] {
		QFile(filePath).remove();
	});
	if (!PrepareTempDirectory(basePath)) {
		return false;
	}
	const auto data = Decompress(ReadAndValidateSource(filePath));
	return ExtractFiles(basePath, data, currentVersion)
		&& WriteReadyFile(basePath);
}

} // namespace Updater::details
