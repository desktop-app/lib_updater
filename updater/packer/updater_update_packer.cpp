// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//

#include "private_key.h"
#include "public_key.h"

#include <QtCore/QString>
#include <QtCore/QFileInfoList>
#include <QtCore/QFileInfo>
#include <QtCore/QDir>
#include <QtCore/QDataStream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>
#include <array>
#include <iostream>

#ifdef Q_OS_WIN // use Lzma SDK for win
#include <LzmaLib.h>
#else
#include <lzma.h>
#endif

using std::string;
using std::cout;

constexpr auto kHashSize = 32;
constexpr auto kSignatureSize = 256;
constexpr auto kPrivateKeySize = 256;

template <typename Callback>
class FinalAction {
public:
	template <typename OtherCallback>
	FinalAction(OtherCallback &&callback)
	: _callback(std::forward<OtherCallback>(callback)) {
	}
	~FinalAction() {
		_callback();
	}

private:
	Callback _callback;

};

template <typename Callback>
FinalAction<std::decay_t<Callback>> finally(Callback &&callback) {
	return FinalAction<std::decay_t<Callback>>(
		std::forward<Callback>(callback));
}

struct Data {
	QFileInfoList files;
	QString removePrefix;
	quint32 version = 0;
};

[[nodiscard]] Data ParseData(int argc, char *argv[]) {
	auto result = Data();
	for (auto i = 0; i != argc; ++i) {
		if (string("--path") == argv[i] && i + 1 < argc) {
			const auto path = QString(argv[i + 1]);
			const auto info = QFileInfo(path);
			result.files.push_back(info);
			if (result.removePrefix.isEmpty()) {
				result.removePrefix = info.canonicalPath() + "/";
			}
		} else if (string("--version") == argv[i] && i + 1 < argc) {
			result.version = QString(argv[i + 1]).toUInt();
		}
	}
	return result;
}

[[nodiscard]] bool ValidateData(const Data &data) {
	return !data.files.isEmpty()
		&& !data.removePrefix.isEmpty()
		&& (data.version > 1000)
		&& (data.version <= 999999999);
}

[[nodiscard]] bool ResolveData(Data &data) {
	auto hasDirectories = bool();
	do {
		hasDirectories = false;
		for (auto i = data.files.begin(); i != data.files.end(); ++i) {
			const auto info = *i;
			if (info.isDir()) {
				hasDirectories = true;
				data.files.erase(i);
				const auto directory = QDir(info.absoluteFilePath());
				const auto mask = QDir::Files
					| QDir::Dirs
					| QDir::NoSymLinks
					| QDir::NoDotAndDotDot;
				data.files.append(directory.entryInfoList(mask));
				break;
			} else if (!info.isReadable()) {
				cout
					<< "Can't read: "
					<< info.absoluteFilePath().toStdString()
					<< "\n";
				return false;
			} else if (info.isHidden()) {
				hasDirectories = true;
				data.files.erase(i);
				break;
			}
		}
	} while (hasDirectories);
	return true;
}

[[nodiscard]] bool CheckEntries(const Data &data) {
	for (const auto &info : data.files) {
		if (!info.canonicalFilePath().startsWith(data.removePrefix)) {
			cout
				<< "Can't find '"
				<< data.removePrefix.toStdString()
				<< "' in file '"
				<< info.canonicalFilePath().toStdString()
				<< "' :(\n";
			return false;
		}
	}
	return true;
}

QDataStream &operator<<(QDataStream &stream, const Data &data) {
	auto flags = quint32();
	stream
		<< flags
		<< quint32(data.version)
		<< quint32(data.files.size());
	cout
		<< "Found "
		<< data.files.size()
		<< " file"
		<< (data.files.size() == 1 ? "" : "s")
		<< "...\n";
	for (const auto &info : data.files) {
		const auto fullPath = info.canonicalFilePath();
		const auto name = fullPath.mid(data.removePrefix.length());
		const auto size = info.size();
		cout << name.toStdString() << " (" << size << ")\n";

		auto f = QFile(fullPath);
		if (!f.open(QIODevice::ReadOnly)) {
			cout
				<< "Can't open '"
				<< fullPath.toStdString()
				<< "' for read...\n";
			stream.setStatus(QDataStream::WriteFailed);
			break;
		}
		const auto content = f.readAll();
		if (content.size() != size) {
			cout
				<< "Size should be: "
				<< size
				<< ", read: "
				<< content.size()
				<< "...\n";
			stream.setStatus(QDataStream::WriteFailed);
			break;
		}
		auto flags = quint32();
		if (info.isExecutable()) {
			flags |= 0x01U;
		}
		stream << name << flags << content;
	}
	return stream;
}

[[nodiscard]] QByteArray Pack(const Data &data) {
	auto result = QByteArray();
	{
		auto stream = QDataStream(&result, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << data;
		if (stream.status() != QDataStream::Ok) {
			cout << "Stream status is bad: " << stream.status() << "\n";
			return QByteArray();
		}
	}
	return result;
}

[[nodiscard]] QByteArray Compress(const QByteArray &source) {
	const auto sourceLength = source.size();
	const auto serializedLength = quint32(sourceLength);
	const auto serializedLengthSize = int(sizeof(serializedLength));

	cout << "Compression start, size: " << sourceLength << "\n";

	auto result = QByteArray();
	const auto reserveLength = sourceLength + 1024 * 1024;
	result.resize(reserveLength);
	const auto resultBytes = reinterpret_cast<uint8_t*>(result.data());
	const auto sourceBytes = reinterpret_cast<const uint8_t*>(source.data());

#ifdef Q_OS_WIN // use Lzma SDK for win
	const auto headerLength = serializedLengthSize + int(LZMA_PROPS_SIZE);

	auto outPropsLength = size_t(LZMA_PROPS_SIZE);
	auto compressedLength = size_t(result.size() - headerLength);
	const auto dst = resultBytes + headerLength;
	const auto dstLength = &compressedLength;
	const auto src = sourceBytes;
	const auto srcLength = size_t(sourceLength);
	const auto outProps = resultBytes + serializedLengthSize;
	const auto compressResult = LzmaCompress(
		dst,
		dstLength,
		src,
		srcLength,
		outProps,
		&outPropsLength,
		9, // 0 <= level <= 9, default 5
		64 * 1024 * 1024, // dictSize, default = (1 << 24)
		4, // 0 <= lc <= 8, default = 3
		0, // 0 <= lp <= 4, default = 0
		2, // 0 <= pb <= 4, default = 2
		273, // 5 <= fb <= 273, default = 32
		2); // numThreads, 1 or 2, default = 2
	if (compressResult != SZ_OK) {
		cout << "Error in compression: " << compressResult << "\n";
		return QByteArray();
	}
#else // use liblzma for others
	const auto headerLength = serializedLengthSize;
	auto compressedLength = result.size() - headerLength;

	auto stream = lzma_stream(LZMA_STREAM_INIT);

	int preset = 9 | LZMA_PRESET_EXTREME;
	const auto initResult = lzma_ret(lzma_easy_encoder(
		&stream,
		preset,
		LZMA_CHECK_CRC64));
	if (initResult != LZMA_OK) {
		const auto message = [&] {
			switch (initResult) {
			case LZMA_MEM_ERROR:
				return "Memory allocation failed";
			case LZMA_OPTIONS_ERROR:
				return "Specified preset is not supported";
			case LZMA_UNSUPPORTED_CHECK:
				return "Specified integrity check is not supported";
			default:
				return "Unknown error, possibly a bug";
			}
		}();
		cout
			<< "Error initializing the encoder: "
			<< message
			<< " (error code "
			<< initResult
			<< ")\n";
		return QByteArray();
	}

	stream.next_out = resultBytes + headerLength;
	stream.avail_out = compressedLength;
	stream.next_in = sourceBytes;
	stream.avail_in = sourceLength;

	const auto compressResult = lzma_ret(lzma_code(&stream, LZMA_FINISH));
	compressedLength -= stream.avail_out;
	lzma_end(&stream);
	if (compressResult != LZMA_OK && compressResult != LZMA_STREAM_END) {
		const auto message = [&] {
			switch (compressResult) {
			case LZMA_MEM_ERROR:
				return "Memory allocation failed";
			case LZMA_DATA_ERROR:
				return "File size limits exceeded";
			default:
				return "Unknown error, possibly a bug";
			}
		}();
		cout
			<< "Error in compression: "
			<< message
			<< " (error code "
			<< compressResult
			<< ")\n";
		return QByteArray();
	}
#endif

	result.resize(int(headerLength + compressedLength));
	memcpy(resultBytes, &serializedLength, serializedLengthSize);

	cout << "Compressed to size: " << result.size() << "\n";
	return result;
}

[[nodiscard]] QByteArray Decompress(const QByteArray &source) {
	cout << "Checking uncompressed...\n";

	const auto sourceLength = source.size();
	auto serializedLength = quint32();
	const auto serializedLengthSize = int(sizeof(serializedLength));
	memcpy(&serializedLength, source.data(), serializedLengthSize);
	if (serializedLength <= 0 || serializedLength > 1024 * 1024 * 1024) {
		cout << "Bad result length: " << serializedLength << "\n";
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
		cout << "Uncompress failed: " << decompressResult << "\n";
		return QByteArray();
	} else if (decompressedLength != serializedLength) {
		cout << "Uncompress bad size: " << decompressedLength << ", was: " << serializedLength << "\n";
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
		const auto message = [&] {
			switch (initResult) {
			case LZMA_MEM_ERROR:
				return "Memory allocation failed";
			case LZMA_OPTIONS_ERROR:
				return "Specified preset is not supported";
			case LZMA_UNSUPPORTED_CHECK:
				return "Specified integrity check is not supported";
			default:
				return "Unknown error, possibly a bug";
			}
		}();
		cout
			<< "Error initializing the decoder: "
			<< message
			<< " (error code "
			<< initResult
			<< ")\n";
		return QByteArray();
	}

	stream.avail_in = compressedLength;
	stream.next_in = sourceBytes + headerLength;
	stream.avail_out = decompressedLength;
	stream.next_out = resultBytes;

	const auto decompressResult = lzma_ret(lzma_code(&stream, LZMA_FINISH));
	if (stream.avail_in) {
		cout
			<< "Error in decompression, "
			<< stream.avail_in
			<< " bytes left in _in of "
			<< compressedLength
			<< " whole.\n";
		return QByteArray();
	} else if (stream.avail_out) {
		cout
			<< "Error in decompression, "
			<< stream.avail_out
			<< " bytes free left in _out of "
			<< decompressedLength
			<< " whole.\n";
		return QByteArray();
	}
	lzma_end(&stream);
	if (decompressResult != LZMA_OK && decompressResult != LZMA_STREAM_END) {
		const auto message = [&] {
			switch (decompressResult) {
			case LZMA_MEM_ERROR:
				return "Memory allocation failed";
			case LZMA_FORMAT_ERROR:
				return "The input data is not in the .xz format";
			case LZMA_OPTIONS_ERROR:
				return "Unsupported compression options";
			case LZMA_DATA_ERROR:
				return "Compressed file is corrupt";
			case LZMA_BUF_ERROR:
				return "Compressed data is truncated or otherwise corrupt";
			default:
				return "Unknown error, possibly a bug";
			}
		}();
		cout
			<< "Error in decompression: "
			<< message
			<< " (error code "
			<< decompressResult
			<< ")\n";
		return QByteArray();
	}
#endif

	return result;
}

void AppendHash(QByteArray &data) {
	const auto size = data.size();
	data.resize(size + kHashSize);
	const auto bytes = reinterpret_cast<uint8_t*>(data.data());
	SHA256(bytes, size, bytes + size);
}

[[nodiscard]] bool CheckHashAfterSign(const QByteArray &data) {
	if (data.size() <= kHashSize + kSignatureSize) {
		cout << "Bad hashed data size: " << data.size() << "\n";
		return false;
	}
	const auto bytes = reinterpret_cast<const uint8_t*>(data.data());
	const auto size = data.size() - kHashSize - kSignatureSize;
	auto counted = std::array<uint8_t, kHashSize>{ { 0 } };
	SHA256(bytes, size, counted.data());
	if (memcmp(counted.data(), data.data() + size, kHashSize) != 0) {
		cout << "Wrong data hash.\n";
		return false;
	}
	return true;
}

[[nodiscard]] bool AppendSignature(QByteArray &data) {
	const auto size = data.size();
	data.resize(size + kSignatureSize);
	const auto bytes = reinterpret_cast<uint8_t*>(data.data());

	cout << "Signing...\n";

	const auto rsa = PEM_read_bio_RSAPrivateKey(
		BIO_new_mem_buf(const_cast<char*>(PrivateKey), -1),
		nullptr,
		nullptr,
		nullptr);
	if (!rsa) {
		cout << "Could not read RSA private key!\n";
		return false;
	} else if (RSA_size(rsa) != kPrivateKeySize) {
		cout << "Bad private key, size: " << RSA_size(rsa) << "\n";
		return false;
	}

	auto signatureLength = size_t();

	const auto context = EVP_MD_CTX_new();
	const auto contextFree = finally([&] { EVP_MD_CTX_free(context); });
	const auto key = EVP_PKEY_new();
	const auto keyFree = finally([&] { EVP_PKEY_free(key); });
	EVP_PKEY_assign_RSA(key, rsa);

	const auto initResult = EVP_DigestSignInit(
		context,
		nullptr,
		EVP_sha256(),
		nullptr,
		key);
	const auto updateResult = EVP_DigestSignUpdate(context, bytes, size);
	const auto getSizeResult = EVP_DigestSignFinal(
		context,
		nullptr,
		&signatureLength);
	if (initResult <= 0) {
		cout << "Could not init signing: " << initResult << "\n";
		return false;
	} else if (updateResult <= 0) {
		cout << "Could not update signing: " << updateResult << "\n";
		return false;
	} else if (getSizeResult <= 0) {
		cout << "Could not get size result: " << getSizeResult << "\n";
		return false;
	} else if (signatureLength != kSignatureSize) {
		cout << "Wrong signature size: " << signatureLength << "\n";
		return false;
	}
	const auto finalResult = EVP_DigestSignFinal(
		context,
		bytes + size,
		&signatureLength);
	if (finalResult <= 0) {
		cout << "Could not get signature: " << finalResult << "\n";
		return false;
	}
	return true;
}

[[nodiscard]] bool CheckSignature(const QByteArray &data) {
	if (data.size() <= kSignatureSize) {
		cout << "Bad signed data size: " << data.size() << "\n";
		return false;
	}
	const auto bytes = reinterpret_cast<const uint8_t*>(data.data());
	const auto size = data.size() - kSignatureSize;

	cout << "Checking signature...\n";
	const auto rsa = PEM_read_bio_RSAPublicKey(
		BIO_new_mem_buf(PublicKey, -1),
		nullptr,
		nullptr,
		nullptr);
	if (!rsa) {
		cout << "Could not read RSA public key!\n";
		return false;
	} else if (RSA_size(rsa) != kSignatureSize) {
		cout << "Bad public key, size: " << RSA_size(rsa) << "\n";
		return false;
	}

	const auto context = EVP_MD_CTX_new();
	const auto contextFree = finally([&] { EVP_MD_CTX_free(context); });
	const auto key = EVP_PKEY_new();
	const auto keyFree = finally([&] { EVP_PKEY_free(key); });
	EVP_PKEY_assign_RSA(key, rsa);

	const auto initResult = EVP_DigestVerifyInit(
		context,
		nullptr,
		EVP_sha256(),
		nullptr,
		key);
	const auto updateResult = EVP_DigestVerifyUpdate(context, bytes, size);
	if (initResult <= 0) {
		cout << "Could not init signing: " << initResult << "\n";
		return false;
	} else if (updateResult <= 0) {
		cout << "Could not update signing: " << updateResult << "\n";
		return false;
	}
	const auto finalResult = EVP_DigestVerifyFinal(
		context,
		bytes + size,
		kSignatureSize);
	if (finalResult <= 0) {
		cout << "Signature verification failed: " << finalResult << "\n";
		return false;
	} if (!CheckHashAfterSign(data)) {
		return false;
	}
	cout << "Signature and hash verified!\n";
	return true;
}

[[nodiscard]] bool WriteResult(const Data &data, const QByteArray &bytes) {
	const auto outName = "packed_update" + QString::number(data.version);

	auto file = QFile(outName);
	if (!file.open(QIODevice::WriteOnly)) {
		cout
			<< "Can't open '"
			<< outName.toStdString()
			<< "' for write...\n";
		return false;
	} else if (file.write(bytes) != bytes.size()) {
		cout << "Couldn't write bytes to '" << outName.toStdString() << "\n";
		return false;
	}
	file.close();

	cout << "Update file '" << outName.toStdString() << "' written!\n";
	return true;
}

int main(int argc, char *argv[]) {
	auto data = ParseData(argc, argv);

	if (!ValidateData(data)) {
		cout << "Usage: update_packer -path {file} -version {version} OR "
			"update_packer -path {dir} -version {version}\n";
		return -1;
	} else if (!ResolveData(data) || !CheckEntries(data)) {
		return -1;
	}

	const auto packed = Pack(data);
	if (packed.isEmpty()) {
		return -1;
	}
	auto compressed = Compress(packed);
	if (compressed.isEmpty() || Decompress(compressed) != packed) {
		cout << "Compress+check failed :(\n";
		return -1;
	}
	compressed.reserve(compressed.size() + kHashSize + kSignatureSize);
	AppendHash(compressed);
	if (!AppendSignature(compressed) || !CheckSignature(compressed)) {
		cout << "Signature+check failed :(\n";
		return -1;
	} else if (!WriteResult(data, compressed)) {
		return -1;
	}
	return 0;
}
