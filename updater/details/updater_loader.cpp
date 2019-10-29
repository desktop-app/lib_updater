// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/details/updater_loader.h"

#include "updater/updater_instance.h"

#include <QtCore/QFileInfo>
#include <QtCore/QDir>

namespace Updater::details {

Loader::Loader(
	const QString &filepath,
	int chunkSize)
: _filepath(filepath)
, _chunkSize(chunkSize) {
}

void Loader::start() {
	if (!validateOutput()
		|| (!_output.isOpen() && !_output.open(QIODevice::Append))) {
		QFile(_filepath).remove();
		threadSafeFailed();
		return;
	}

	startLoading();
}

int Loader::alreadySize() const {
	QMutexLocker lock(&_sizesMutex);
	return _alreadySize;
}

int Loader::totalSize() const {
	QMutexLocker lock(&_sizesMutex);
	return _totalSize;
}

rpl::producer<QString> Loader::ready() const {
	return _ready.events();
}

auto Loader::progress() const -> rpl::producer<Progress> {
	return _progress.events();
}

rpl::producer<> Loader::failed() const {
	return _failed.events();
}

void Loader::wipeFolder() {
	const auto info = QFileInfo(_filepath);
	const auto dir = info.dir();
	const auto all = dir.entryInfoList(QDir::Files);
	for (auto i = all.begin(), e = all.end(); i != e; ++i) {
		if (i->absoluteFilePath() != info.absoluteFilePath()) {
			QFile::remove(i->absoluteFilePath());
		}
	}
}

bool Loader::validateOutput() {
	if (_filepath.isEmpty()) {
		return false;
	}

	QFileInfo info(_filepath);
	const auto dir = info.dir();
	if (!dir.exists()) {
		dir.mkdir(dir.absolutePath());
	}
	_output.setFileName(_filepath);

	if (!info.exists()) {
		return true;
	}
	const auto fullSize = info.size();
	if (fullSize < _chunkSize || fullSize > kMaxFileSize) {
		return _output.remove();
	}
	const auto goodSize = int((fullSize % _chunkSize)
		? (fullSize - (fullSize % _chunkSize))
		: fullSize);
	if (_output.resize(goodSize)) {
		_alreadySize = goodSize;
		return true;
	}
	return false;
}

void Loader::threadSafeProgress(Progress progress) {
	crl::on_main(this, [=] {
		_progress.fire_copy(progress);
	});
}

void Loader::threadSafeReady() {
	crl::on_main(this, [=] {
		_ready.fire_copy(_filepath);
	});
}

void Loader::threadSafeFailed() {
	crl::on_main(this, [=] {
		_failed.fire({});
	});
}

void Loader::writeChunk(bytes::const_span data, int totalSize) {
	const auto size = data.size();
	if (size > 0) {
		const auto written = _output.write(QByteArray::fromRawData(
			reinterpret_cast<const char*>(data.data()),
			size));
		if (written != size) {
			threadSafeFailed();
			return;
		}
	}

	const auto progress = [&] {
		QMutexLocker lock(&_sizesMutex);
		if (!_totalSize) {
			_totalSize = totalSize;
		}
		_alreadySize += size;
		return Progress{ _alreadySize, _totalSize };
	}();

	if (progress.size > 0 && progress.already >= progress.size) {
		_output.close();
		threadSafeReady();
	} else {
		threadSafeProgress(progress);
	}
}

rpl::lifetime &Loader::lifetime() {
	return _lifetime;
}

} // namespace Updater::details
