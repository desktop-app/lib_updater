// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "base/weak_ptr.h"
#include "base/bytes.h"

#include <QtCore/QString>
#include <QtCore/QFile>
#include <QtCore/QMutex>
#include <rpl/producer.h>
#include <rpl/event_stream.h>

namespace Updater {
struct Progress;
} // namespace Updater

namespace Updater::details {

class Loader : public base::has_weak_ptr {
public:
	Loader(const QString &filepath, int chunkSize);

	static constexpr auto kChunkSize = 128 * 1024;
	static constexpr auto kMaxFileSize = 256 * 1024 * 1024;

	void start();
	void wipeFolder();
	void wipeOutput();

	int alreadySize() const;
	int totalSize() const;

	rpl::producer<Progress> progress() const;
	rpl::producer<QString> ready() const;
	rpl::producer<> failed() const;

	rpl::lifetime &lifetime();

	virtual ~Loader() = default;

protected:
	void threadSafeFailed();

	// Single threaded.
	void writeChunk(bytes::const_span data, int totalSize);

private:
	virtual void startLoading() = 0;

	bool validateOutput();
	void threadSafeProgress(Progress progress);
	void threadSafeReady();

	QString _filepath;
	int _chunkSize = 0;

	QFile _output;
	int _alreadySize = 0;
	int _totalSize = 0;
	mutable QMutex _sizesMutex;
	rpl::event_stream<Progress> _progress;
	rpl::event_stream<QString> _ready;
	rpl::event_stream<> _failed;

	rpl::lifetime _lifetime;

};

}