// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/details/updater_http_loader.h"

#include "base/basic_types.h"
#include <QtCore/QString>
#include <QtCore/QRegularExpression>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

namespace Updater::details {
namespace {

using ErrorSignal = void(QNetworkReply::*)(QNetworkReply::NetworkError);
const auto QNetworkReply_error = ErrorSignal(&QNetworkReply::error);

} // namespace

class HttpLoaderActor : public QObject {
public:
	HttpLoaderActor(
		not_null<HttpLoader*> parent,
		not_null<QThread*> thread,
		const QString &url);

private:
	void start();
	void sendRequest();

	void gotMetaData();
	void partFinished(qint64 got, qint64 total);
	void partFailed(QNetworkReply::NetworkError e);

	not_null<HttpLoader*> _parent;
	QString _url;
	QNetworkAccessManager _manager;
	std::unique_ptr<QNetworkReply> _reply;

};

HttpLoaderActor::HttpLoaderActor(
	not_null<HttpLoader*> parent,
	not_null<QThread*> thread,
	const QString &url)
	: _parent(parent) {
	_url = url;
	moveToThread(thread);
	_manager.moveToThread(thread);

	connect(thread, &QThread::started, this, [=] { start(); });
}

void HttpLoaderActor::start() {
	sendRequest();
}

void HttpLoaderActor::sendRequest() {
	auto request = QNetworkRequest(_url);
	const auto rangeHeaderValue = "bytes="
		+ QByteArray::number(_parent->alreadySize())
		+ "-";
	request.setRawHeader("Range", rangeHeaderValue);
	request.setAttribute(
		QNetworkRequest::HttpPipeliningAllowedAttribute,
		true);
	_reply.reset(_manager.get(request));
	connect(
		_reply.get(),
		&QNetworkReply::downloadProgress,
		this,
		&HttpLoaderActor::partFinished);
	connect(
		_reply.get(),
		QNetworkReply_error,
		this,
		&HttpLoaderActor::partFailed);
	connect(
		_reply.get(),
		&QNetworkReply::metaDataChanged,
		this,
		&HttpLoaderActor::gotMetaData);
}

void HttpLoaderActor::gotMetaData() {
	const auto pairs = _reply->rawHeaderPairs();
	for (const auto pair : pairs) {
		if (QString::fromUtf8(pair.first).toLower() == "content-range") {
			const auto m = QRegularExpression("/(\\d+)([^\\d]|$)").match(QString::fromUtf8(pair.second));
			if (m.hasMatch()) {
				_parent->writeChunk({}, m.captured(1).toInt());
			}
		}
	}
}

void HttpLoaderActor::partFinished(qint64 got, qint64 total) {
	if (!_reply) return;

	const auto statusCode = _reply->attribute(
		QNetworkRequest::HttpStatusCodeAttribute);
	if (statusCode.isValid()) {
		const auto status = statusCode.toInt();
		if (status != 200 && status != 206 && status != 416) {
			_parent->threadSafeFailed();
			return;
		}
	}

	const auto data = _reply->readAll();
	_parent->writeChunk(bytes::make_span(data), total);
}

void HttpLoaderActor::partFailed(QNetworkReply::NetworkError e) {
	if (!_reply) return;

	const auto statusCode = _reply->attribute(
		QNetworkRequest::HttpStatusCodeAttribute);
	_reply.release()->deleteLater();
	if (statusCode.isValid()) {
		const auto status = statusCode.toInt();
		if (status == 416) { // Requested range not satisfiable
			_parent->writeChunk({}, _parent->alreadySize());
			return;
		}
	}
	_parent->threadSafeFailed();
}

HttpLoader::HttpLoader(const QString &path, const QString &url)
: Loader(path, kChunkSize)
, _url(url) {
}

void HttpLoader::startLoading() {
	_thread = std::make_unique<QThread>();
	_actor = new HttpLoaderActor(this, _thread.get(), _url);
	_thread->start();
}

HttpLoader::~HttpLoader() {
	if (const auto thread = base::take(_thread)) {
		if (const auto actor = base::take(_actor)) {
			QObject::connect(
				thread.get(),
				&QThread::finished,
				actor,
				&QObject::deleteLater);
		}
		thread->quit();
		thread->wait();
	}
}

} // namespace Updater::details
