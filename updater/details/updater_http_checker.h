// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "updater/details/updater_checker.h"
#include "base/basic_types.h"

#include <QtCore/QString>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

namespace Updater {
class Instance;
} // namespace Updater

namespace Updater::details {

class HttpChecker : public Checker {
public:
	HttpChecker(
		not_null<Instance*> instance,
		const QString &url,
		bool testing);

	void start() override;

	~HttpChecker();

private:
	struct ParsedVersion {
		QString url;
		int version;
	};
	void gotResponse();
	void gotFailure(QNetworkReply::NetworkError e);
	void clearSentRequest();
	bool handleResponse(const QByteArray &response);
	[[nodiscard]] std::optional<ParsedVersion> parseResponse(
		const QByteArray &response) const;

	const not_null<Instance*> _instance;
	std::unique_ptr<QNetworkAccessManager> _manager;
	QNetworkReply *_reply = nullptr;
	QString _url;

};

} // namespace Updater::details
