// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/details/updater_http_checker.h"

#include "base/platform/base_platform_info.h"
#include "base/qt_adapters.h"
#include "updater/details/updater_http_loader.h"
#include "updater/updater_instance.h"

#include <QtCore/QJsonObject>
#include <QtCore/QJsonDocument>
#include <cmath>

namespace Updater::details {
namespace {

constexpr auto kMaxResponseSize = 1024 * 1024;

template <typename Callback>
bool ParseCommonMap(
		const QByteArray &json,
		bool testing,
		Callback &&callback) {
	auto error = QJsonParseError{ 0, QJsonParseError::NoError };
	const auto document = QJsonDocument::fromJson(json, &error);
	if (error.error != QJsonParseError::NoError) {
		return false;
	} else if (!document.isObject()) {
		return false;
	}
	const auto platforms = document.object();
	const auto platform = Platform::AutoUpdateKey();
	const auto it = platforms.constFind(platform);
	if (it == platforms.constEnd()) {
		return false;
	} else if (!(*it).isObject()) {
		return false;
	}
	const auto types = (*it).toObject();
	const auto list = [&]() -> std::vector<QString> {
		return { "stable" };
	}();
	auto bestAvailableVersion = 0;
	for (const auto &type : list) {
		const auto it = types.constFind(type);
		if (it == types.constEnd()) {
			continue;
		} else if (!(*it).isObject()) {
			return false;
		}
		const auto map = (*it).toObject();
		const auto key = testing ? "testing" : "released";
		const auto version = map.constFind(key);
		if (version == map.constEnd()) {
			continue;
		}
		const auto availableVersion = [&] {
			if ((*version).isString()) {
				const auto string = (*version).toString();
				if (const auto index = string.indexOf(':'); index > 0) {
					return string.midRef(0, index).toInt();
				}
				return string.toInt();
			} else if ((*version).isDouble()) {
				return int(std::round((*version).toDouble()));
			}
			return 0;
		}();
		if (!availableVersion) {
			return false;
		}
		if (availableVersion > bestAvailableVersion) {
			bestAvailableVersion = availableVersion;
			if (!callback(availableVersion, map)) {
				return false;
			}
		}
	}
	if (!bestAvailableVersion) {
		return false;
	}
	return true;
}

[[nodiscard]] QString ExtractUrlBase(const QString &url) {
	const auto index = url.indexOf("://");
	const auto first = (index >= 0)
		? url.indexOf('/', index + 3)
		: url.indexOf('/');
	return url.mid(0, first);
}

} // namespace

HttpChecker::HttpChecker(
	not_null<Instance*> instance,
	const QString &url,
	bool testing)
: Checker(testing)
, _instance(instance)
, _url(url) {
	//const auto updaterVersion = Platform::AutoUpdateVersion();
	//const auto path = Local::readAutoupdatePrefix()
	//	+ qstr("/current")
	//	+ (updaterVersion > 1 ? QString::number(updaterVersion) : QString());
}

void HttpChecker::start() {
	auto url = QUrl(_url);
	const auto request = QNetworkRequest(url);
	_manager = std::make_unique<QNetworkAccessManager>();
	_reply = _manager->get(request);
	_reply->connect(_reply, &QNetworkReply::finished, [=] {
		gotResponse();
	});
	_reply->connect(_reply, base::QNetworkReply_error, [=](auto e) {
		gotFailure(e);
	});
}

void HttpChecker::gotResponse() {
	if (!_reply) {
		return;
	}

	_instance->updateLastCheckTime();
	const auto response = _reply->readAll();
	clearSentRequest();

	if (response.size() >= kMaxResponseSize || !handleResponse(response)) {
		gotFailure(QNetworkReply::UnknownContentError);
	}
}

[[nodiscard]] QString DownloadPath(
		const QString &basePath,
		const QString &url,
		int version) {
	return basePath + "update-" + QString::number(version);
}

bool HttpChecker::handleResponse(const QByteArray &response) {
	const auto handle = [&](const QString &url, int version) {
		done(url.isEmpty()
			? nullptr
			: std::make_shared<HttpLoader>(
				DownloadPath(_instance->downloadPath(), url, version),
				url));
		return true;
	};
	if (const auto version = parseResponse(response)) {
		return handle(version->url, version->version);
	}
	return false;
}

void HttpChecker::clearSentRequest() {
	const auto reply = base::take(_reply);
	if (!reply) {
		return;
	}
	reply->disconnect(reply, &QNetworkReply::finished, nullptr, nullptr);
	reply->disconnect(reply, base::QNetworkReply_error, nullptr, nullptr);
	reply->abort();
	reply->deleteLater();
	_manager = nullptr;
}

void HttpChecker::gotFailure(QNetworkReply::NetworkError e) {
	if (const auto reply = base::take(_reply)) {
		reply->deleteLater();
	}

	fail();
}

std::optional<HttpChecker::ParsedVersion> HttpChecker::parseResponse(
		const QByteArray &response) const {
	auto bestAvailableVersion = 0;
	auto bestLink = QString();
	const auto accumulate = [&](
			int version,
			const QJsonObject &map) {
		bestAvailableVersion = version;
		const auto link = map.constFind("link");
		if (link == map.constEnd()) {
			return false;
		} else if (!(*link).isString()) {
			return false;
		}
		bestLink = (*link).toString();
		return true;
	};
	const auto success = ParseCommonMap(response, testing(), accumulate);
	if (!success) {
		return std::nullopt;
	}
	const auto result = ExtractUrlBase(_url) + bestLink.replace(
		"{version}",
		QString::number(bestAvailableVersion));
	if (bestAvailableVersion <= _instance->currentVersion()) {
		return ParsedVersion{ QString(), 0 };
	}
	return ParsedVersion{ result, bestAvailableVersion };
}

HttpChecker::~HttpChecker() {
	clearSentRequest();
}

} // namespace Updater::details
