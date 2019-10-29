// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/updater_instance.h"

#include "updater/details/updater_http_checker.h"
#include "updater/details/updater_loader.h"
#include "updater/details/updater_unpack.h"
#include "updater/details/updater_install_methods.h"
#include "base/platform/base_platform_info.h"
#include "base/platform/base_platform_file_utilities.h"
#include "base/integration.h"
#include "base/timer.h"
#include "base/bytes.h"
#include "base/unixtime.h"
#include "base/weak_ptr.h"

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QMutex>
#include <QtCore/QRegularExpression>
#include <QtCore/QProcess>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkAccessManager>

namespace Updater {
namespace {

constexpr auto kTimeout = 10 * crl::time(1000);

using namespace details;

} // namespace

int Install(const QStringList &arguments, const InfoForRegistry &info) {
	return details::Install(arguments, info);
}

Instance::Instance(const Settings &settings, int currentVersion)
: _settings(settings)
, _currentVersion(currentVersion)
, _timer([=] { check(); })
, _retryTimer([=] { handleTimeout(); }) {
	checking() | rpl::start_with_next([=] {
		handleChecking();
	}, _lifetime);
	progress() | rpl::start_with_next([=] {
		handleProgress();
	}, _lifetime);
	failed() | rpl::start_with_next([=] {
		handleFailed();
	}, _lifetime);
	ready() | rpl::start_with_next([=] {
		handleReady();
	}, _lifetime);
	isLatest() | rpl::start_with_next([=] {
		handleLatest();
	}, _lifetime);
}

Instance::~Instance() {
	stop();
}

rpl::producer<> Instance::checking() const {
	return _checking.events();
}

rpl::producer<> Instance::isLatest() const {
	return _isLatest.events();
}

auto Instance::progress() const
-> rpl::producer<Progress> {
	return _progress.events();
}

rpl::producer<> Instance::failed() const {
	return _failed.events();
}

rpl::producer<> Instance::ready() const {
	return _ready.events();
}

void Instance::check() {
	start(Start::Normal);
}

void Instance::updateLastCheckTime() {
	_lastCheckTime = base::unixtime::now();
}

int Instance::currentVersion() const {
	return _currentVersion;
}

QString Instance::downloadPath() const {
	return _settings.basePath + "updates/";
}

QString Instance::unpackPath() const {
	return _settings.basePath + "updates/unpacked/";
}

void Instance::clearAll() {
	stop();
	base::Platform::DeleteDirectory(downloadPath());
}

QString Instance::findUpdateFile() const {
	const auto updates = QDir(downloadPath());
	if (!updates.exists()) {
		return QString();
	}
	const auto list = updates.entryInfoList(QDir::Files);
	for (const auto &info : list) {
		if (QRegularExpression(
			"^update-\\d+$",
			QRegularExpression::CaseInsensitiveOption
		).match(info.fileName()).hasMatch()) {
			return info.absoluteFilePath();
		}
	}
	return QString();
}

void Instance::handleReady() {
	stop();
	_action = Action::Ready;
	updateLastCheckTime();
}

void Instance::handleFailed() {
	scheduleNext();
}

void Instance::handleLatest() {
	if (const auto update = findUpdateFile(); !update.isEmpty()) {
		QFile(update).remove();
	}
	scheduleNext();
}

void Instance::handleChecking() {
	_action = Action::Checking;
	_retryTimer.callOnce(kTimeout);
}

void Instance::handleProgress() {
	_retryTimer.callOnce(kTimeout);
}

void Instance::scheduleNext() {
	stop();
	updateLastCheckTime();
	start(Start::Wait);
}

auto Instance::state() const -> State {
	if (_action == Action::Ready) {
		return State::Ready;
	} else if (_action == Action::Loading) {
		return State::Download;
	}
	return State::None;
}

int Instance::size() const {
	return _activeLoader ? _activeLoader->totalSize() : 0;
}

int Instance::already() const {
	return _activeLoader ? _activeLoader->alreadySize() : 0;
}

void Instance::stop() {
	_httpImplementation = Implementation();
	_activeLoader = nullptr;
	_action = Action::Waiting;
}

void Instance::cancel() {
	stop();
	QFile(unpackPath() + "ready").remove();
	if (const auto name = findUpdateFile(); !name.isEmpty()) {
		QFile(name).remove();
	}
}

void Instance::start(Start type) {
	if (base::Integration::Instance().executablePath().isEmpty()) {
		return;
	}

	_timer.cancel();
	if (_action != Action::Waiting) {
		return;
	} else if (type == Start::Now) {
		_lastCheckTime = 0;
	}

	_retryTimer.cancel();
	const auto constDelay = _settings.delayConstPart;
	const auto randDelay = _settings.delayRandPart;
	const auto updateInSecs = _lastCheckTime
		+ constDelay
		+ int(rand() % randDelay)
		- base::unixtime::now();
	auto sendRequest = (updateInSecs <= 0)
		|| (updateInSecs > constDelay + randDelay);
	if (!sendRequest && type != Start::Wait && !findUpdateFile().isEmpty()) {
		sendRequest = true;
	}

	if (sendRequest) {
		startImplementation(
			&_httpImplementation,
			std::make_unique<HttpChecker>(this, _settings.url, _testing));

		_checking.fire({});
	} else {
		_timer.callOnce((updateInSecs + 5) * crl::time(1000));
	}
}

void Instance::startImplementation(
		not_null<Implementation*> which,
		std::unique_ptr<Checker> checker) {
	if (!checker) {
		class EmptyChecker : public Checker {
		public:
			EmptyChecker() : Checker(false) {
			}

			void start() override {
				crl::on_main(this, [=] { fail(); });
			}

		};
		checker = std::make_unique<EmptyChecker>();
	}

	checker->ready(
	) | rpl::start_with_next([=](std::shared_ptr<Loader> &&loader) {
		checkerDone(which, std::move(loader));
	}, checker->lifetime());
	checker->failed(
	) | rpl::start_with_next([=] {
		checkerFail(which);
	}, checker->lifetime());

	*which = Implementation{ std::move(checker) };

	crl::on_main(which->checker.get(), [=] {
		which->checker->start();
	});
}

void Instance::checkerDone(
		not_null<Implementation*> which,
		std::shared_ptr<Loader> loader) {
	which->checker = nullptr;
	which->loader = std::move(loader);

	tryLoaders();
}

void Instance::checkerFail(not_null<Implementation*> which) {
	which->checker = nullptr;
	which->failed = true;

	tryLoaders();
}

void Instance::test() {
	_testing = true;
	start(Start::Now);
}

void Instance::handleTimeout() {
	if (_action == Action::Checking) {
		const auto reset = [&](Implementation &which) {
			if (base::take(which.checker)) {
				which.failed = true;
			}
		};
		reset(_httpImplementation);
		if (!tryLoaders()) {
			_lastCheckTime = 0;
			_timer.callOnce(kTimeout);
		}
	} else if (_action == Action::Loading) {
		_failed.fire({});
	}
}

bool Instance::tryLoaders() {
	if (_httpImplementation.checker) {
		// Some checkers didn't finish yet.
		return true;
	}
	_retryTimer.cancel();

	const auto tryOne = [&](Implementation &which) {
		_activeLoader = std::move(which.loader);
		if (const auto loader = _activeLoader.get()) {
			_action = Action::Loading;

			loader->progress(
			) | rpl::start_to_stream(_progress, loader->lifetime());
			loader->ready(
			) | rpl::start_with_next([=](QString &&filepath) {
				finalize(std::move(filepath));
			}, loader->lifetime());
			loader->failed(
			) | rpl::start_with_next([=] {
				_failed.fire({});
			}, loader->lifetime());

			_retryTimer.callOnce(kTimeout);
			loader->wipeFolder();
			loader->start();
		} else {
			_isLatest.fire({});
		}
	};
	if (_httpImplementation.failed) {
		_failed.fire({});
		return false;
	} else {
		tryOne(_httpImplementation);
	}
	return true;
}

void Instance::finalize(QString filepath) {
	if (_action != Action::Loading) {
		return;
	}
	_retryTimer.cancel();
	_activeLoader = nullptr;
	_action = Action::Unpacking;
	const auto basePath = unpackPath();
	const auto currentVersion = _currentVersion;
	const auto weak = base::make_weak(this);
	crl::async([=] {
		const auto ready = Unpack(basePath, filepath, currentVersion);
		crl::on_main(weak, [=] {
			unpackDone(ready);
		});
	});
}

void Instance::unpackDone(bool ready) {
	if (ready) {
		_ready.fire({});
	} else {
		clearAll();
		_failed.fire({});
	}
}

bool Instance::readyToRestart() {
	const auto path = unpackPath();
	const auto readyFilePath = path + "ready";
	if (!QFile(readyFilePath).exists()) {
		clearAll();
		return false;
	}

	// check ready version
	const auto versionPath = path + "_update_version.tmp";
	auto f = QFile(versionPath);
	if (!f.open(QIODevice::ReadOnly)) {
		clearAll();
		return false;
	}
	const auto content = f.readAll();
	f.close();
	const auto version = content.isEmpty()
		? int(0)
		: QString::fromLatin1(content).toInt();
	if (version <= _currentVersion) {
		clearAll();
		return false;
	}
	return true;
}

FnMut<void(QString, QStringList)> Instance::restarter() {
	if (!readyToRestart()) {
		return nullptr;
	}
	const auto source = unpackPath();
	return [=](QString canonicalExecutableName, QStringList arguments) {
		Restart(source, canonicalExecutableName, arguments);
	};
}

} // namespace Updater
