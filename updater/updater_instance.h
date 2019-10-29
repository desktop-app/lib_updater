// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "base/timer.h"

namespace Updater {
namespace details {

class Checker;
class Loader;

struct Implementation {
	std::unique_ptr<Checker> checker;
	std::shared_ptr<Loader> loader;
	bool failed = false;
};

} // namespace details

enum class State {
	None,
	Download,
	Ready,
};

struct Progress {
	int64 already = 0;
	int64 size = 0;
};

struct Settings {
	QString basePath;
	QString url;
	TimeId delayConstPart = 0;
	TimeId delayRandPart = 0;
};

// Windows only.
struct InfoForRegistry {
	QString guid;
	QString fullName;
	QString publisher;
	QString iconGroup;
	QString helpLink;
	QString supportLink;
	QString updateLink;
};

int Install(const QStringList &arguments, const InfoForRegistry &info);

class Instance final : public base::has_weak_ptr {
public:
	Instance(const Settings &settings, int currentVersion);
	~Instance();

	[[nodiscard]] rpl::producer<> checking() const;
	[[nodiscard]] rpl::producer<> isLatest() const;
	[[nodiscard]] rpl::producer<Progress> progress() const;
	[[nodiscard]] rpl::producer<> failed() const;
	[[nodiscard]] rpl::producer<> ready() const;

	enum class Start {
		Now,
		Normal,
		Wait,
	};
	void start(Start type);
	void stop();
	void cancel();
	void test();

	[[nodiscard]] State state() const;
	[[nodiscard]] int already() const;
	[[nodiscard]] int size() const;

	void updateLastCheckTime();
	[[nodiscard]] int currentVersion() const;
	[[nodiscard]] QString downloadPath() const;
	void clearAll();

	[[nodiscard]] bool readyToRestart();

	// restarter()(canonicalExecutableName, relaunchArguments);
	[[nodiscard]] FnMut<void(QString, QStringList)> restarter();

private:
	enum class Action {
		Waiting,
		Checking,
		Loading,
		Unpacking,
		Ready,
	};
	void check();
	QString findUpdateFile() const;
	void startImplementation(
		not_null<details::Implementation*> which,
		std::unique_ptr<details::Checker> checker);
	bool tryLoaders();
	void handleTimeout();
	void checkerDone(
		not_null<details::Implementation*> which,
		std::shared_ptr<details::Loader> loader);
	void checkerFail(not_null<details::Implementation*> which);

	void finalize(QString filepath);
	void unpackDone(bool ready);
	void handleChecking();
	void handleProgress();
	void handleLatest();
	void handleFailed();
	void handleReady();
	void scheduleNext();

	[[nodiscard]] QString unpackPath() const;

	const Settings _settings;
	int _currentVersion = 0;
	TimeId _lastCheckTime = 0;
	bool _testing = false;
	Action _action = Action::Waiting;
	base::Timer _timer;
	base::Timer _retryTimer;
	rpl::event_stream<> _checking;
	rpl::event_stream<> _isLatest;
	rpl::event_stream<Progress> _progress;
	rpl::event_stream<> _failed;
	rpl::event_stream<> _ready;
	details::Implementation _httpImplementation;
	std::shared_ptr<details::Loader> _activeLoader;

	rpl::lifetime _lifetime;

};

} // namespace Updater
