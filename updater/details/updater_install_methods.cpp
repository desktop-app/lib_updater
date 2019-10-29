// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/details/updater_install_methods.h"

#include "updater/updater_instance.h"
#include "base/integration.h"
#include "base/platform/base_platform_file_utilities.h"

#include <QtCore/QDir>
#include <QtCore/QProcess>

#ifdef Q_OS_WIN

#include "base/platform/win/base_windows_h.h"
#include <Shellapi.h>
#include <Shlwapi.h>
#include <ShlObj.h>

#else // Q_OS_WIN

#include <sys/stat.h>
#include <unistd.h>
#include <iostream>

#endif // Q_OS_WIN

namespace Updater::details {
namespace {

[[nodiscard]] bool IsWriteProtected(const QString &directory) {
	auto f = QFile(directory + "_updater_check.tmp");
	const auto good = f.open(QIODevice::WriteOnly) && f.write("1", 1) == 1;
	f.close();
	f.remove();

	return !good;
}

[[nodiscard]] int ReadVersion(const QString &path) {
	auto f = QFile(path);
	const auto content = f.open(QIODevice::ReadOnly)
		? f.readAll()
		: QByteArray();
	return QString::fromLatin1(content).toInt();
}

#ifdef Q_OS_WIN

bool CopyWithOverwrite(const QString &src, const QString &dst) {
	QDir().mkpath(QFileInfo(dst).absolutePath());

	const auto nativeSource = QDir::toNativeSeparators(src).toStdWString();
	const auto nativeTarget = QDir::toNativeSeparators(dst).toStdWString();
	int copyTries = 0;
	do {
		const auto copied = CopyFile(
			nativeSource.c_str(),
			nativeTarget.c_str(),
			FALSE);
		if (!copied) {
			++copyTries;
			Sleep(100);
		} else {
			break;
		}
		if (!(copyTries % 10)) {
			base::Platform::CloseProcesses(dst);
		}
	} while (copyTries < 100);
	return (copyTries < 100);
}

struct NativeLaunch {
	std::wstring launchPath;
	std::wstring workingDirectory;
	std::wstring arguments;
};

[[nodiscard]] NativeLaunch Native(
		const QString &path,
		const QStringList &arguments) {
	const auto convertPath = [](const QString &path) {
		return QDir::toNativeSeparators(path).toStdWString();
	};
	return {
		convertPath(path),
		convertPath(QDir::currentPath()),
		('"' + arguments.join("\" \"") + '"').toStdWString()
	};
}

bool Launch(
		const QString &path,
		const QStringList &arguments,
		bool runElevated) {
	const auto operation = runElevated ? L"runas" : nullptr;
	const auto native = Native(path, arguments);
	const auto hwnd = HWND(0);
	const auto result = ShellExecute(
		hwnd,
		operation,
		native.launchPath.c_str(),
		native.arguments.c_str(),
		native.workingDirectory.c_str(),
		SW_SHOWNORMAL);
	return (long(result) >= 32);
}

bool LaunchAsNormalUser(
		const QString &tempLocation,
		const QString &path,
		const QStringList &arguments) {
	const auto simple = [&] {
		return Launch(path, arguments, false);
	};
	if (!SUCCEEDED(CoInitialize(0))) {
		return simple();
	}
	const auto comGuard = gsl::finally([&] { CoUninitialize(); });

	auto psl = (IShellLink*)nullptr;
	const auto pslResult = CoCreateInstance(
		CLSID_ShellLink,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IShellLink,
		(LPVOID*)&psl);
	if (!SUCCEEDED(pslResult)) {
		return simple();
	}
	const auto pslGuard = gsl::finally([&] { psl->Release(); });

	auto ppf = (IPersistFile*)nullptr;

	const auto native = Native(path, arguments);
	psl->SetArguments(native.arguments.c_str());
	psl->SetPath(native.launchPath.c_str());
	psl->SetWorkingDirectory(native.workingDirectory.c_str());
	psl->SetDescription(L"");

	const auto ppfResult = psl->QueryInterface(
		IID_IPersistFile,
		(LPVOID*)&ppf);
	if (!SUCCEEDED(ppfResult)) {
		return simple();
	}
	const auto ppfGuard = gsl::finally([&] { ppf->Release(); });

	const auto link = QDir::toNativeSeparators(
		tempLocation + "_updater_link.lnk"
	).toStdWString();

	if (!SUCCEEDED(ppf->Save(link.c_str(), TRUE))) {
		return simple();
	}

	ShellExecute(0, 0, L"explorer.exe", link.c_str(), 0, SW_SHOWNORMAL);
	return true;
}

bool UpdateRegistry(const InfoForRegistry &info, int version) {
	auto rkey = HKEY();
	const auto path = ("Software\\Microsoft\\Windows\\CurrentVersion\\"
		"Uninstall\\{" + info.guid + "}_is1").toStdWString();
	const auto status = RegOpenKeyEx(
		HKEY_CURRENT_USER,
		path.c_str(),
		0,
		KEY_QUERY_VALUE | KEY_SET_VALUE,
		&rkey);
	if (status != ERROR_SUCCESS) {
		return false;
	}
	const auto major = version / 1000000;
	const auto minor = (version % 1000000) / 1000;
	const auto patch = version % 1000;
	const auto versionString = patch
		? QString("%1.%2.%3").arg(major).arg(minor).arg(patch)
		: QString("%1.%2").arg(major).arg(minor);
	auto stLocalTime = SYSTEMTIME();
	GetLocalTime(&stLocalTime);

	const auto wideVersion = versionString.toStdWString();
	const auto wideName = (info.fullName + " version ").toStdWString()
		+ wideVersion;
	const auto widePublisher = info.publisher.toStdWString();
	const auto wideIconGroup = info.iconGroup.toStdWString();
	const auto wideDate = QString("%1%2%3"
	).arg(stLocalTime.wYear, 4, 10, QChar('0')
	).arg(stLocalTime.wMonth, 2, 10, QChar('0')
	).arg(stLocalTime.wDay, 2, 10, QChar('0')).toStdWString();
	const auto wideHelpLink = info.helpLink.toStdWString();
	const auto wideSupportLink = info.supportLink.toStdWString();
	const auto wideUpdateLink = info.updateLink.toStdWString();

	const auto set = [&](const wchar_t *name, const std::wstring &value) {
		auto bytes = std::vector<BYTE>((value.size() + 1) * 2, 0);
		memcpy(bytes.data(), value.c_str(), bytes.size());
		RegSetValueEx(rkey, name, 0, REG_SZ, bytes.data(), bytes.size());
	};
	set(L"DisplayVersion", wideVersion);
	set(L"DisplayName", wideName);
	set(L"Publisher", widePublisher);
	set(L"Inno Setup: Icon Group", wideIconGroup);
	set(L"InstallDate", wideDate);
	set(L"HelpLink", wideHelpLink);
	set(L"URLInfoAbout", wideSupportLink);
	set(L"URLUpdateInfo", wideUpdateLink);

	RegCloseKey(rkey);
	return true;
}

#else // Q_OS_WIN

bool CopyWithOverwrite(const QString &src, const QString &dst) {
	QDir().mkpath(QFileInfo(dst).absolutePath());
	QFile(dst).remove();
	if (QFile(src).rename(dst)) {
		std::cout << "Renamed!.." << std::endl;
		return true;
	}

	std::cout << "Copy with overwrite :(.." << std::endl;

	const auto from = QFile::encodeName(src).toStdString();
	const auto to = QFile::encodeName(dst).toStdString();
	const auto ffrom = fopen(from.c_str(), "rb");
	const auto fto = fopen(to.c_str(), "wb");
	if (!ffrom) {
		if (fto) fclose(fto);
		return false;
	}
	if (!fto) {
		fclose(ffrom);
		return false;
	}
	static const int BufSize = 65536;
	char buf[BufSize];
	while (size_t size = fread(buf, 1, BufSize, ffrom)) {
		fwrite(buf, 1, size, fto);
	}

	// From http://stackoverflow.com/questions/5486774/keeping-fileowner-and-permissions-after-copying-file-in-c
	struct stat fst;
	//let's say this wont fail since you already worked OK on that fp
	if (fstat(fileno(ffrom), &fst) != 0) {
		fclose(ffrom);
		fclose(fto);
		return false;
	}
	//update to the same uid/gid
	if (fchown(fileno(fto), fst.st_uid, fst.st_gid) != 0) {
		fclose(ffrom);
		fclose(fto);
		return false;
	}
	//update the permissions
	if (fchmod(fileno(fto), fst.st_mode) != 0) {
		fclose(ffrom);
		fclose(fto);
		return false;
	}

	fclose(ffrom);
	fclose(fto);

	return true;
}

bool Launch(
		const QString &path,
		const QStringList &arguments,
		bool runElevated) {
#ifdef Q_OS_MAC
	base::Platform::RemoveQuarantine(path);
#endif // Q_OS_MAC

	std::cout << "Will launch:" << std::endl;
	std::cout << path.toStdString() << std::endl;
	std::cout << "Arguments:" << std::endl;
	for (const auto &argument : arguments) {
		std::cout << argument.toStdString() << std::endl;
	}
	auto process = QProcess();
	process.setProgram(path);
	process.setArguments(arguments);
	std::cout << "Starting!" << std::endl;
	return process.startDetached();
}

bool LaunchAsNormalUser(
		const QString &tempLocation,
		const QString &path,
		const QStringList &arguments) {
	return Launch(path, arguments, false);
}

void UpdateRegistry(const InfoForRegistry &info, int version) {
}

#endif // Q_OS_WIN

struct InstallArguments {
	QString source;
	QString self;
	QString target;
	QString executable;
	bool writeProtected = false;
	QStringList relaunchArguments;
};

[[nodiscard]] InstallArguments ParseInstallArguments(QStringList arguments) {
	const auto relaunchArgumentsIndex = arguments.indexOf("--");
	const auto relaunchArguments = (relaunchArgumentsIndex > 0)
		? arguments.mid(relaunchArgumentsIndex + 1)
		: QStringList();

	auto next = QString();
	auto values = std::map<QString, QString>();
	for (const auto &argument : arguments.mid(0, relaunchArgumentsIndex)) {
		if (!next.isEmpty()) {
			values[next] = argument;
			next = QString();
		} else if (argument.startsWith("--")) {
			next = argument;
		}
	}
	return {
		values["--source"],
		values["--self"],
		values["--target"],
		values["--executable"],
		(values["--writeprotected"] == "1"),
		relaunchArguments
	};
}

[[nodiscard]] bool ResolvePaths(QFileInfoList &list) {
	auto hasDirectories = bool();
	do {
		hasDirectories = false;
		for (auto i = list.begin(); i != list.end(); ++i) {
			const auto info = *i;
			if (info.isDir()) {
				hasDirectories = true;
				list.erase(i);
				const auto directory = QDir(info.absoluteFilePath());
				const auto mask = QDir::Files
					| QDir::Dirs
					| QDir::NoSymLinks
					| QDir::NoDotAndDotDot;
				list.append(directory.entryInfoList(mask));
				break;
			} else if (!info.isReadable()) {
				return false;
			}
		}
	} while (hasDirectories);
	return true;
}

[[nodiscard]] std::map<QString, QString> CollectCopyRequests(
		const InstallArguments &values) {
	const auto base = values.source;
#ifdef Q_OS_MAC
	const auto canonical = values.self + ".app";
#else // Q_OS_MAC
	const auto canonical = values.self;
#endif // Q_OS_MAC
	auto list = QFileInfoList() << QFileInfo(base);
	if (!ResolvePaths(list)) {
		return {};
	}
	auto result = std::map<QString, QString>();
	for (const auto &entry : list) {
		const auto path = entry.absoluteFilePath();
		if (!path.startsWith(base, Qt::CaseInsensitive)) {
			return {};
		}
		const auto relative = path.mid(base.size());
		const auto target = relative.startsWith(canonical, Qt::CaseInsensitive)
			? (values.target + values.executable + relative.mid(canonical.size()))
			: (values.target + relative);
		result[path] = target;
		std::cout << path.toStdString() << " ->" << std::endl;
		std::cout << "-> " << target.toStdString() << std::endl;
	}
	return result;
}

} // namespace

bool Restart(
		const QString &source,
		QString canonicalExecutableName,
		QStringList relaunchArguments) {
	const auto ready = source + "ready";
	const auto target = base::Integration::Instance().executableDir();
	const auto executable = base::Integration::Instance().executableName();
	if (target.isEmpty() || executable.isEmpty()) {
		QFile(ready).remove();
		return false;
	}
#ifdef Q_OS_WIN
	canonicalExecutableName += ".exe";
#endif // Q_OS_WIN || Q_OS_MAC

	const auto fullPath = source + canonicalExecutableName;

#ifdef Q_OS_MAC
	const auto innerPath = ".app/Contents/MacOS/" + canonicalExecutableName;
	const auto launchPath = fullPath + innerPath;
#else // Q_OS_MAC
	const auto launchPath = fullPath;
#endif // Q_OS_MAC

	if (!QFile(launchPath).exists()) {
		QFile(ready).remove();
		return false;
	}

	const auto writeProtected = IsWriteProtected(target);
	auto arguments = QStringList()
		<< "installupdate"
		<< "--source"
		<< source
		<< "--self"
		<< canonicalExecutableName
		<< "--target"
		<< target
		<< "--executable"
		<< executable
		<< "--writeprotected"
		<< (writeProtected ? "1" : "0")
		<< "--"
		<< relaunchArguments;

	return Launch(
		launchPath,
		std::move(arguments),
		writeProtected);
}

int Install(const QStringList &arguments, const InfoForRegistry &info) {
	const auto values = ParseInstallArguments(arguments);
	if (values.executable.isEmpty()
		|| values.self.isEmpty()
		|| values.source.isEmpty()
		|| values.target.isEmpty()) {
		return -1;
	}
	const auto version = ReadVersion(values.source + "_update_version.tmp");
	QFile(values.source + "ready").remove();
	QFile(values.source + "_update_version.tmp").remove();

	const auto copies = CollectCopyRequests(values);

#ifdef Q_OS_MAC
	base::Platform::DeleteDirectory(values.target + values.executable + "/Contents");
#endif // Q_OS_MAC

	for (const auto &[src, dst] : copies) {
		if (!CopyWithOverwrite(src, dst)) {
			return -1;
		}
	}
	if (version > 0) {
		UpdateRegistry(info, version);
	}

	const auto fullPath = values.target + values.executable;
#ifdef Q_OS_MAC
	const auto innerPath = "/Contents/MacOS/" + values.self;
	const auto launchPath = fullPath + innerPath;
#else // Q_OS_MAC
	const auto launchPath = fullPath;
#endif // Q_OS_MAC
	const auto relaunched = values.writeProtected
		? LaunchAsNormalUser(values.source, launchPath, values.relaunchArguments)
		: Launch(launchPath, values.relaunchArguments, false);
	std::cout << "Result: " << (relaunched ? 0 : -1) << std::endl;
	return relaunched ? 0 : -1;
}

} // namespace Updater::details
