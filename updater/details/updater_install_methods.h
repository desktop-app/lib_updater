// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

namespace Updater::details {

bool Restart(
	const QString &source,
	QString canonicalExecutableName,
	QStringList relaunchArguments);

int Install(const QStringList &arguments);

} // namespace Updater::details
