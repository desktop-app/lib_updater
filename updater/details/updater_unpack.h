// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

namespace Updater::details {

[[nodiscard]] bool Unpack(
	const QString &basePath,
	const QString &filePath,
	quint32 currentVersion);

} // namespace Updater::details
