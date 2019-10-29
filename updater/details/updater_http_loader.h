// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "updater/details/updater_loader.h"

#include <QtCore/QThread>

namespace Updater::details {

class HttpLoaderActor;

class HttpLoader : public Loader {
public:
	HttpLoader(const QString &path, const QString &url);

	~HttpLoader();

private:
	void startLoading() override;

	friend class HttpLoaderActor;

	QString _url;
	std::unique_ptr<QThread> _thread;
	HttpLoaderActor *_actor = nullptr;

};

} // namespace Updater::details
