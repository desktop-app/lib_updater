// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "base/weak_ptr.h"

#include <rpl/producer.h>
#include <rpl/event_stream.h>

namespace Updater::details {

class Loader;

class Checker : public base::has_weak_ptr {
public:
	Checker(bool testing);

	virtual void start() = 0;

	rpl::producer<std::shared_ptr<Loader>> ready() const;
	rpl::producer<> failed() const;

	rpl::lifetime &lifetime();

	virtual ~Checker() = default;

protected:
	bool testing() const;
	void done(std::shared_ptr<Loader> result);
	void fail();

private:
	bool _testing = false;
	rpl::event_stream<std::shared_ptr<Loader>> _ready;
	rpl::event_stream<> _failed;

	rpl::lifetime _lifetime;

};

} // namespace Updater::details