// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "updater/details/updater_checker.h"

namespace Updater::details {

Checker::Checker(bool testing) : _testing(testing) {
}

rpl::producer<std::shared_ptr<Loader>> Checker::ready() const {
	return _ready.events();
}

rpl::producer<> Checker::failed() const {
	return _failed.events();
}

bool Checker::testing() const {
	return _testing;
}

void Checker::done(std::shared_ptr<Loader> result) {
	_ready.fire(std::move(result));
}

void Checker::fail() {
	_failed.fire({});
}

rpl::lifetime &Checker::lifetime() {
	return _lifetime;
}

} // namespace Updater::details
