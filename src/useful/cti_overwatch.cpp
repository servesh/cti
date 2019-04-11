/******************************************************************************\
 * cti_overwatch_process.c - cti overwatch process used to ensure child
 *                           processes will be cleaned up on unexpected exit.
 *
 * Copyright 2014 Cray Inc.  All Rights Reserved.
 *
 * Unpublished Proprietary Information.
 * This unpublished work is protected to trade secret, copyright and other laws.
 * Except as permitted by contract or express written permission of Cray Inc.,
 * no part of this work or its content may be used, reproduced or disclosed
 * in any form.
 *
 * $HeadURL$
 * $Date$
 * $Rev$
 * $Author$
 *
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>

#include <algorithm>
#include <tuple>
#include <set>
#include <unordered_map>
#include <future>
#include <vector>

#include "cti_defs.h"
#include "useful/cti_argv.hpp"

#include "cti_overwatch.hpp"

void
usage(char const *argv0)
{
	fprintf(stdout, "Usage: %s [OPTIONS]...\n", argv0);
	fprintf(stdout, "Create an overwatch process to ensure children are cleaned up on parent exit\n");
	fprintf(stdout, "This should not be called directly.\n\n");

	fprintf(stdout, "\t-%c, --%s  pid of original client application (required)\n",
		CTIOverwatchArgv::ClientPID.val, CTIOverwatchArgv::ClientPID.name);
	fprintf(stdout, "\t-%c, --%s  control msgqueue key (required)\n",
		CTIOverwatchArgv::QueueKey.val, CTIOverwatchArgv::QueueKey.name);
	fprintf(stdout, "\t-%c, --%s  Display this text and exit\n\n",
		CTIOverwatchArgv::Help.val, CTIOverwatchArgv::Help.name);
}

static void tryTerm(pid_t const pid)
{
	if (::kill(pid, SIGTERM)) {
		return;
	}
	::sleep(3);
	::kill(pid, SIGKILL);
	::waitpid(pid, nullptr, 0);
}

/* types */

struct ProcSet
{
	std::set<pid_t> m_pids;

	ProcSet() {}

	ProcSet(ProcSet&& moved)
		: m_pids{std::move(moved.m_pids)}
	{
		moved.m_pids.clear();
	}

	void clear()
	{
		// copy and clear member
		auto const pids = m_pids;
		m_pids.clear();

		// create futures
		std::vector<std::future<void>> termFutures;
		termFutures.reserve(m_pids.size());

		// terminate in parallel
		for (auto&& pid : pids) {
			fprintf(stderr, "terminating pid %d\n", pid);
			termFutures.emplace_back(std::async(std::launch::async, tryTerm, pid));
		}

		// collect
		for (auto&& future : termFutures) {
			future.wait();
		}
	}

	~ProcSet()
	{
		if (!m_pids.empty()) {
			clear();
		}
	}

	void insert(pid_t const pid)   { m_pids.insert(pid); }
	void erase(pid_t const pid)    { m_pids.erase(pid);  }
	bool contains(pid_t const pid) { return (m_pids.find(pid) != m_pids.end()); }
};

/* global variables */

// messaging
pid_t clientPid = pid_t{-1};
auto msgQueue = MsgQueue<OverwatchMsgType, OverwatchData>{};

// running apps / utils
auto appList = ProcSet{};
auto utilMap = std::unordered_map<pid_t, ProcSet>{};

// threading helpers
std::vector<std::future<void>> runningThreads;
template <typename Func>
void start_thread(Func&& func) {
	runningThreads.emplace_back(std::async(std::launch::async, func));
}
void finish_threads() {
	for (auto&& future : runningThreads) {
		future.wait();
	}
}

void shutdown()
{
	// terminate all running utilities
	start_thread([&](){ utilMap.clear(); });

	// terminate all running apps
	start_thread([&](){ appList.clear(); });

	// clean up msgQueue
	msgQueue.deregister();

	// wait for all threads
	finish_threads();
}

// sigchld handler
void
sigchld_handler(int sig)
{
	if (sig != SIGCHLD) {
		return;
	}

	pid_t exitedPid;
	while ((exitedPid = waitpid(-1, nullptr, WNOHANG)) != -1) {

		// abnormal cti termination
		if (exitedPid == clientPid) {

			// run final cleanup
			shutdown();

			exit(1);

		// regular app termination
		} else if (appList.contains(exitedPid)) {
			// app already terminated
			appList.erase(exitedPid);

			// terminate all of app's utilities
			start_thread([&](){ utilMap.erase(exitedPid); });
		}
	}
}

int 
main(int argc, char *argv[])
{
	{ auto incomingArgv = cti_argv::IncomingArgv<CTIOverwatchArgv>{argc, argv};
		int c; std::string optarg;
		while (true) {
			std::tie(c, optarg) = incomingArgv.get_next();
			if (c < 0) {
				break;
			}

			switch (c) {

			case CTIOverwatchArgv::ClientPID.val:
				clientPid = std::stoll(optarg);
				fprintf(stderr, "client pid %d\n", clientPid);
				break;

			case CTIOverwatchArgv::QueueKey.val:
				msgQueue = MsgQueue<OverwatchMsgType, OverwatchData>{std::stoi(optarg)};
				fprintf(stderr, "msgqueue key %d\n", std::stoi(optarg));
				break;

			case CTIOverwatchArgv::Help.val:
				usage(argv[0]);
				exit(0);

			case '?':
			default:
				usage(argv[0]);
				exit(1);

			}
		}
	}

	if ((clientPid < 0) || !msgQueue) {
		usage(argv[0]);
		exit(1);
	}

	auto throw_if = [](int const result) {
		if (result) { throw std::runtime_error(strerror(errno)); }
	};

	// ensure all signals except SIGCHLD are blocked
	sigset_t mask;
	throw_if(sigfillset(&mask));
	throw_if(sigdelset(&mask, SIGCHLD));
	throw_if(sigprocmask(SIG_SETMASK, &mask, nullptr));

	// setup the SIGCHLD handler
	struct sigaction sigchld_action;
	memset(&sigchld_action, 0, sizeof(sigchld_action));
	throw_if(sigfillset(&sigchld_action.sa_mask));
	sigchld_action.sa_handler = sigchld_handler;
	throw_if(sigaction(SIGCHLD, &sigchld_action, nullptr));

	// wait for msgQueue command
	while (true) {
		OverwatchMsgType msgType; OverwatchData msgData;
		std::tie(msgType, msgData) = msgQueue.recv();

		switch (msgType) {

		case OverwatchMsgType::AppRegister:
			if (msgData.appPid > 0) {

				// register app pid
				appList.insert(msgData.appPid);

			} else {
				throw std::runtime_error("invalid app pid: " + std::to_string(msgData.appPid));
			}
			break;

		case OverwatchMsgType::UtilityRegister:
			if (msgData.appPid > 0) {
				if (msgData.utilPid > 0) {

					// register app pid if not tracked
					if (!appList.contains(msgData.appPid)) {
						appList.insert(msgData.appPid);
					}

					// register utility pid to app
					utilMap[msgData.appPid].insert(msgData.utilPid);

				} else {
					throw std::runtime_error("invalid util pid: " + std::to_string(msgData.utilPid));
				}
			} else {
				throw std::runtime_error("invalid app pid: " + std::to_string(msgData.appPid));
			}
			break;

		case OverwatchMsgType::AppDeregister:
			if (msgData.appPid > 0) {

				// terminate all of app's utilities
				start_thread([&](){ utilMap.erase(msgData.appPid); });

				// ensure app is terminated
				if (appList.contains(msgData.appPid)) {
					start_thread([&](){ tryTerm(msgData.appPid); });
					start_thread([&](){ appList.erase(msgData.appPid); });
				}

			} else {
				throw std::runtime_error("invalid app pid: " + std::to_string(msgData.appPid));
			}
			break;

		case OverwatchMsgType::Shutdown:
			shutdown();

			return 0;

		default:
			fprintf(stderr, "unknown msg type %ld data %d %d\n", msgType, msgData.appPid, msgData.utilPid);
			break;

		}
	}
}

