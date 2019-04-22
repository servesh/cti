/*********************************************************************************\
 * Frontend.hpp - define workload manager frontend interface and common base class
 *
 * Copyright 2014-2019 Cray Inc.    All Rights Reserved.
 *
 * Unpublished Proprietary Information.
 * This unpublished work is protected to trade secret, copyright and other laws.
 * Except as permitted by contract or express written permission of Cray Inc.,
 * no part of this work or its content may be used, reproduced or disclosed
 * in any form.
 *
 *********************************************************************************/

#pragma once

#include <cstdarg>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include <pwd.h>

#include "cti_fe_iface.hpp"

#include "useful/cti_log.h"
#include "useful/cti_useful.h"
#include "useful/cti_overwatch.h"

struct CTIHost {
    std::string hostname;
    size_t      numPEs;
};

using CStr      = const char*;
using CArgArray = const char* const[];

/* CTI Frontend object interfaces */

// This is used to ensure the static global pointers get cleaned up upon exit
class Frontend_cleanup final {
public:
    Frontend_cleanup() = default;
    ~Frontend_cleanup();
};

// Forward declarations
class App;

/*
**
** The Frontend object is defined below. It defines the generic WLM interface that
** all implementations must implement. It is an abstract base class, so we are
** never able to instantiate a Frontend object without the specialization that
** implements the generic WLM interface. Anything that is frontend related, but
** not WLM specific should be implemented directly in the base Frontend.
*/
class Frontend {
public: // impl.-specific interface that derived type must implement
    // wlm type
    virtual cti_wlm_type
    getWLMType() const = 0;

    // launch application with barrier
    virtual std::weak_ptr<App>
    launchBarrier(CArgArray launcher_argv, int stdout_fd, int stderr_fd,
                  CStr inputFile, CStr chdirPath, CArgArray env_list) = 0;

    // create an application instance from an already-running job (the number of IDs used to
    // represent a job is implementation-defined)
    virtual std::weak_ptr<App>
    registerJob(size_t numIds, ...) = 0;

    // get hostname of current node
    virtual std::string
    getHostname(void) const = 0;

private: // Private static data members that are accessed only via base frontend
    static std::atomic<Frontend*>               m_instance;
    static std::mutex                           m_mutex;
    static std::unique_ptr<Frontend_cleanup>    m_cleanup;

private: // Private data members usable only by the base Frontend
    FE_iface            m_iface;

protected: // Protected data members that belong to any frontend
    struct passwd       m_pwd;
    std::vector<char>   m_pwd_buf;
    // Directory paths
    std::string         m_cfg_dir;
    std::string         m_base_dir;
    std::string         m_ld_audit_path;
    std::string         m_overwatch_path;
    std::string         m_dlaunch_path;

protected: // Ownership sets
    // Frontends have direct ownership of all App objects
    std::unordered_set<std::shared_ptr<App>>    m_apps;

public: // Values set by cti_setAttribute
    bool                m_stage_deps;

private: // Private static utility methods used by the generic frontend
    // get the logger associated with the frontend - can only construct logger
    // after fe instantiation!
    static cti::Logger& getLogger(void);
    // get the frontend type for this system
    static cti_wlm_type detect_Frontend();

public: // Public static utility methods - Try to keep these to a minimum
    // Get the singleton instance to the Frontend
    static Frontend& inst();
    // Used to destroy the singleton
    static void destroy();

private: // Private utility methods used by the generic frontend
    static bool isRunningOnBackend() { return (getenv(BE_GUARD_ENV_VAR) != nullptr); }
    // use user info to build unique staging path; optionally create the staging direcotry
    std::string findCfgDir(struct passwd& pwd);
    // find the base CTI directory from the environment and verify its permissions
    std::string findBaseDir(void);
    // Try to cleanup old files left in the cfg dir during the ctor.
    void doFileCleanup();

// FIXME: Remove the overwatch stuff after integration
public:
    cti::overwatch_handle make_overwatch_handle(pid_t targetPid);

public: // Public interface to generic WLM-agnostic capabilities
    // Write to the log file associated with the Frontend
    template <typename... Args>
    void writeLog(char const* fmt, Args&&... args)
    {
        getLogger().write(fmt, std::forward<Args>(args)...);
    }
    // Remove an app object
    void removeApp(std::shared_ptr<App> app)
    {
        // drop the shared_ptr
        m_apps.erase(app);
    }
    // Interface accessor - guarantees access via singleton object
    FE_iface& Iface() { return m_iface; }
    // Register a cleanup file
    void addFileCleanup(std::string file);
    // Accessors
    std::string getCfgDir() { return m_cfg_dir; }
    std::string getBaseDir() { return m_base_dir; }
    std::string getLdAuditPath() { return m_ld_audit_path; }
    std::string getOverwatchPath() { return m_overwatch_path; }
    std::string getDlaunchPath() { return m_dlaunch_path; }

protected: // Constructor/destructors
    Frontend();
public:
    virtual ~Frontend() = default;
    Frontend(const Frontend&) = delete;
    Frontend& operator=(const Frontend&) = delete;
};

// Forward declarations
class Session;

// This is the app instance interface that all wlms should implement.
// We only create weak_ptr to the base, not the derived.
// XXX: This takes a reference to the fe object. Once we move to C++20 we can
// use std:atomic on shared_ptr and weak_ptr, so rethink the design then.
class App : public std::enable_shared_from_this<App> {
public: // impl.-specific interface that derived type must implement
    /* app host setup accessors */

    // return the string version of the job identifer
    virtual std::string getJobId() const = 0;

    // get hostname where the job launcher was started
    virtual std::string getLauncherHostname() const = 0;

    // get backend base directory used for staging
    virtual std::string getToolPath() const = 0;

    // get backend directory where the pmi_attribs file can be found
    virtual std::string getAttribsPath() const = 0;

    /* app file setup accessors */

    // extra wlm specific binaries required by backend library
    virtual std::vector<std::string> getExtraBinaries() const { return {}; }

    // extra wlm specific libraries required by backend library
    virtual std::vector<std::string> getExtraLibraries() const { return {}; }

    // extra wlm specific library directories required by backend library
    virtual std::vector<std::string> getExtraLibDirs() const { return {}; }

    // extra wlm specific files required by backend library
    virtual std::vector<std::string> getExtraFiles() const { return {}; }

    /* running app information accessors */

    // retrieve number of PEs in app
    virtual size_t getNumPEs() const = 0;

    // retrieve number of compute nodes in app
    virtual size_t getNumHosts() const = 0;

    // get hosts list for app
    virtual std::vector<std::string> getHostnameList() const = 0;

    // get PE rank/host placement for app
    virtual std::vector<CTIHost> getHostsPlacement() const = 0;

    /* running app interaction interface */

    // release app from barrier
    virtual void releaseBarrier() = 0;

    // kill application
    virtual void kill(int signal) = 0;

    // ship package to backends
    virtual void shipPackage(std::string const& tarPath) const = 0;

    // start backend tool daemon
    virtual void startDaemon(CArgArray argv) = 0;

protected: // Protected data members that belong to any App
    // Reference to Frontend associated with App
    Frontend& m_frontend;
    // Apps have direct ownership of all Session objects underneath it
    std::unordered_set<std::shared_ptr<Session>> m_sessions;

public:
    // App specific logger
    template <typename... Args>
    void writeLog(char const* fmt, Args&&... args) const {
        m_frontend.writeLog((getJobId() + ":" + fmt).c_str(), std::forward<Args>(args)...);
    }

public: // Public interface to generic WLM-agnostic capabilities
    // Create a new session associated with this app
    std::weak_ptr<Session> createSession() {
        auto ret = m_sessions.emplace(std::make_shared<Session>(*this));
        if (!ret.second) {
            throw std::runtime_error("Failed to create new Session object.");
        }
        return *ret.first;
    }
    // Remove a session object
    void removeSession(std::shared_ptr<Session>& sess) {
        // drop the shared_ptr
        m_sessions.erase(sess);
    }
    // Frontend acessor
    // TODO: When we switch to std::atomic on shared_ptr with C++20,
    // this can return a shared_ptr handle instead.
    Frontend& getFrontend() { return m_frontend; }

public: // Constructor/destructors
    App(Frontend& fe)
    : m_frontend{fe}, m_sessions{}
    { }
    virtual ~App() = default;
    App(const App&) = delete;
    App& operator=(const App&) = delete;
};
