/******************************************************************************\
 * Session.cpp - Session object impl
 *
 * Copyright 2013-2019 Cray Inc.    All Rights Reserved.
 *
 * Unpublished Proprietary Information.
 * This unpublished work is protected to trade secret, copyright and other laws.
 * Except as permitted by contract or express written permission of Cray Inc.,
 * no part of this work or its content may be used, reproduced or disclosed
 * in any form.
 *
 ******************************************************************************/

// This pulls in config.h
#include "cti_defs.h"
#include "cti_argv_defs.hpp"

#include "Archive.hpp"
#include "Manifest.hpp"
#include "Session.hpp"

#include "useful/cti_wrappers.hpp"

// getpid
#include <sys/types.h>
#include <unistd.h>
// valid chars array used in seed generation
static const char _cti_valid_char[] {
    '0','1','2','3','4','5','6','7','8','9',
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z' };
class CTIPRNG {
    char _cti_r_state[256];
public:
    CTIPRNG() {
        // We need to generate a good seed to avoid collisions. Since this
        // library can be used by automated tests, it is vital to have a
        // good seed.
        struct timespec     tv;
        unsigned int        pval;
        unsigned int        seed;

        // get the current time from epoch with nanoseconds
        if (clock_gettime(CLOCK_REALTIME, &tv)) {
            throw std::runtime_error("clock_gettime failed.");
        }

        // generate an appropriate value from the pid, we shift this to
        // the upper 16 bits of the int. This should avoid problems with
        // collisions due to slight variations in nano time and adding in
        // pid offsets.
        pval = (unsigned int)getpid() << ((sizeof(unsigned int) * CHAR_BIT) - 16);

        // Generate the seed. This is not crypto safe, but should have enough
        // entropy to avoid the case where two procs are started at the same
        // time that use this interface.
        seed = (tv.tv_sec ^ tv.tv_nsec) + pval;

        // init the state
        initstate(seed, (char *)_cti_r_state, sizeof(_cti_r_state));

        // set the PRNG state
        if (setstate((char *)_cti_r_state) == NULL) {
            throw std::runtime_error("setstate failed.");
        }
    }

    char genChar() {
        unsigned int oset;

        // Generate a random offset into the array. This is random() modded
        // with the number of elements in the array.
        oset = random() % (sizeof(_cti_valid_char)/sizeof(_cti_valid_char[0]));
        // assing this char
        return _cti_valid_char[oset];
    }
};

static CTIPRNG& _cti_getPRNG()
{
    static CTIPRNG prng;
    return prng;
}


std::string
Session::generateStagePath() {
    std::string stageName;
    // check to see if the caller set a staging directory name, otherwise generate one
    if (const char* customStagePath = getenv(DAEMON_STAGE_VAR)) {
        stageName = customStagePath;
    } else {
        // remove placeholder Xs from DEFAULT_STAGE_DIR
        const std::string stageFormat(DEFAULT_STAGE_DIR);
        stageName = stageFormat.substr(0, stageFormat.find("X"));

        // now start replacing the 'X' characters in the stage_name string with
        // randomness
        size_t numChars = stageFormat.length() - stageName.length();
        for (size_t i = 0; i < numChars; i++) {
            stageName.push_back(_cti_getPRNG().genChar());
        }
    }
    return stageName;
}

Session::Session(App& owningApp)
    : m_AppPtr{owningApp.shared_from_this()}
    , m_manifests{}
    , m_manifestCnt{0}
    , m_seqNum{0}
    , m_folders{}
    , m_sourcePaths{}
    , m_stageName{generateStagePath()}
    , m_stagePath{owningApp.getToolPath() + "/" + m_stageName}
    , m_wlmType{std::to_string(owningApp.getFrontend().getWLMType())}
    , m_ldLibraryPath{m_stagePath + "/lib"} // default libdir /tmp/cti_daemonXXXXXX/lib
{
    // Typically it is bad practice to call class methods from constructors,
    // but in this case we need to ensure we ship dependencies as part of
    // placing the session in a valid state. We have fully constructed the
    // session at this point, and the class is marked final.
    auto wp = createManifest();
    auto mp = wp.lock();
    if (!mp) {
        throw std::runtime_error("Unable to create manifest for session ctor.");
    }
    for (auto const& path : owningApp.getExtraBinaries()) {
        mp->addBinary(path);
    }
    for (auto const& path : owningApp.getExtraLibraries()) {
        mp->addLibrary(path);
    }
    for (auto const& path : owningApp.getExtraLibDirs()) {
        mp->addLibDir(path);
    }
    for (auto const& path : owningApp.getExtraFiles()) {
        mp->addFile(path);
    }

    // ship basefile manifest and run remote extraction
    sendManifest(mp);
}

Session::~Session() {
    // Check to see if we need to try cleanup on compute nodes. We bypass the
    // cleanup if we never shipped a manifest.
    if (m_seqNum == 0) {
        return;
    }
    writeLog("launchCleanup: creating daemonArgv for cleanup\n");
    // get owning app
    auto app = getOwningApp();
    // create DaemonArgv
    cti::OutgoingArgv<DaemonArgv> daemonArgv("cti_daemon");
    daemonArgv.add(DaemonArgv::ApID,                app->getJobId());
    daemonArgv.add(DaemonArgv::ToolPath,            app->getToolPath());
    auto apath = app->getAttribsPath();
    if (!apath.empty()) {
        daemonArgv.add(DaemonArgv::PMIAttribsPath,  apath);
    }
    daemonArgv.add(DaemonArgv::WLMEnum,             m_wlmType);
    daemonArgv.add(DaemonArgv::Directory,           m_stageName);
    daemonArgv.add(DaemonArgv::InstSeqNum,          std::to_string(m_seqNum));
    daemonArgv.add(DaemonArgv::Clean);
    if (getenv(DBG_ENV_VAR)) { daemonArgv.add(DaemonArgv::Debug); };

    // call cleanup function with DaemonArgv
    // wlm_startDaemon adds the argv[0] automatically, so argv.get() + 1 for arguments.
    writeLog("launchCleanup: launching daemon for cleanup\n");
    app->startDaemon(daemonArgv.get() + 1);
}

std::string
Session::shipManifest(std::shared_ptr<Manifest>& mani) {
    // Finalize and drop our reference to the manifest.
    // Note we keep it alive via our shared_ptr. We do this early on
    // in case an error happens to guarantee cleanup.
    removeManifest(mani);
    // Instance number of this manifest
    auto inst = mani->instance();
    // Name of archive to create for the manifest files
    const std::string archiveName(m_stageName + std::to_string(inst) + ".tar");
    // Get frontend reference
    auto app = getOwningApp();
    auto& fe = app->getFrontend();
    // Register the cleanup file with the frontend for this archive
    fe.addFileCleanup(archiveName);
    writeLog("shipManifest %d: merge into session\n", inst);
    // merge manifest into session and get back list of files to remove
    auto& folders = mani->folders();
    auto& sources = mani->sources();
    auto toRemove = mergeTransfered(folders, sources);
    for (auto folderFilePair : toRemove) {
        folders[folderFilePair.first].erase(folderFilePair.second);
        sources.erase(folderFilePair.second);
    }
    // Check to see if we have an extra LD_LIBRARY_PATH entry to deal with
    auto& libPath = mani->extraLibraryPath();
    if ( !libPath.empty() ) {
        std::string const remoteLibDirPath{m_stagePath + "/" + libPath};
        m_ldLibraryPath = remoteLibDirPath + ":" + m_ldLibraryPath;
    }
    // todo: block signals handle race with file creation
    // create and fill archive
    Archive archive(fe.getCfgDir() + "/" + archiveName);
    // setup basic archive entries
    archive.addDirEntry(m_stageName);
    archive.addDirEntry(m_stageName + "/bin");
    archive.addDirEntry(m_stageName + "/lib");
    archive.addDirEntry(m_stageName + "/tmp");
    // add the unique files to archive
    for (auto folderIt : folders) {
        for (auto fileIt : folderIt.second) {
            const std::string destPath(m_stageName + "/" + folderIt.first +
                "/" + fileIt);
            writeLog("shipManifest %d: addPath(%s, %s)\n", inst, destPath.c_str(), sources.at(fileIt).c_str());
            archive.addPath(destPath, sources.at(fileIt));
        }
    }
    // ship package
    app->shipPackage(archiveName.c_str());
    // Increment shipped count
    ++m_seqNum;
    return archiveName;
}

void
Session::sendManifest(std::shared_ptr<Manifest>& mani) {
    // Short circuit if there is nothing to send
    if (mani->empty()) {
        removeManifest(mani);
        return;
    }
    // get instance
    auto inst = mani->instance();
    // Get owning app
    auto app = getOwningApp();
    // Ship the manifest
    auto archiveName = shipManifest(mani);
    // create DaemonArgv
    cti::OutgoingArgv<DaemonArgv> daemonArgv(CTI_DLAUNCH_BINARY);
    daemonArgv.add(DaemonArgv::ApID,         app->getJobId());
    daemonArgv.add(DaemonArgv::ToolPath,     app->getToolPath());
    daemonArgv.add(DaemonArgv::WLMEnum,      m_wlmType);
    daemonArgv.add(DaemonArgv::ManifestName, archiveName);
    daemonArgv.add(DaemonArgv::Directory,    m_stageName);
    daemonArgv.add(DaemonArgv::InstSeqNum,   std::to_string(m_seqNum));
    if (getenv(DBG_ENV_VAR)) { daemonArgv.add(DaemonArgv::Debug); };
    // call transfer function with DaemonArgv
    writeLog("sendManifest %d: starting daemon\n", inst);
    // wlm_startDaemon adds the argv[0] automatically, so argv.get() + 1 for arguments.
    app->startDaemon(daemonArgv.get() + 1);
    // Increment shipped manifests at this point. No exception was thrown.
    ++m_seqNum;
}

void
Session::execManifest(std::shared_ptr<Manifest>& mani, const char * const daemon,
        const char * const daemonArgs[], const char * const envVars[]) {
    // Add daemon to the manifest
    mani->addBinary(daemon);
    // Get the owning app
    auto app = getOwningApp();
    // Check to see if there is a manifest to send
    std::string archiveName;
    if (!mani->empty()) {
        archiveName = shipManifest(mani);
    }
    else {
        // No need to ship an empty manifest.
        removeManifest(mani);
    }
    // get real name of daemon binary
    const std::string binaryName(cti::getNameFromPath(cti::findPath(daemon)));
    // create DaemonArgv
    writeLog("execManifest: creating daemonArgv for %s\n", daemon);
    cti::OutgoingArgv<DaemonArgv> daemonArgv(CTI_DLAUNCH_BINARY);
    daemonArgv.add(DaemonArgv::ApID,                app->getJobId());
    daemonArgv.add(DaemonArgv::ToolPath,            app->getToolPath());
    auto apath = app->getAttribsPath();
    if (!apath.empty()) {
        daemonArgv.add(DaemonArgv::PMIAttribsPath,  apath);
    }
    if (!m_ldLibraryPath.empty()) {
        daemonArgv.add(DaemonArgv::LdLibraryPath,   m_ldLibraryPath);
    }
    daemonArgv.add(DaemonArgv::WLMEnum,             m_wlmType);
    if (!archiveName.empty()) {
        daemonArgv.add(DaemonArgv::ManifestName,    archiveName);
    }
    daemonArgv.add(DaemonArgv::Binary,              binaryName);
    daemonArgv.add(DaemonArgv::Directory,           m_stageName);
    daemonArgv.add(DaemonArgv::InstSeqNum,          std::to_string(m_seqNum));
    if (getenv(DBG_ENV_VAR)) { daemonArgv.add(DaemonArgv::Debug); };
    // add env vars
    if (envVars != nullptr) {
        for (const char* const* var = envVars; *var != nullptr; var++) {
            daemonArgv.add(DaemonArgv::EnvVariable, *var);
        }
    }
    // add daemon arguments
    cti::ManagedArgv rawArgVec(daemonArgv.eject());
    if (daemonArgs != nullptr) {
        rawArgVec.add("--");
        for (const char* const* var = daemonArgs; *var != nullptr; var++) {
            rawArgVec.add(*var);
        }
    }
    // call launch function with DaemonArgv
    writeLog("execManifest: starting daemon\n");
    // wlm_startDaemon adds the argv[0] automatically, so argv.get() + 1 for arguments.
    app->startDaemon(rawArgVec.get() + 1);
    writeLog("execManifest: daemon started\n");
    // Increment shipped manifests at this point. No exception was thrown.
    ++m_seqNum;
}

void
Session::removeManifest(std::shared_ptr<Manifest>& mani) {
    // Finalize manifest
    mani->finalize();
    // drop the shared_ptr
    m_manifests.erase(mani);
}

Session::Conflict
Session::hasFileConflict(const std::string& folderName,
    const std::string& realName, const std::string& candidatePath) const {

    // has /folderName/realName been shipped to the backend?
    const std::string fileArchivePath(folderName + "/" + realName);
    auto namePathPair = m_sourcePaths.find(fileArchivePath);
    if (namePathPair != m_sourcePaths.end()) {
        if (cti::isSameFile(namePathPair->first, candidatePath)) {
            return Conflict::AlreadyAdded;
        } else {
            return Conflict::NameOverwrite;
        }
    }

    return Conflict::None;
}

std::vector<FolderFilePair>
Session::mergeTransfered(const FoldersMap& newFolders, const PathMap& newPaths) {
    std::vector<FolderFilePair> toRemove;
    for (auto folderContentsPair : newFolders) {
        const std::string& folderName = folderContentsPair.first;
        const std::set<std::string>& folderContents = folderContentsPair.second;
        for (auto fileName : folderContents) {
            // mark fileName to be located at /folderName/fileName
            m_folders[folderName].insert(fileName);
            // map /folderName/fileName to source file path newPaths[fileName]
            const std::string fileArchivePath(folderName + "/" + fileName);
            if (m_sourcePaths.find(fileArchivePath) != m_sourcePaths.end()) {
                throw std::runtime_error(
                    std::string("tried to merge transfered file ") + fileArchivePath +
                    " but it was already in the session!");
            } else {
                if (cti::isSameFile(m_sourcePaths[fileArchivePath], newPaths.at(fileName))) {
                    // duplicate, tell manifest to not bother shipping
                    toRemove.push_back(std::make_pair(folderName, fileName));
                } else {
                    // register new file as coming from Manifest's source
                    m_sourcePaths[fileArchivePath] = newPaths.at(fileName);
                }
            }
        }
    }
    return toRemove;
}

std::vector<std::string>
Session::getSessionLockFiles() {
    std::vector<std::string> ret;
    // Get the owning app
    auto app = getOwningApp();
    auto tp = app->getToolPath();
    // Create the lock files based on the current sequence number
    for(auto i=0; i < m_seqNum; ++i) {
        ret.emplace_back(tp + "/.lock_" + m_stageName + "_" + std::to_string(i));
    }
    return ret;
}
