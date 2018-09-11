#include <unistd.h>
#include <fcntl.h>

#include <string>

#include "Manifest.hpp"
#include "Session.hpp"

#include "cti_fe.h"
#include "useful/cti_useful.h"
#include "ld_val/ld_val.h"

// promote session pointer to a shared pointer (otherwise throw)
inline std::shared_ptr<Session> getSessionHandle(std::weak_ptr<Session> sessionPtr) {
	if (auto liveSession = sessionPtr.lock()) { return liveSession; }
	throw std::runtime_error("Manifest is not valid, already shipped.");
}

/* wrappers for CTI helper functions */

static CharPtr findPath(const std::string& fileName) {
	if (auto fullPath = CharPtr(_cti_pathFind(fileName.c_str(), nullptr), free)) {
		return fullPath;
	} else { // _cti_pathFind failed with nullptr result
		throw std::runtime_error(fileName + ": Could not locate in PATH.");
	}
}

static CharPtr findLib(const std::string& fileName) {
	if (auto fullPath = CharPtr(_cti_libFind(fileName.c_str()), free)) {
		return fullPath;
	} else { // _cti_libFind failed with nullptr result
		throw std::runtime_error(fileName + ": Could not locate in LD_LIBRARY_PATH or system location.");
	}
}
static CharPtr getNameFromPath(const std::string& filePath) {
	if (auto realName = CharPtr(_cti_pathToName(filePath.c_str()), free)) {
		return realName;
	} else { // _cti_pathToName failed with nullptr result
		throw std::runtime_error("Could not convert the fullname to realname.");
	}
}

static CharPtr getRealPath(const std::string& filePath) {
	if (auto realPath = CharPtr(realpath(filePath.c_str(), nullptr), free)) {
		return realPath;
	} else { // realpath failed with nullptr result
		throw std::runtime_error("realpath failed.");
	}
}

// add dynamic library dependencies to manifest
void Manifest::addLibDeps(const std::string& filePath) {
	// get array of library paths using ld_val libArray
	if (auto libArray = StringArray(
			_cti_ld_val(filePath.c_str(), _cti_getLdAuditPath()),
		stringArrayDeleter)) {

		// add to manifest
		for (char** elem = libArray.get(); *elem != nullptr; elem++) {
			addLibrary(*elem, Manifest::DepsPolicy::Ignore);
		}
	}
}

/* manifest file add implementations */

// add file to manifest if session reports no conflict on realname / filepath
void Manifest::checkAndAdd(const std::string& folder, const std::string& filePath,
	const std::string& realName) {

	auto liveSession = getSessionHandle(sessionPtr);

	// check for conflicts in session
	switch (liveSession->hasFileConflict(folder, realName, filePath)) {
		case Session::Conflict::None: break;
		case Session::Conflict::AlreadyAdded: return;
		case Session::Conflict::NameOverwrite:
			throw std::runtime_error(realName + ": session conflict");
	}

	// add to manifest registry
	folders[folder].emplace(realName);
	sourcePaths[realName] = filePath;
}

void Manifest::addBinary(const std::string& rawName, DepsPolicy depsPolicy) {
	// get path and real name of file
	const std::string filePath(findPath(rawName).get());
	const std::string realName(getNameFromPath(filePath).get());

	// check permissions
	if (access(filePath.c_str(), R_OK | X_OK)) {
		throw std::runtime_error("Specified binary does not have execute permissions.");
	}

	checkAndAdd("bin", filePath, realName);

	// add libraries if needed
	if (depsPolicy == DepsPolicy::Stage) {
		addLibDeps(filePath);
	}
}

void Manifest::addLibrary(const std::string& rawName, DepsPolicy depsPolicy) {
	// get path and real name of file
	const std::string filePath(findLib(rawName).get());
	const std::string realName(getNameFromPath(filePath).get());

	auto liveSession = getSessionHandle(sessionPtr);

	// check for conflicts in session
	/* TODO: We need to create a way to ship conflicting libraries. Since
		most libraries are sym links to their proper version, name collisions
		are possible. In the future, the launcher should be able to handle
		this by pointing its LD_LIBRARY_PATH to a custom directory containing
		the conflicting lib. Don't actually implement this until the need arises.
	*/
	switch (liveSession->hasFileConflict("lib", realName, filePath)) {
		case Session::Conflict::None:
			// add to manifest registry
			folders["lib"].emplace(realName);
			sourcePaths[realName] = filePath;
		case Session::Conflict::AlreadyAdded: return;
		case Session::Conflict::NameOverwrite:
			throw std::runtime_error(realName + ": session conflict");
			// todo: add to custom library directory
	}

	// add libraries if needed
	if (depsPolicy == DepsPolicy::Stage) {
		addLibDeps(filePath);
	}
}

void Manifest::addLibDir(const std::string& rawPath) {
	// get real path and real name of directory
	const std::string realPath(getRealPath(rawPath).get());
	const std::string realName(getNameFromPath(realPath).get());

	checkAndAdd("lib", realPath, realName);
}

void Manifest::addFile(const std::string& rawName) {
	// get path and real name of file
	const std::string filePath(findPath(rawName).get());
	const std::string realName(getNameFromPath(filePath).get());

	checkAndAdd("", filePath, realName);
}

/* manifest transfer / wlm interface implementations */

#include "Archive.hpp"
// create manifest archive with libarchive and ship package with WLM transfer function
static RemotePackage createAndShipArchive(const std::shared_ptr<Session>& liveSession,
	const std::string& archiveName, const FoldersMap& folders, const PathMap& filePaths,
	size_t instanceCount) {

	// todo: block signals handle race with file creation

	// create and fill archive
	Archive archive(liveSession->configPath + "/" + archiveName);

	// setup basic archive entries
	archive.addDirEntry(liveSession->stageName);
	archive.addDirEntry(liveSession->stageName + "/bin");
	archive.addDirEntry(liveSession->stageName + "/lib");
	archive.addDirEntry(liveSession->stageName + "/tmp");

	// add files to archive
	for (auto folderIt : folders) {
		for (auto fileIt : folderIt.second) {
			const std::string destPath(liveSession->stageName + "/" + folderIt.first +
				"/" + fileIt);
			DEBUG("ship " << instanceCount << ": addPath(" << destPath << ", " << filePaths.at(fileIt) << ")" << std::endl);
			archive.addPath(destPath, filePaths.at(fileIt));
		}
	}

	// ship package and finalize manifest with session
	RemotePackage remotePackage(std::move(archive), archiveName, liveSession,
		instanceCount);

	// todo: end block signals

	return remotePackage;
}

RemotePackage Manifest::finalizeAndShip() {
	auto liveSession = getSessionHandle(sessionPtr);

	// todo: resolveManifestConflicts with liveSession

	const std::string archiveName(liveSession->stageName + std::to_string(instanceCount) +
		".tar");

	// create the hidden name for the cleanup file. This will be checked by future
	// runs to try assisting in cleanup if we get killed unexpectedly. This is cludge
	// in an attempt to cleanup. The ideal situation is to be able to tell the kernel
	// to remove the tarball if the process exits, but no mechanism exists today that
	// I know about.
	{ const std::string cleanupFilePath(liveSession->configPath + "/." + archiveName);
		auto cleanupFileHandle = UniquePtrDestr<FILE>(
			fopen(cleanupFilePath.c_str(), "w"), fclose);
		pid_t pid = getpid();
		if (fwrite(&pid, sizeof(pid), 1, cleanupFileHandle.get()) != 1) {
			throw std::runtime_error("fwrite to cleanup file failed.");
		}
	}

	// create manifest archive with libarchive and ship package with WLM transfer function
	auto remotePackage = createAndShipArchive(liveSession, archiveName, folders, 
		sourcePaths, instanceCount);

	// merge manifest into session
	DEBUG("finalizeAndExtract " << instanceCount << ": merge into session" << std::endl);
	liveSession->mergeTransfered(folders, sourcePaths);

	// manifest is finalized, no changes can be made
	invalidate();
	return remotePackage;
}

/* package implementations */

#include "ArgvDefs.hpp"

RemotePackage::RemotePackage(Archive&& archiveToShip, const std::string& archiveName_,
	std::shared_ptr<Session> liveSession, size_t instanceCount_) :
		archiveName(archiveName_),
		sessionPtr(liveSession),
		instanceCount(instanceCount_) {

	const std::string& finalizedArchivePath = archiveToShip.finalize();
	liveSession->shipPackage(finalizedArchivePath.c_str());
} // archiveToShip destructor: remove archive from disk

void RemotePackage::extract() {
	if (archiveName.empty()) { return; }

	auto liveSession = getSessionHandle(sessionPtr);

	// create DaemonArgv
	OutgoingArgv<DaemonArgv> daemonArgv("cti_daemon");
	{ using DA = DaemonArgv;
		daemonArgv.add(DA::ApID,         liveSession->jobId);
		daemonArgv.add(DA::ToolPath,     liveSession->toolPath);
		daemonArgv.add(DA::WLMEnum,      liveSession->wlmEnum);
		daemonArgv.add(DA::ManifestName, archiveName);
		daemonArgv.add(DA::Directory,    liveSession->stageName);
		daemonArgv.add(DA::InstSeqNum,   std::to_string(instanceCount));
		if (getenv(DBG_ENV_VAR)) { daemonArgv.add(DA::Debug); };
	}

	// call transfer function with DaemonArgv
	DEBUG("finalizeAndExtract " << instanceCount << ": starting daemon" << std::endl);
	// wlm_startDaemon adds the argv[0] automatically, so argv.get() + 1 for arguments.
	liveSession->startDaemon(daemonArgv.get() + 1);

	invalidate();
}

void RemotePackage::extractAndRun(const char * const daemonBinary,
	const char * const daemonArgs[], const char * const envVars[]) {

	auto liveSession = getSessionHandle(sessionPtr);

	// get real name of daemon binary
	const std::string binaryName(getNameFromPath(findPath(daemonBinary).get()).get());

	// create DaemonArgv
	DEBUG("finalizeAndRun: creating daemonArgv for " << daemonBinary << std::endl);
	OutgoingArgv<DaemonArgv> daemonArgv("cti_daemon");
	{ using DA = DaemonArgv;
		daemonArgv.add(DA::ApID,         liveSession->jobId);
		daemonArgv.add(DA::ToolPath,     liveSession->toolPath);
		if (!liveSession->attribsPath.empty()) {
			daemonArgv.add(DA::PMIAttribsPath, liveSession->attribsPath);
		}
		daemonArgv.add(DA::WLMEnum,      liveSession->wlmEnum);
		if (!archiveName.empty()) { daemonArgv.add(DA::ManifestName, archiveName); }
		daemonArgv.add(DA::Binary,       binaryName);
		daemonArgv.add(DA::Directory,    liveSession->stageName);
		daemonArgv.add(DA::InstSeqNum,   std::to_string(instanceCount));
		daemonArgv.add(DA::Directory,    liveSession->stageName);
		if (getenv(DBG_ENV_VAR)) { daemonArgv.add(DA::Debug); };
	}

	// add env vars
	if (envVars != nullptr) {
		for (const char* const* var = envVars; *var != nullptr; var++) {
			daemonArgv.add(DaemonArgv::EnvVariable, *var);
		}
	}

	// add daemon arguments
	ManagedArgv rawArgVec(daemonArgv.eject());
	if (daemonArgs != nullptr) {
		rawArgVec.add("--");
		for (const char* const* var = daemonArgs; *var != nullptr; var++) {
			rawArgVec.add(*var);
		}
	}

	// call launch function with DaemonArgv
	DEBUG("finalizeAndRun: starting daemon" << std::endl);
	// wlm_startDaemon adds the argv[0] automatically, so argv.get() + 1 for arguments.
	liveSession->startDaemon(rawArgVec.get() + 1);

	invalidate();
}