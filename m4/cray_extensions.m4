#
# cray_extensions.m4 Cray configure extensions.
#
# Copyright 2012-2019 Cray Inc.  All Rights Reserved.
#
# Unpublished Proprietary Information.
# This unpublished work is protected to trade secret, copyright and other laws.
# Except as permitted by contract or express written permission of Cray Inc.,
# no part of this work or its content may be used, reproduced or disclosed
# in any form.
#

dnl
dnl read release and library version information from disk
dnl This is not portable due to tr -d and source...
dnl
AC_DEFUN([cray_INIT],
[
	dnl Pull in the revision information from the $PWD/release_versioning file
	m4_define([CRAYTOOL_RELEASE], [m4_esyscmd([source $PWD/release_versioning; echo $craytool_major.$craytool_minor | tr -d '\n'])])

	m4_define([CRAYTOOL_BE_CURRENT], [m4_esyscmd([source $PWD/release_versioning; echo $be_current | tr -d '\n'])])
	m4_define([CRAYTOOL_BE_REVISION], [m4_esyscmd([source $PWD/release_versioning; echo $be_revision | tr -d '\n'])])
	m4_define([CRAYTOOL_BE_AGE], [m4_esyscmd([source $PWD/release_versioning; echo $be_age | tr -d '\n'])])

	m4_define([CRAYTOOL_FE_CURRENT], [m4_esyscmd([source $PWD/release_versioning; echo $fe_current | tr -d '\n'])])
	m4_define([CRAYTOOL_FE_REVISION], [m4_esyscmd([source $PWD/release_versioning; echo $fe_revision | tr -d '\n'])])
	m4_define([CRAYTOOL_FE_AGE], [m4_esyscmd([source $PWD/release_versioning; echo $fe_age | tr -d '\n'])])

	AC_SUBST([CRAYTOOL_BE_VERSION], [CRAYTOOL_BE_CURRENT:CRAYTOOL_BE_REVISION:CRAYTOOL_BE_AGE])
	AC_SUBST([CRAYTOOL_FE_VERSION], [CRAYTOOL_FE_CURRENT:CRAYTOOL_FE_REVISION:CRAYTOOL_FE_AGE])
	AC_SUBST([CRAYTOOL_RELEASE_VERSION], [CRAYTOOL_RELEASE])

	AC_DEFINE_UNQUOTED([CTI_BE_VERSION], ["CRAYTOOL_BE_CURRENT.CRAYTOOL_BE_REVISION.CRAYTOOL_BE_AGE"], [Version number of CTI backend.])
	AC_DEFINE_UNQUOTED([CTI_FE_VERSION], ["CRAYTOOL_FE_CURRENT.CRAYTOOL_FE_REVISION.CRAYTOOL_FE_AGE"], [Version number of CTI frontend.])

	AC_SUBST([CRAYTOOL_EXTERNAL], [${CRAYTOOL_DIR}/external])
	AC_SUBST([CRAYTOOL_EXTERNAL_INSTALL], [${CRAYTOOL_DIR}/external/install])

	if test ! -d "${CRAYTOOL_EXTERNAL_INSTALL}"; then
		AS_MKDIR_P([${CRAYTOOL_EXTERNAL_INSTALL}])
	fi
])

dnl
dnl build libarchive automatically
dnl
AC_DEFUN([cray_BUILD_LIBARCHIVE],
[
	cray_cv_lib_archive_build=no

	dnl External source directory
	_cray_external_srcdir="${CRAYTOOL_EXTERNAL}/libarchive"

	AC_MSG_CHECKING([for libarchive submodule])

	dnl Ensure the libarchive source was checked out
	AS_IF(	[test ! -f "$_cray_external_srcdir/README.md"],
			[AC_MSG_ERROR([git submodule libarchive not found.])],
			[AC_MSG_RESULT([yes])]
			)

	dnl cd to the checked out source directory
	cd ${_cray_external_srcdir}

	AC_MSG_NOTICE([Building libarchive...])

	autoreconf -ifv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD

	dnl run configure with options that work on build systems
	./configure --prefix=${CRAYTOOL_EXTERNAL_INSTALL} --disable-shared --with-pic --without-expat --without-xml2 \
	--without-openssl --without-nettle --without-lzo2 --without-lzma --without-libiconv-prefix --without-iconv \
	--without-lzmadec --without-bz2lib --without-zlib --disable-bsdtar --disable-bsdcpio \
	--disable-rpath >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[libarchive configure failed.]],
	 		[]
	 		)

	dnl make
	make -j8 >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[libarchive make failed.]],
	 		[]
	 		)
	make install >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[libarchive make install failed.]],
	 		[cray_cv_lib_archive_build=yes]
	 		)

	dnl go home
	cd ${CRAYTOOL_DIR}
])

dnl
dnl define post-cache libarchive env
dnl
AC_DEFUN([cray_ENV_LIBARCHIVE],
[
	AC_SUBST([LIBARC_SRC], [${CRAYTOOL_EXTERNAL}/libarchive])
	AC_SUBST([INTERNAL_LIBARCHIVE], [${CRAYTOOL_EXTERNAL_INSTALL}])
])

dnl
dnl build libssh automatically
dnl
AC_DEFUN([cray_BUILD_LIBSSH],
[
	cray_cv_lib_ssh_build=no

	dnl External source directory
	_cray_external_srcdir="${CRAYTOOL_EXTERNAL}/libssh"

	AC_MSG_CHECKING([for libssh submodule])

	dnl Ensure the libssh source was checked out
	AS_IF(	[test ! -f "$_cray_external_srcdir/README"],
			[AC_MSG_ERROR([git submodule libssh not found.])],
			[AC_MSG_RESULT([yes])]
			)

	dnl cd to the checked out source directory
	cd ${_cray_external_srcdir}

	AC_MSG_NOTICE([Building libssh...])

	dnl configure using cmake
	rm -rf build
	mkdir -p build
	cd build
	cmake -DCMAKE_INSTALL_PREFIX=${CRAYTOOL_EXTERNAL_INSTALL} -DCMAKE_C_COMPILER=$(which gcc) -DCMAKE_CXX_COMPILER=$(which g++) -DCMAKE_BUILD_TYPE=Debug .. >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[libssh cmake failed.]],
	 		[]
	 		)

	dnl make
	make -j8 >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[libssh make failed.]],
	 		[]
	 		)

	dnl install to stage
	make install >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[libssh make install failed.]],
	 		[cray_cv_lib_ssh_build=yes]
	 		)

	dnl go home
	cd ${CRAYTOOL_DIR}
])

dnl
dnl define post-cache libssh env
dnl
AC_DEFUN([cray_ENV_LIBSSH],
[
	AC_SUBST([LIBSSH_SRC], [${CRAYTOOL_EXTERNAL}/libssh])
	AC_SUBST([INTERNAL_LIBSSH], [${CRAYTOOL_EXTERNAL_INSTALL}])
	AC_SUBST([LIBSSH_LOC], [${CRAYTOOL_EXTERNAL_INSTALL}/lib/libssh.so])
])

dnl
dnl configure elfutils
dnl
AC_DEFUN([cray_CONF_ELFUTILS],
[
	cray_cv_elfutils_conf=no

	dnl External source directory
	_cray_external_srcdir="${CRAYTOOL_EXTERNAL}/elfutils"

	AC_MSG_CHECKING([for elfutils submodule])

	dnl Ensure the libssh source was checked out
	AS_IF(	[test ! -f "$_cray_external_srcdir/README"],
			[AC_MSG_ERROR([git submodule elfutils not found.])],
			[AC_MSG_RESULT([yes])]
			)

	dnl cd to the checked out source directory
	cd ${_cray_external_srcdir}

	AC_MSG_NOTICE([Configuring elfutils...])

	autoreconf -ifv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD

	dnl configure
	./configure --prefix=${prefix} --enable-maintainer-mode
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[elfutils configure failed.]],
	 		[]
	 		)

	AC_MSG_NOTICE([Staging elfutils...])

	dnl make
	make -j8 >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[elfutils make failed.]],
	 		[]
	 		)

	dnl install to stage - this also gets included in final package
	make -j8 install prefix=${CRAYTOOL_EXTERNAL_INSTALL} >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[elfutils make install failed.]],
	 		[cray_cv_elfutils_conf=yes]
	 		)

	dnl go home
	cd ${CRAYTOOL_DIR}
])

dnl
dnl define post-cache libssh env
dnl
AC_DEFUN([cray_ENV_ELFUTILS],
[
	AC_SUBST([INTERNAL_ELFUTILS], [${CRAYTOOL_EXTERNAL_INSTALL}])
])

dnl
dnl stage boost automatically
dnl
AC_DEFUN([cray_BUILD_BOOST],
[
	cray_cv_boost_build=no

	dnl External source directory
	_cray_external_srcdir="${CRAYTOOL_EXTERNAL}/boost"

	AC_MSG_CHECKING([for boost submodule])

	dnl Ensure the boost source was checked out
	AS_IF(	[test ! -d "$_cray_external_srcdir/tools/build"],
			[AC_MSG_ERROR([git submodule boost not found.])],
			[AC_MSG_RESULT([yes])]
			)

	dnl cd to the checked out source directory
	cd ${_cray_external_srcdir}

	AC_MSG_NOTICE([Staging boost build...])

	save_LDFLAGS="$LDFLAGS"
	LDFLAGS="$LDFLAGS -Wl,-z,origin -Wl,-rpath,$ORIGIN -Wl,--enable-new-dtags"

	./bootstrap.sh --prefix=${prefix} --with-toolset=gcc >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD

	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[boost bootstrap failed.]]
	 		)

	dnl pre-build boost libraries
	./b2 -j32 stage >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD

	dnl install to temporary staging location for internal use
	./b2 -j32 --prefix=${CRAYTOOL_EXTERNAL_INSTALL} install >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD

	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[boost b2 stage failed.]],
	 		[cray_cv_boost_build=yes]
	 		)

	LDFLAGS="$save_LDFLAGS"

	dnl go home
	cd ${CRAYTOOL_DIR}
])

dnl
dnl define post-cache boost env
dnl
AC_DEFUN([cray_ENV_BOOST],
[
	AC_SUBST([BOOST_SRC], [${CRAYTOOL_EXTERNAL}/boost])
	AC_SUBST([BOOST_ROOT], [${CRAYTOOL_EXTERNAL_INSTALL}])
])

dnl
dnl stage tbb automatically
dnl
AC_DEFUN([cray_BUILD_TBB],
[
	cray_cv_tbb_build=no

	dnl External source directory
	_cray_external_srcdir="${CRAYTOOL_EXTERNAL}/tbb"

	dnl Temporary build directory
	_cray_tmpdir="${CRAYTOOL_EXTERNAL_INSTALL}/TBB-build"

	if test ! -d "$_cray_tmpdir"; then
		AS_MKDIR_P([$_cray_tmpdir])
	fi

	AC_MSG_CHECKING([for tbb submodule])

	dnl Ensure the tbb source was checked out
	AS_IF(	[test ! -d "$_cray_external_srcdir/build"],
			[AC_MSG_ERROR([git submodule tbb not found.])],
			[AC_MSG_RESULT([yes])]
			)

	dnl cd to the checked out source directory
	cd ${_cray_external_srcdir}

	AC_MSG_NOTICE([Building TBB...])

	save_LDFLAGS="$LDFLAGS"
	LDFLAGS="$LDFLAGS -Wl,-z,origin -Wl,-rpath,$ORIGIN -Wl,--enable-new-dtags"
	make -j8 tbb tbbmalloc tbb_build_dir=$_cray_tmpdir tbb_build_prefix=tbb >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD

	AS_IF(	[test ! -f "$_cray_tmpdir/tbb_release/libtbb.so"],
			[AC_MSG_ERROR[tbb build failed.]],
			[cray_cv_tbb_build=yes]
			)

	LDFLAGS="$save_LDFLAGS"

	dnl go home
	cd ${CRAYTOOL_DIR}
])

dnl
dnl define post-cache tbb env
dnl
AC_DEFUN([cray_ENV_TBB],
[
	AC_SUBST([TBB_LIBRARY], [${CRAYTOOL_EXTERNAL_INSTALL}/TBB-build/tbb_release])
	AC_SUBST([TBB_INCLUDE_DIR], [${CRAYTOOL_EXTERNAL}/tbb/include])
])

dnl
dnl build dyninst automatically
dnl
AC_DEFUN([cray_BUILD_DYNINST],
[
	cray_cv_dyninst_build=no

	dnl External source directory
	_cray_external_srcdir="${CRAYTOOL_EXTERNAL}/dyninst"

	AC_MSG_CHECKING([for dyninst submodule])

	dnl Ensure the dyninst source was checked out
	AS_IF(	[test ! -f "$_cray_external_srcdir/README.md"],
			[AC_MSG_ERROR([git submodule dyninst not found.])],
			[AC_MSG_RESULT([yes])]
			)

	dnl cd to the checked out source directory
	cd ${_cray_external_srcdir}

	AC_MSG_NOTICE([Building dyninst...])

	save_LDFLAGS="$LDFLAGS"
	LDFLAGS="$LDFLAGS -Wl,-z,origin -Wl,-rpath,$ORIGIN -Wl,--enable-new-dtags"

	dnl configure using cmake
	rm -rf build
	mkdir -p build
	cd build
	_cray_dyninst_cmake_opts="-DCMAKE_C_COMPILER=$(which gcc) -DCMAKE_CXX_COMPILER=$(which g++) -DCMAKE_BUILD_TYPE=RelWithDebInfo -DPATH_BOOST=${BOOST_ROOT} -DBoost_INCLUDE_DIR=${BOOST_ROOT}/include -DLIBELF_INCLUDE_DIR=${INTERNAL_ELFUTILS}/include -DLIBELF_LIBRARIES=${INTERNAL_ELFUTILS}/lib/libelf.so -DLIBDWARF_INCLUDE_DIR=${INTERNAL_ELFUTILS}/include -DLIBDWARF_LIBRARIES=${INTERNAL_ELFUTILS}/lib/libdw.so -DTBB_INCLUDE_DIRS=${TBB_INCLUDE_DIR} -DTBB_tbb_LIBRARY_RELEASE=${TBB_LIBRARY}/libtbb.so -DUSE_OpenMP=OFF"
	cmake -DCMAKE_INSTALL_PREFIX=${CRAYTOOL_EXTERNAL_INSTALL} $_cray_dyninst_cmake_opts .. >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[dyninst cmake failed.]],
	 		[]
	 		)

	dnl make
	make -j8 >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[dyninst make failed.]],
	 		[]
	 		)

	dnl install to staging location for internal use
	make install >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[dyninst make install failed.]],
	 		[]
	 		)

	dnl cmake to prefix for final build
	cmake -DCMAKE_INSTALL_PREFIX=${prefix} $_cray_dyninst_cmake_opts .. >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
	AS_IF(	[test $? != 0],
	 		[AC_MSG_ERROR[dyninst cmake failed.]],
	 		[cray_cv_dyninst_build=yes]
	 		)

	LDFLAGS="$save_LDFLAGS"

	dnl go home
	cd ${CRAYTOOL_DIR}
])

dnl
dnl define post-cache dyninst env
dnl
AC_DEFUN([cray_ENV_DYNINST],
[
	AC_SUBST([DYNINST_BUILD], [${CRAYTOOL_EXTERNAL}/dyninst/build])
	AC_SUBST([INTERNAL_DYNINST], [${CRAYTOOL_EXTERNAL_INSTALL}])
])

dnl
dnl create alps files in a staging location
dnl
AC_DEFUN([cray_SETUP_ALPS_RPMS],
[
	dnl Set this to the CLE base version we are buidling against. Note that this
	dnl does not include update level information.
	CLE_RPM_VERS="5.2"

	dnl Set this to the location of the alps RPMS we should build against
	ALPS_RPM_DIR="/cray/css/release/cray/build/xt/sles11sp3/x86_64/RB-5.2UP00-ari/working/latest-RB-5.2UP00/ALPS/x86_64"

	dnl Set this to the location of the xmlrpc-epi RPMS we should build against
	XMLRPC_RPM_DIR="/cray/css/release/cray/build/xt/sles11sp3/x86_64/RB-5.2UP00-ari/working/latest-RB-5.2UP00/3rd-party/x86_64/"

	dnl Create a temporary directory to extract the alps libraries to
	_cray_tmpdir="${CRAYTOOL_EXTERNAL}/alps_base"

	AC_MSG_CHECKING([for ALPS stage directory])

	AS_IF(	[test ! -d "$_cray_tmpdir"],
			[	AC_MSG_RESULT([no])

				dnl check required execs
				AC_PROG_MKDIR_P

				AC_ARG_VAR([RPM2CPIO], [Location of rpm2cpio])
				AC_ARG_VAR([CPIO], [Location of cpio])

				AC_PATH_PROG([RPM2CPIO], [rpm2cpio], [rpm2cpio])
				if test -z "$RPM2CPIO"; then
					AC_MSG_ERROR([rpm2cpio not found.])
				fi

				AC_PATH_PROG([CPIO], [cpio], [cpio])
				if test -z "$CPIO"; then
					AC_MSG_ERROR([cpio not found.])
				fi

				AC_MSG_NOTICE([Creating ALPS staging directory in $_cray_tmpdir])

				dnl resolve the names of the alps rpms
				if test -d "$ALPS_RPM_DIR"; then
					ALPS_RPM_1=$(find $ALPS_RPM_DIR/cray-libalps0-$CLE_RPM_VERS.[[0-9\.\-]]*.ari.x86_64.rpm 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$ALPS_RPM_1"; then
						AC_MSG_ERROR([ALPS RPM cray-libalps0-$CLE_RPM_VERS not found.])
					fi
					ALPS_RPM_2=$(find $ALPS_RPM_DIR/cray-libalps-devel-$CLE_RPM_VERS.[[0-9\.\-]]*.ari.x86_64.rpm 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$ALPS_RPM_2"; then
						AC_MSG_ERROR([ALPS RPM cray-libalps-devel-$CLE_RPM_VERS not found.])
					fi
					ALPS_RPM_3=$(find $ALPS_RPM_DIR/cray-libalpsutil0-$CLE_RPM_VERS.[[0-9\.\-]]*.ari.x86_64.rpm 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$ALPS_RPM_3"; then
						AC_MSG_ERROR([ALPS RPM cray-libalpsutil0-$CLE_RPM_VERS not found.])
					fi
					ALPS_RPM_4=$(find $ALPS_RPM_DIR/cray-libalpsutil-devel-$CLE_RPM_VERS.[[0-9\.\-]]*.ari.x86_64.rpm 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$ALPS_RPM_4"; then
						AC_MSG_ERROR([ALPS RPM alps-devel-$CLE_RPM_VERS not found.])
					fi
				else
					AC_MSG_ERROR([ALPS RPM directory $ALPS_RPM_DIR not found.])
				fi

				dnl resolve the names of the xmlrpc rpms
				if test -d "$XMLRPC_RPM_DIR"; then
					XMLRPC_RPM_1=$(find $XMLRPC_RPM_DIR/cray-libxmlrpc-epi0-[[0-9\.\-]]*.x86_64.rpm 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$XMLRPC_RPM_1"; then
						AC_MSG_ERROR([XMLRPC RPM cray-libxmlrpc-epi0 not found.])
					fi
					XMLRPC_RPM_2=$(find $XMLRPC_RPM_DIR/cray-libxmlrpc-epi-devel-[[0-9\.\-]]*.x86_64.rpm 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$XMLRPC_RPM_1"; then
						AC_MSG_ERROR([XMLRPC RPM cray-libxmlrpc-epi-devel not found.])
					fi
				else
					AC_MSG_ERROR([XMLRPC RPM directory $XMLRPC_RPM_DIR not found.])
				fi

				AS_MKDIR_P([$_cray_tmpdir])
				cd $_cray_tmpdir
				$RPM2CPIO $ALPS_RPM_1 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				$RPM2CPIO $ALPS_RPM_2 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				$RPM2CPIO $ALPS_RPM_3 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				$RPM2CPIO $ALPS_RPM_4 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				$RPM2CPIO $XMLRPC_RPM_1 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				$RPM2CPIO $XMLRPC_RPM_2 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				cd ${CRAYTOOL_DIR}
			],
			[AC_MSG_RESULT([yes])])

	AC_ARG_VAR([READLINK], [Location of readlink])

	AC_PATH_PROG([READLINK], [readlink], [readlink])
	if test -z "$READLINK"; then
		AC_MSG_ERROR([readlink not found.])
	fi

	dnl We need to resolve the stage location since this will change with each alps version.
	_cray_alps_inst=$($READLINK -m ${_cray_tmpdir}/opt/cray/alps/*)

	AC_MSG_CHECKING([for presence of ALPS libraries])

	if test ! -d "${_cray_alps_inst}/lib64/"; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([ALPS lib directory $_cray_alps_inst/lib64/ not found.])
	fi

	if test ! -d "${_cray_alps_inst}/include/"; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([ALPS include directory $_cray_alps_inst/include/ not found.])
	fi

	if test ! -d "${_cray_tmpdir}/usr/lib64"; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([XMLRPC lib directory $_cray_tmpdir/usr/lib64 not found.])
	fi

	AC_MSG_RESULT([yes])

	AC_SUBST([ALPS_BASE], [${CRAYTOOL_EXTERNAL}/alps_base])
	AC_SUBST([ALPS_LDFLAGS], ["-L${_cray_alps_inst}/lib64 -L${_cray_tmpdir}/usr/lib64"])
	AC_SUBST([ALPS_CFLAGS], ["-I${_cray_alps_inst}/include"])
])

dnl
dnl create wlm_detect files in a staging location
dnl
AC_DEFUN([cray_SETUP_WLM_DETECT_RPMS],
[
	dnl Set this to the location of the wlm_detect RPMS we should build against
	WLM_DETECT_RPM_DIR="/cray/css/release/cray/build/xt/sles11sp3/x86_64/RB-5.2UP00-ari/working/latest/rpms/x86_64/"

	dnl Create a temporary directory to extract the wlm_detect libraries to
	_cray_tmpdir="${CRAYTOOL_EXTERNAL}/wlm_detect_base"

	AC_PROG_AWK

	AC_MSG_CHECKING([for wlm_detect stage directory])

	AS_IF(	[test ! -d "$_cray_tmpdir"],
			[	AC_MSG_RESULT([no])

				dnl check required execs
				AC_PROG_MKDIR_P

				AC_ARG_VAR([RPM2CPIO], [Location of rpm2cpio])
				AC_ARG_VAR([CPIO], [Location of cpio])

				AC_PATH_PROG([RPM2CPIO], [rpm2cpio], [rpm2cpio])
				if test -z "$RPM2CPIO"; then
					AC_MSG_ERROR([rpm2cpio not found.])
				fi

				AC_PATH_PROG([CPIO], [cpio], [cpio])
				if test -z "$CPIO"; then
					AC_MSG_ERROR([cpio not found.])
				fi

				AC_MSG_NOTICE([Creating wlm_detect staging directory in $_cray_tmpdir])

				dnl resolve the names of the wlm_detect rpms
				if test -d "$WLM_DETECT_RPM_DIR"; then
					WLM_DETECT_RPM_1=$(find $WLM_DETECT_RPM_DIR/cray-libwlm_detect0* 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$WLM_DETECT_RPM_1"; then
						AC_MSG_ERROR([wlm_detect rpm cray-libwlm_detect not found.])
					fi
					WLM_DETECT_RPM_2=$(find $WLM_DETECT_RPM_DIR/cray-libwlm_detect-devel-* 2>&AS_MESSAGE_LOG_FD)
					if test ! -e "$WLM_DETECT_RPM_2"; then
						AC_MSG_ERROR([wlm_detect rpm cray-libwlm_detect-devel not found.])
					fi
				else
					AC_MSG_ERROR([wlm_detect rpm directory $WLM_DETECT_RPM_DIR not found.])
				fi

				AS_MKDIR_P([$_cray_tmpdir])
				cd $_cray_tmpdir
				$RPM2CPIO $WLM_DETECT_RPM_1 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				$RPM2CPIO $WLM_DETECT_RPM_2 | $CPIO -idv >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
				cd ${CRAYTOOL_DIR}
			],
			[AC_MSG_RESULT([yes])])

	dnl find libwlm_detect.so for awk
	WLM_DETECT_LIB_LOC=$(find $_cray_tmpdir -name libwlm_detect.so 2>&AS_MESSAGE_LOG_FD)
	WLM_DETECT_BASE_NAME=$(echo $WLM_DETECT_LIB_LOC | $AWK '{match($[1],/wlm_detect\/([[0-9a-f.-]]*.ari)\/lib64\/libwlm_detect.so/,a)}END{print a[[1]]}' 2>&AS_MESSAGE_LOG_FD)
	if test "x$WLM_DETECT_BASE_NAME" = x; then
		AC_MSG_ERROR([Could not obtain wlm_detect install directory name.])
	fi

	AC_MSG_CHECKING([for presence of wlm_detect libraries])

	if test ! -d "$_cray_tmpdir/opt/cray/wlm_detect/$WLM_DETECT_BASE_NAME/lib64/"; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([wlm_detect lib directory $_cray_tmpdir/opt/cray/wlm_detect/$WLM_DETECT_BASE_NAME/lib64/ not found.])
	fi

	if test ! -d "$_cray_tmpdir/opt/cray/wlm_detect/$WLM_DETECT_BASE_NAME/include/"; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([wlm_detect include directory $_cray_tmpdir/opt/cray/wlm_detect/$WLM_DETECT_BASE_NAME/include/ not found.])
	fi

	AC_MSG_RESULT([yes])

	AC_SUBST([WLM_DETECT_BASE], [${CRAYTOOL_EXTERNAL}/wlm_detect_base])
	AC_SUBST([WLM_DETECT_LDFLAGS], ["-L$_cray_tmpdir/opt/cray/wlm_detect/$WLM_DETECT_BASE_NAME/lib64"])
	AC_SUBST([WLM_DETECT_CFLAGS], ["-I$_cray_tmpdir/opt/cray/wlm_detect/$WLM_DETECT_BASE_NAME/include"])
])
