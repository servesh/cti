#!/bin/bash
set -e

cmake_module="cmake/3.5.2"

if [[ $1 == "-d" && ! -z $2 ]]
then
  BUILD_DIR=$2
else
  BUILD_DIR=$PWD/install
  if [ -d $BUILD_DIR ]
  then
    rm -rf $BUILD_DIR
  fi
  mkdir $BUILD_DIR
  chmod a+rwx $BUILD_DIR
fi
echo "Building to " $BUILD_DIR
topLevel=$PWD

boostSO_Major=1
boostSO_Minor=66
boostSO_Fix=0
dwarfDir=""
dwarfVer=18.1.0
ulib=/cray/css/ulib
redhat_release_file="/etc/redhat-release"
suse_release_file="/etc/SuSE-release"
os_release_file="/etc/os-release"
buildRelease=0           # default to not being a build release
swDebugStr="-DCMAKE_BUILD_TYPE=RelWithDebInfo"
boost_inst_base=""
boost_inc=""
boost_full_name=${boostSO_Major}_${boostSO_Minor}_${boostSO_Fix}

function source_module_script() {
  if [ -e $redhat_release_file ]; then
    # centos
    if [[ -e /usr/share/Modules/init/bash ]]; then
      source /usr/share/Modules/init/bash
    fi
  else
    # get sles version
    SLES_VER=$(cat $suse_release_file 2>&1 /dev/null | grep VERSION | cut -f3 -d" ")
    if [[ $SLES_VER -lt 12 ]]; then
      modules_prefix=/opt
    else
      modules_prefix=/opt/cray/pe
    fi

    # load sles script
    if [[ -e $modules_prefix/modules/default/init/bash ]]; then
      source $modules_prefix/modules/default/init/bash
    fi
  fi
}

function set_OS(){
  # set OS, arch
  if [ -e "$redhat_release_file" ]; then
    OS="CentOS"
    arch=x86_64
  elif [ -e "$os_release_file" ]; then
    arch=$(uname -m)
    SLES_VER=$(cat /etc/os-release | grep VERSION= | cut -d \" -f2)
    if [[ $SLES_VER = 12 ]]; then
      OS="SLES12"
    elif [[ $SLES_VER = 15 ]]; then
      OS="SLES15"
    fi
  elif [ -e "$suse_release_file" ]; then
    arch=$(cat $suse_release_file | head -1 | cut -d'(' -f2 | cut -d')' -f1)
    SLES_VER=$(cat $suse_release_file | grep VERSION | cut -f3 -d" ")
    if [[ $SLES_VER = 11 ]]; then
      OS="SLES11"
    elif [[ $SLES_VER = 12 ]]; then
      OS="SLES12"
    fi
  fi
  export OS
  export arch

  gccVer=6.1.0
  module load gcc/$gccVer
  export gccVer

  # use OS and arch to set right gcc, boost, libelf, libdwarf
  if [[ $arch == "aarch64" ]]; then
    boost_inst_base=$ulib/boost/1_66_aarch64/boost_${boost_full_name}/install
    boost_inc=$boost_inst_base/include
    elfDir=/usr             # Fixme: this is too ephemeral ???
    dwarfDir=$ulib/aarch64/dwarf/$dwarfVer
  elif [[ $arch == "x86_64" ]]; then
    boost_inst_base=$ulib/boost/1_66/boost_${boost_full_name}/install
    boost_inc=$boost_inst_base/include
    elfDir=/cray/css/users/debugger/elf/elfutils-0.168/install/
    if [[ $OS == "SLES11" ]]; then
      dwarfDir=$ulib/sles11/dwarf/$dwarfVer
    elif [[ $OS == "SLES12" ]]; then
      dwarfDir=$ulib/dwarf/$dwarfVer
    elif [[ $OS == "CentOS" ]]; then
      dwarfDir=$ulib/dwarf/$dwarfVer
    fi
  fi
}

#_______________________ Start of main code ______________________________
source_module_script


module purge 2>/dev/null
module load $cmake_module

set_OS

#
# Build DyninstAPI
#
PLATFORM=
if [[ $arch == "x86_64" ]]; then
  export PLATFORM=x86_64_cnl
  export PLATFORM=x86_64-unknown-linux2.4 # Is PLATFORM even needed?
elif [[ $arch == "aarch64" ]]; then
  export PLATFORM=aarch64-unknown-linux-gnu
fi
echo "PLATFORM IS: $PLATFORM"

swSO_Major=9
swSO_Minor=3

#swPackageName=dyninst-11f20bf   # http://git.dyninst.org/?p=dyninst.git;a=summary 3/21/2014
#swPackageName=dyninst_9.2       # http://github.com/dyninst/dyninst pull on 11/7/2016
swPackageName=dyninst           # Dyninst 9.3 as a submodule

swSourceDir=$PWD/external/$swPackageName
swBuildDir=$swSourceDir
swInstallDir=$PWD/external/install
swPrefix=$swInstallDir


if [ -e "$swInstallDir/lib/libdyninstAPI.so" ]; then
  buildDyninstAPI=0
else
  buildDyninstAPI=1
fi

if [[ $buildDyninstAPI == 1 ]]
then
  echo "--------------------------------------------- Building DyninstAPI"
  echo  "swDebugStr='$swDebugStr'"
  mkdir -p $swBuildDir
  cd $swBuildDir
  #updated for Aarch64  (c++ to g++)
  echo arch: "$arch"
  if [[ $arch == "x86_64" ]]
  then
    cmake $swSourceDir \
      $swDebugStr \
      -DCMAKE_C_COMPILER=/opt/gcc/$gccVer/bin/gcc \
      -DCMAKE_CXX_COMPILER=/opt/gcc/$gccVer/bin/g++ \
      -DCMAKE_INSTALL_PREFIX=$swPrefix \
      -DCMAKE_INSTALL_EXEC_PREFIX=$swPrefix \
      -DPATH_BOOST=$boost_inst_base \
      -DBoost_INCLUDE_DIR=$boost_inc \
      -DLIBDWARF_INCLUDE_DIR=$dwarfDir/include \
      -DLIBDWARF_LIBRARIES=$dwarfDir/lib/libdwarf.so \
      -DLIBELF_INCLUDE_DIR=$elfDir/include \
      -DLIBELF_LIBRARIES=$elfDir/lib/libelf.so \
      $swSourceDir

      #-DCMAKE_BUILD_TYPE=RelWithDebInfo \

  elif [[ $arch == "aarch64" ]]
  then
    cmake $swSourceDir \
      $swDebugStr \
      -DCMAKE_C_COMPILER=/opt/gcc/$gccVer/bin/gcc \
      -DCMAKE_CXX_COMPILER=/opt/gcc/$gccVer/bin/g++ \
      -DCMAKE_INSTALL_PREFIX=$swPrefix \
      -DCMAKE_INSTALL_EXEC_PREFIX=$swPrefix \
      -DPATH_BOOST=$boost_inst_base \
      -DBoost_INCLUDE_DIR=$boost_inc \
      -DLIBDWARF_INCLUDE_DIR=$dwarfDir/include \
      -DLIBDWARF_LIBRARIES=$dwarfDir/lib/libdwarf.so \
      -DLIBELF_INCLUDE_DIR=$elfDir/include/libelf \
      -DLIBELF_LIBRARIES=$elfDir/lib64/libelf.so \
      $swSourceDir
  fi

  cd $swSourceDir
  make
  make install
fi

cd $topLevel
autoreconf -ifv

./configure --prefix=$BUILD_DIR --with-boost=$boost_inst_base --with-dyninst=$swInstallDir --with-dyninst-libdir=$swInstallDir/lib

# Deliver DSOs and commnode on install
if [[ $doingInstall == "1" ]]
then
  mkdir -p $BUILD_DIR/lib/ $BUILD_DIR/libexec
  if [ $arch == "x86_64" ]
  then
    cp $elfDir/lib/libelf.so.1 $BUILD_DIR/lib/
  elif [ $arch = "aarch64" ]
  then
    cp $elfDir/lib64/libelf.so.1 $BUILD_DIR/lib/
  fi
  chmod -R 755 $BUILD_DIR/lib/ $BUILD_DIR/libexec
fi

make DWARF_HOME=$dwarfDir \
    SW_HOME=$swPrefix \
    BOOST_HOME=$boost_inst_base
make install
make tests;

# install DSOs
mkdir -p $BUILD_DIR/lib/
cp $swPrefix/lib/libdyninstAPI.so.$swSO_Major.$swSO_Minor $BUILD_DIR/lib/
cp $swPrefix/lib/libsymtabAPI.so.$swSO_Major.$swSO_Minor $BUILD_DIR/lib/
cp $swPrefix/lib/libdynDwarf.so.$swSO_Major.$swSO_Minor $BUILD_DIR/lib/
cp $swPrefix/lib/libdynElf.so.$swSO_Major.$swSO_Minor $BUILD_DIR/lib/
cp $swPrefix/lib/libpcontrol.so.$swSO_Major.$swSO_Minor $BUILD_DIR/lib/
cp $swPrefix/lib/libcommon.so.$swSO_Major.$swSO_Minor $BUILD_DIR/lib/
cp $boost_inst_base/lib/libboost_thread.so.$boostSO_Major.$boostSO_Minor.$boostSO_Fix $BUILD_DIR/lib/
cp $boost_inst_base/lib/libboost_system.so.$boostSO_Major.$boostSO_Minor.$boostSO_Fix $BUILD_DIR/lib/
cp $boost_inst_base/lib/libboost_date_time.so.$boostSO_Major.$boostSO_Minor.$boostSO_Fix $BUILD_DIR/lib/
cp $boost_inst_base/lib/libboost_atomic.so.$boostSO_Major.$boostSO_Minor.$boostSO_Fix $BUILD_DIR/lib/
cp $boost_inst_base/lib/libboost_chrono.so.$boostSO_Major.$boostSO_Minor.$boostSO_Fix $BUILD_DIR/lib/
chmod -R 755 $BUILD_DIR/lib/

cd $topLevel
mkdir -p $BUILD_DIR/docs
cp $PWD/extras/docs/ATTRIBUTIONS_cti.txt $BUILD_DIR/docs
mkdir $BUILD_DIR/examples
cp -R $PWD/examples/* $BUILD_DIR/examples

mkdir -p $BUILD_DIR/lib/pkgconfig/
rm -f $BUILD_DIR/lib/pkgconfig/*
cp $PWD/scripts/craytools_be.pc  $BUILD_DIR/lib/pkgconfig/craytools_be.pc
cp $PWD/scripts/craytools_fe.pc  $BUILD_DIR/lib/pkgconfig/craytools_fe.pc
chmod a+rwx $BUILD_DIR/lib/pkgconfig/craytools_be.pc
chmod a+rwx $BUILD_DIR/lib/pkgconfig/craytools_fe.pc

echo "Done"
