/******************************************************************************\
 * cti_useful_unit_test.hpp - /Useful unit tests for CTI
 *
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 ******************************************************************************/

#pragma once

#include <unistd.h>
#include <stdio.h>

#include <memory>
#include <string>
#include <vector>

#include "useful/cti_argv.hpp"
#include "useful/cti_dlopen.hpp"
#include "useful/cti_execvp.hpp"
#include "useful/cti_log.h"
#include "useful/cti_path.h"
#include "useful/cti_stack.h"
#include "useful/cti_wrappers.hpp"

// include google testing files
#include "gmock/gmock.h"
#include "gtest/gtest.h"

// the fixture for unit testing the C archive interface
class CTIUsefulUnitTest : public ::testing::Test
{
protected:


protected:
    CTIUsefulUnitTest();
    ~CTIUsefulUnitTest();
};
