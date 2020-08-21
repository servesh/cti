/******************************************************************************\
 * cti_manifest_unit_test.hpp - Manifest unit tests for CTI
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

#include <memory>
#include <vector>

#include "frontend/cti_fe_iface.hpp"

#include "MockFrontend/Frontend.hpp"

#include "frontend/transfer/Session.hpp"
#include "frontend/transfer/Manifest.hpp"

#include "cti_fe_unit_test.hpp"

// The fixture for unit testing the manifest
class CTIManifestUnitTest : public CTIAppUnitTest
{
protected: // variables
    std::shared_ptr<Session>  sessionPtr;
    std::shared_ptr<Manifest> manifestPtr;
    std::vector<std::string> file_names;

    // vectors to store temp files in
    std::vector<std::string> temp_dir_names;
    std::vector<std::string> temp_file_names;

    // consts for test files
    const std::string TEST_FILE_NAME = "archive_test_file";

protected: // interface
    CTIManifestUnitTest();
    ~CTIManifestUnitTest();
};
