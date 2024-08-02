/************************************************************************
 * NASA Docket No. GSC-18,719-1, and identified as “core Flight System: Bootes”
 *
 * Copyright (c) 2020 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ************************************************************************/

/**
 * @file
 *
 *  The Cam App header file containing version information
 */

#ifndef CAM_APP_VERSION_H
#define CAM_APP_VERSION_H

/* Development Build Macro Definitions */

#define CAM_APP_BUILD_NUMBER    46 /*!< Development Build: Number of commits since baseline */
#define CAM_APP_BUILD_BASELINE  "equuleus-rc1" /*!< Development Build: git tag that is the base for the current development */
#define CAM_APP_BUILD_DEV_CYCLE "equuleus-rc2" /**< @brief Development: Release name for current development cycle */
#define CAM_APP_BUILD_CODENAME  "Equuleus" /**< @brief: Development: Code name for the current build */

/*
 * Version Macros, see \ref cfsversions for definitions.
 */
#define CAM_APP_MAJOR_VERSION 1  /*!< @brief Major version number. */
#define CAM_APP_MINOR_VERSION 0  /*!< @brief Minor version number. */
#define CAM_APP_REVISION      0  /*!< @brief Revision version number. Value of 0 indicates a development version.*/

/**
 * @brief Last official release.
 */
#define CAM_APP_LAST_OFFICIAL "v1.0.0"

/*!
 * @brief Mission revision.
 *
 * Reserved for mission use to denote patches/customizations as needed.
 * Values 1-254 are reserved for mission use to denote patches/customizations as needed. NOTE: Reserving 0 and 0xFF for
 * cFS open-source development use (pending resolution of nasa/cFS#440)
 */
#define CAM_APP_MISSION_REV 0xFF

#define CAM_APP_STR_HELPER(x) #x /*!< @brief Helper function to concatenate strings from integer macros */
#define CAM_APP_STR(x) \
    CAM_APP_STR_HELPER(x) /*!< @brief Helper function to concatenate strings from integer macros */

/*! @brief Development Build Version Number.
 * @details Baseline git tag + Number of commits since baseline. @n
 * See @ref cfsversions for format differences between development and release versions.
 */
#define CAM_APP_VERSION CAM_APP_BUILD_BASELINE "+dev" CAM_APP_STR(CAM_APP_BUILD_NUMBER)

/**
 * @brief Max Version String length.
 * 
 * Maximum length that an OSAL version string can be.
 * 
 */
#define CAM_APP_CFG_MAX_VERSION_STR_LEN 256

#endif /* CAM_APP_VERSION_H */
