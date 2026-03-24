/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-app.h"

int app_initialize(const char *const argv[])
{
    int rv;

    rv = udm_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to initialize UDM");
        return rv;
    }
    ogs_info("UDM initialize...done");

    // BRR: загружаем конфигурацию HSM из той же директории, что и udm.yaml
    char *config_dir = ogs_app()->config.path;
    char *hsm_path = ogs_path_join(config_dir, "hsm.yaml");
    if (hsm_config_load(hsm_path) != 0) {
        ogs_warn("[S3G] HSM config not loaded, HSM disabled");
    }
    ogs_free(hsm_path);
    // BRR

    return OGS_OK;
}

void app_terminate(void)
{
    udm_terminate();
    ogs_info("UDM terminate...done");
}
