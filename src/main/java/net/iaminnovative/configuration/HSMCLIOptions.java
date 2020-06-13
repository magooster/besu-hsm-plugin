/*
 * Copyright 2020 Ian Cusden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package net.iaminnovative.configuration;

import com.google.common.base.MoreObjects;
import picocli.CommandLine.Option;

public class HSMCLIOptions {

    private static final String KEY_ALIAS = "--plugin-hsm-key-alias";
    private static final String KEYSTORE_PASSWORD = "--plugin-hsm-keystore-password";
    private static final String KEYSTORE_CONFIG = "--plugin-hsm-keystore-config";

    @Option(
            names = {KEY_ALIAS},
            paramLabel = "<STRING>",
            description = "The key alias")
    public String keyAlias;

    @Option(
            names = {KEYSTORE_PASSWORD},
            paramLabel = "<STRING>",
            description = "The user password (pin) for the keystore")
    public String keystorePassword;

    @Option(
            names = {KEYSTORE_CONFIG},
            paramLabel = "<STRING>",
            description = "The pcks11 config file")
    public String keystoreConfig;

    private HSMCLIOptions() {}

    public static HSMCLIOptions create() {
        return new HSMCLIOptions();
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("keyAlias", keyAlias)
                .add("keystoreConfig", keystoreConfig)
                .toString();
    }
}
