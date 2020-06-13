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
package net.iaminnovative;

import java.util.Optional;

import com.google.auto.service.AutoService;
import com.google.common.base.Suppliers;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hyperledger.besu.plugin.BesuContext;
import org.hyperledger.besu.plugin.BesuPlugin;
import org.hyperledger.besu.plugin.services.PicoCLIOptions;
import org.hyperledger.besu.plugin.services.SecurityModuleService;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;

import net.iaminnovative.configuration.HSMCLIOptions;

@AutoService(BesuPlugin.class)
public class HSMSecurityPlugin implements BesuPlugin {

    private static final Logger LOG = LogManager.getLogger();
    private static final String PLUGIN_NAME = "hsm";

    private HSMCLIOptions options;
    private BesuContext context;
    private HSMSecurityModule hsmSecurityModule;

    public HSMSecurityPlugin() {
        this.options = HSMCLIOptions.create();
    }

    @Override
    public Optional<String> getName() {
        return Optional.of("HSM Security Module");
    }

    @Override
    public void register(final BesuContext context) {
        LOG.info("Registering HSM Security Module Plugin");

        this.context = context;

        context.getService(PicoCLIOptions.class)
                .ifPresentOrElse(
                        this::createPicoCLIOptions,
                        () -> LOG.error("Could not obtain PicoCLIOptionsService"));

        context.getService(SecurityModuleService.class)
                .ifPresentOrElse(
                        this::createAndRegister,
                        () ->
                                LOG.error(
                                        "Failed to register Security Module due to missing SecurityModuleService."));


    }

    @Override
    public void start() {
        LOG.info("Starting HSM Security Plugin with options " + options);
        // Initialise here and not in constructor as options aren't available until start
        // TODO: Check for missing arguments (can't set to required in Option otherwise besu command
        // barfs)
        hsmSecurityModule.initialize(
                options.keyAlias, options.keystoreConfig, options.keystorePassword);
    }

    @Override
    public void stop() {
        LOG.debug("Stopping HSM Security Plugin.");
    }

    private void createAndRegister(final SecurityModuleService service) {

        hsmSecurityModule = new HSMSecurityModule();

        service.register(PLUGIN_NAME, Suppliers.memoize(this::getSecurityModule)::get);
    }

    private SecurityModule getSecurityModule() {
        return hsmSecurityModule;
    }

    private void createPicoCLIOptions(final PicoCLIOptions picoCLIOptions) {
        picoCLIOptions.addPicoCLIOptions(PLUGIN_NAME, this.options);
    }
}
