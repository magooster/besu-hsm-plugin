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

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;

public class HSMPublicKey implements PublicKey {

    private final ECPoint ecPoint;

    HSMPublicKey(final ECPublicKey ecPublicKey) {
        ecPoint = ecPublicKey.getW();
    }

    @Override
    public ECPoint getW() {
        return ecPoint;
    }
}
