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

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.ECPointUtil;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;

public class HSMSecurityModule implements SecurityModule {

    private static final Logger LOG = LogManager.getLogger();

    public static final String ALGORITHM = "EC";
    public static final String CURVE_NAME = "secp256k1";

    private static final ECGenParameterSpec SECP256K1_CURVE = new ECGenParameterSpec(CURVE_NAME);

    private static Provider provider = Security.getProvider("SunPKCS11");
    private static PrivateKey privateKey;
    private static HSMPublicKey publicKey;

    public HSMSecurityModule() {}

    public void initialize(String keyAlias, String configFile, String password)
            throws SecurityModuleException {
        try {
            provider = provider.configure(configFile);
            Security.addProvider(provider);

            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);

            keyStore.load(null, password.toCharArray());

            privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            if (privateKey != null) {
                // Get certificate of public key
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
                // Get & cache public key
                publicKey = new HSMPublicKey((ECPublicKey) cert.getPublicKey());
            }

        } catch (Exception ex) {
            throw new SecurityModuleException("Keystore Error: " + ex.getMessage(), ex);
        }
    }

    @Override
    public HSMSignature sign(Bytes32 dataHash) throws SecurityModuleException {
        try {
            Signature signatureInstance = Signature.getInstance("NONEwithECDSA", provider);
            signatureInstance.initSign(privateKey);
            signatureInstance.update(dataHash.toArrayUnsafe());
            return new HSMSignature(signatureInstance.sign());
        } catch (final Exception ex) {
            throw new SecurityModuleException(
                    "Unexpected error while signing: " + ex.getMessage(), ex);
        }
    }

    @Override
    public HSMPublicKey getPublicKey() throws SecurityModuleException {
        LOG.info("getPublicKey");
        if (!(publicKey == null)) {
            LOG.info(
                    SECP256K1.PublicKey.create(ECPointUtil.getEncodedBytes(publicKey.getW()))
                            .toString());
        }
        else {

        }
        return publicKey;
    }

    @Override
    public Bytes32 calculateECDHKeyAgreement(PublicKey partyKey) throws SecurityModuleException {

        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(ALGORITHM, provider);
            parameters.init(SECP256K1_CURVE);
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

            ECPublicKeySpec keySpec = new ECPublicKeySpec(partyKey.getW(), ecParameters);

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            java.security.PublicKey publicKey = keyFactory.generatePublic(keySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", provider);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            return Bytes32.wrap(keyAgreement.generateSecret());
        } catch (Exception ex) {
            throw new SecurityModuleException(
                    "Unexpected error while deriving key: " + ex.getMessage(), ex);
        }
    }
}
