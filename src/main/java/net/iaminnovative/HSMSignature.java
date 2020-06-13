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

import java.math.BigInteger;
import java.util.Arrays;

import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;

public class HSMSignature implements Signature {

    private final byte[] signature;

    HSMSignature(final byte[] signature) {
        this.signature = extractSignatureBytes(signature);
    }

    @Override
    public BigInteger getR() {
        return new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
    }

    @Override
    public BigInteger getS() {
        return new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
    }

    // Decode a DER encoded signature
    private static byte[] extractSignatureBytes(byte[] signature) {

        byte[] sig = new byte[64];

        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];

        int startS = startR + 2 + lengthR;
        int lengthS = signature[startS + 1];

        int offsetR = 0;
        if (signature[startR + 2] == 0) {
            offsetR = 1;
            lengthR = lengthR - 1;
        }

        int offsetS = 0;
        if (signature[startS + 2] == 0) {
            offsetS = 1;
            lengthS = lengthS - 1;
        }

        System.arraycopy(signature, startR + 2 + offsetR, sig, 32 - lengthR, lengthR);
        System.arraycopy(signature, startS + 2 + offsetS, sig, 64 - lengthS, lengthS);

        return sig;
    }
}
