package org.example;


import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

public class BIP32JavaExample {

    private static final X9ECParameters x9 = SECNamedCurves.getByName("secp256k1");
    private static final ECParameterSpec ecSpec = new ECParameterSpec(
            x9.getCurve(),
            x9.getG(),
            x9.getN(),
            x9.getH());

    private static final BigInteger n = ecSpec.getN();
    private static final String BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    static class KeyData {
        byte[] sk, chainCode;
        ECPoint pk;
        int depth, childNumber;
        byte[] parentFingerprint;

        KeyData(byte[] sk, byte[] chainCode) {
            this.sk = sk;
            this.chainCode = chainCode;
            this.pk = ecSpec.getG().multiply(new BigInteger(1, sk)).normalize();
            this.depth = 0;
            this.childNumber = 0;
            this.parentFingerprint = new byte[4];
        }

        KeyData(byte[] sk, byte[] chainCode, ECPoint pk, int depth,
                int childNumber, byte[] parentFingerprint) {
            this.sk = sk;
            this.chainCode = chainCode;
            this.pk = pk;
            this.depth = depth;
            this.childNumber = childNumber;
            this.parentFingerprint = parentFingerprint;
        }
    }

    public static KeyData generateMasterKey(byte[] seed) throws Exception {
        byte[] I = hmacSha512("Bitcoin seed".getBytes(), seed);
        byte[] IL = Arrays.copyOfRange(I, 0, 32);
        byte[] IR = Arrays.copyOfRange(I, 32, 64);
        return new KeyData(IL, IR);
    }

    public static byte[] hmacSha512(byte[] key, byte[] data) throws Exception {
        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] out = new byte[64];
        hmac.doFinal(out, 0);
        return out;
    }

    public static byte[] fingerprint(ECPoint pubKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] shaHash = sha.digest(pubKey.getEncoded(true));
        RIPEMD160Digest rmd = new RIPEMD160Digest();
        rmd.update(shaHash, 0, shaHash.length);
        byte[] ripemd = new byte[20];
        rmd.doFinal(ripemd, 0);
        return Arrays.copyOf(ripemd, 4);
    }

    public static KeyData deriveChildKey(KeyData parent, int index, boolean hardened) throws Exception {
        int idx = hardened ? (index | 0x80000000) : index;
        ByteBuffer data;
        if (hardened) {
            data = ByteBuffer.allocate(1 + 32 + 4);
            data.put((byte) 0x00);
            data.put(parent.sk);
            data.putInt(idx);
        } else {
            data = ByteBuffer.allocate(33 + 4);
            data.put(parent.pk.getEncoded(true));
            data.putInt(idx);
        }
        byte[] I = hmacSha512(parent.chainCode, data.array());
        byte[] IL = Arrays.copyOfRange(I, 0, 32);
        byte[] IR = Arrays.copyOfRange(I, 32, 64);

        BigInteger parseIL = new BigInteger(1, IL);
        BigInteger kpar = new BigInteger(1, parent.sk);
        BigInteger childSkInt = parseIL.add(kpar).mod(n);
        if (childSkInt.equals(BigInteger.ZERO)) {
            throw new RuntimeException("Derived zero key!");
        }
        byte[] childSk = childSkInt.toByteArray();
        if (childSk.length > 32) {
            childSk = Arrays.copyOfRange(childSk, childSk.length - 32, childSk.length);
        } else if (childSk.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(childSk, 0, tmp, 32 - childSk.length, childSk.length);
            childSk = tmp;
        }

        ECPoint childPk = ecSpec.getG().multiply(childSkInt).normalize();
        byte[] fingerprint = fingerprint(parent.pk);

        return new KeyData(childSk, IR, childPk, parent.depth + 1, idx, fingerprint);
    }

    public static KeyData derivePath(KeyData master, String path) throws Exception {
        if (!path.startsWith("m")) {
            throw new IllegalArgumentException("Path must start with 'm'");
        }
        KeyData kd = master;
        if (path.length() == 1) return kd;
        String[] parts = path.substring(2).split("/");
        for (String part : parts) {
            boolean hardened = part.endsWith("'");
            int idx = Integer.parseInt(hardened ? part.substring(0, part.length() - 1) : part);
            kd = deriveChildKey(kd, idx, hardened);
        }
        return kd;
    }

    public static String base58CheckEncode(byte[] payload) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(sha256.digest(payload));
        byte[] full = new byte[payload.length + 4];
        System.arraycopy(payload, 0, full, 0, payload.length);
        System.arraycopy(hash, 0, full, payload.length, 4);
        return base58Encode(full);
    }

    public static String base58Encode(byte[] input) {
        BigInteger intData = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (intData.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divmod = intData.divideAndRemainder(BigInteger.valueOf(58));
            intData = divmod[0];
            int digit = divmod[1].intValue();
            sb.append(BASE58.charAt(digit));
        }
        for (int i = 0; i < input.length && input[i] == 0; i++) {
            sb.append('1');
        }
        return sb.reverse().toString();
    }

    public static String encodeXPrv(KeyData kd) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(78);
        buf.putInt(0x0488ADE4); // xprv
        buf.put((byte) kd.depth);
        buf.put(kd.parentFingerprint);
        buf.putInt(kd.childNumber);
        buf.put(kd.chainCode);
        buf.put((byte) 0x00);
        buf.put(kd.sk);
        return base58CheckEncode(buf.array());
    }

    public static String encodeXPub(KeyData kd) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(78);
        buf.putInt(0x0488B21E); // xpub
        buf.put((byte) kd.depth);
        buf.put(kd.parentFingerprint);
        buf.putInt(kd.childNumber);
        buf.put(kd.chainCode);
        buf.put(kd.pk.getEncoded(true));
        return base58CheckEncode(buf.array());
    }

    /**
     * 生成比特币测试网 P2PKH 地址
     */
    public static String pubKeyToTestnetAddress(ECPoint pubKey) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] shaHash = sha256.digest(pubKey.getEncoded(true));

        RIPEMD160Digest rmd = new RIPEMD160Digest();
        rmd.update(shaHash, 0, shaHash.length);
        byte[] pubKeyHash = new byte[20];
        rmd.doFinal(pubKeyHash, 0);

        // 测试网版本号 0x6F
        byte[] versionedPayload = new byte[1 + pubKeyHash.length];
        versionedPayload[0] = (byte) 0x6F;
        System.arraycopy(pubKeyHash, 0, versionedPayload, 1, pubKeyHash.length);

        // Base58Check编码
        return base58CheckEncode(versionedPayload);
    }

    public static void main(String[] args) throws Exception {
        byte[] seed = hexStringToByteArray("000102030405060708090a0b0c0d0e0f");
        KeyData master = generateMasterKey(seed);

        System.out.println("m");
        System.out.println(" xprv: " + encodeXPrv(master));
        System.out.println(" xpub: " + encodeXPub(master));
        System.out.println(" testnet address: " + pubKeyToTestnetAddress(master.pk));
        System.out.println();

        String[] paths = {
                "m/0'",
                "m/0'/1",
                "m/0'/1/2'",
                "m/0'/1/2'/2",
                "m/0'/1/2'/2/1000000000"
        };
        for (String path : paths) {
            KeyData kd = derivePath(master, path);
            System.out.println(path);
            System.out.println(" xprv: " + encodeXPrv(kd));
            System.out.println(" xpub: " + encodeXPub(kd));
            System.out.println(" testnet address: " + pubKeyToTestnetAddress(kd.pk));
            System.out.println();
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        return data;
    }
}
