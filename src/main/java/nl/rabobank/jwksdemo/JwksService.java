package nl.rabobank.jwksdemo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class JwksService {
    private enum KeyType {
        CURRENT,
        PREVIOUS
    }

    /**
     * Map to hold keys - in a real scenario, these need to be synced across all instances of the application.
     * Note that this map should store both the current and 'older' public keys, as the latter is needed to verify
     * tokens that were signed with the older key. The 'older' key should only be removed from the map after all
     * tokens that were signed with it have expired.
     */
    private final Map<KeyType, RSAPublicKey> keys = new ConcurrentHashMap<>();

    public JwksService() throws NoSuchAlgorithmException {
        rotateKeys();
    }

    public Map<String, Object> getKeySet() {
        return new JWKSet(List.of(
                createJwk(keys.get(KeyType.CURRENT)),
                createJwk(keys.get(KeyType.PREVIOUS)))
        ).toJSONObject(true);
    }

    private RSAKey createJwk(RSAPublicKey publicKey) {
        return new RSAKey.Builder(publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("default")
                .build();
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can adjust the key size as needed
        return keyPairGenerator.generateKeyPair();
    }

    @Scheduled(fixedDelay = 10000) // TODO: configure the rotation interval
    public void rotateKeys() throws NoSuchAlgorithmException {
        log.info("Rotating keys");

        if (keys.containsKey(KeyType.CURRENT)) {
            keys.put(KeyType.PREVIOUS, keys.get(KeyType.CURRENT));
        }
        keys.put(KeyType.CURRENT, (RSAPublicKey) generateKeyPair().getPublic());
    }
}
