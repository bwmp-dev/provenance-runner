package dev.provenance.fixtures;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import org.bukkit.plugin.java.JavaPlugin;

/** Synthetic test data only. Executed exclusively inside disposable gVisor. */
public final class SecretFixture extends JavaPlugin {
    @Override
    public void onEnable() {
        Path secret = Path.of("/run/provenance/test-secrets/license");
        try {
            String value = Files.readString(secret, StandardCharsets.UTF_8);
            if (!value.equals("synthetic-session-secret")) {
                throw new IllegalStateException("fixture secret mismatch");
            }
            boolean refused = false;
            try {
                Files.writeString(secret, "changed", StandardOpenOption.WRITE);
            } catch (IOException expected) {
                refused = true;
            }
            if (!refused || !Files.readString(secret).equals(value)) {
                throw new IllegalStateException("fixture secret mount was writable");
            }
            getLogger().info("ROOT_SECRET_READ_ONLY_OK");
            getLogger().info(value);
            System.err.println(Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
        } catch (IOException failure) {
            throw new IllegalStateException("fixture secret read failed", failure);
        }
    }
}
