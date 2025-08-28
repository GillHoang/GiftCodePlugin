package vn.hanh.hehe;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.Plugin;
import vn.hanh.hehe.crypto.Ed25519;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * LicenseManager (Java 17+, Spigot/Paper)
 * - POST /license/validate (JSON)
 * - Verify Ed25519 signature (server signs with private key)
 * - Grace window & periodic check
 * - Only reads license.key (+ optional license.ip) from config.yml
 * <p>
 * config.yml (tối giản):
 * license:
 * key: "xxxx-xxxx-xxxx-xxxx-xxxx"
 * ip: ""   # optional
 */
public class LicenseManager {
    private final Plugin plugin;

    // ====== CÁC HẰNG SỐ ẨN TRONG CODE (client không thấy trong config.yml) ======
    private static final String PLUGIN_ID = "giftcode-plugin"; // phải trùng server
    private static final String VALIDATION_URL = "http://localhost:3000/license/validate";
    private static final int CHECK_INTERVAL_SECONDS = 3600;
    private static final int GRACE_SECONDS = 86400;
    private static final boolean AUTO_CHECK = true;

    // Ed25519 PUBLIC KEY (PEM) – CHỈ LÀ PUBLIC, an toàn để nhúng vào JAR
    private static final String PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n" +
                    "MCowBQYDK2VwAyEAWWWZJVjAlGM1v3KV2VJb6lXEzsrHt9S2ZRTnNi7m+eA=\n" +
                    "-----END PUBLIC KEY-----\n";

    // ====== Runtime/config ======
    private String licenseKey;
    private String staticIp;     // optional: gửi ip cố định nếu có
    private String serverId;     // lưu local vào machine.dat
    private final AtomicBoolean checking = new AtomicBoolean(false);

    private volatile boolean isLicenseValid = false;
    private volatile long lastOkAt = 0L;

    private PublicKey publicKey;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final String KEY_PATTERN = "^[A-Za-z0-9]{4}(-[A-Za-z0-9]{4}){4}$";

    public LicenseManager(Plugin plugin) {
        this.plugin = plugin;
        try {
            this.publicKey = Ed25519.loadPublicKeyFromPEM(PUBLIC_KEY_PEM);
        } catch (Exception e) {
            plugin.getLogger().severe("[License] Failed to load Ed25519 public key: " + e.getMessage());
        }
        loadMinimalConfig();
        ensureServerIdFile();
    }

    // ---------- Public API ----------
    public void validateAsync(String mcUsername) {
        if (checking.getAndSet(true)) return;
        CompletableFuture.supplyAsync(() -> performValidation(mcUsername))
                .whenComplete((ok, ex) -> {
                    checking.set(false);
                    if (ex != null) {
                        plugin.getLogger().warning("[License] Validation exception: " + ex.getMessage());
                        handlePostCheck(false, "exception");
                        return;
                    }
                    handlePostCheck(ok, null);
                });
    }

    public void startPeriodicCheck() {
        if (!AUTO_CHECK) return;
        long period = 20L * Math.max(30, CHECK_INTERVAL_SECONDS);
        Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> validateAsync(null), period, period);
    }

    public boolean isLicenseValid() {
        if (isLicenseValid) return true;
        return (System.currentTimeMillis() - lastOkAt) <= (GRACE_SECONDS * 1000L);
    }

    public boolean shouldBlockCommands() {
        return !isLicenseValid();
    }

    public String getMaskedLicenseKey() {
        if (licenseKey == null || licenseKey.length() < 10) return "xxxx-xxxx-xxxx-xxxx-xxxx";
        return licenseKey.substring(0, 4) + "-****-****-****-" + licenseKey.substring(licenseKey.length() - 4);
    }

    public void reloadConfig() {
        loadMinimalConfig();
        validateAsync(null);
    }

    public void sendLicenseWarning(CommandSender sender, String reason) {
        sender.sendMessage(ChatColor.RED + "License Error" + (reason != null ? " (" + reason + ")" : ""));
        sender.sendMessage(ChatColor.YELLOW + "Please set a valid license key in config.yml.");
    }

    // ---------- Core ----------
    private boolean performValidation(String mcUsername) {
        if (!looksLikeKey(licenseKey)) {
            plugin.getLogger().severe("[License] Invalid or missing license.key");
            return false;
        }
        try {
            JsonObject body = new JsonObject();
            body.addProperty("licenseKey", licenseKey);
            body.addProperty("pluginId", PLUGIN_ID);
            body.addProperty("serverId", serverId);
            if (staticIp != null && !staticIp.isEmpty()) body.addProperty("ip", staticIp);
            if (mcUsername != null && !mcUsername.isEmpty()) body.addProperty("mcUsername", mcUsername);

            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);

            URL url = new URL(VALIDATION_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout((int) Duration.ofSeconds(5).toMillis());
            conn.setReadTimeout((int) Duration.ofSeconds(10).toMillis());
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setRequestProperty("User-Agent", plugin.getName() + "/" + plugin.getDescription().getVersion());
            conn.getOutputStream().write(bytes);

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) {
                plugin.getLogger().warning("[License] No body, HTTP " + code);
                return fallbackOnGrace();
            }
            String resp = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            conn.disconnect();
            if (code >= 400) {
                plugin.getLogger().warning("[License] HTTP " + code + " body: " + trimBody(resp));
                return fallbackOnGrace();
            }

            // Verify Ed25519 signature
            JsonObject obj = JsonParser.parseString(resp).getAsJsonObject();
            String signature = optString(obj, "signature", null);
            String rawForSig = stripTrailingSignature(resp);
            boolean sigOk = (publicKey == null) || Ed25519.verify(rawForSig, signature, publicKey);
            if (!sigOk) {
                plugin.getLogger().severe("[License] Signature verification FAILED (Ed25519).");
                return false;
            }

            boolean valid = optBool(obj, "valid", false);
            boolean active = optBool(obj, "active", false);
            boolean expired = optBool(obj, "expired", false);
            String reason = optString(obj, "reason", null);
            String plan = optString(obj, "plan", null);
            int boundServers = optInt(obj, "boundServers", 0);
            int boundIps = optInt(obj, "boundIps", 0);

            if (valid && active && !expired) {
                lastOkAt = System.currentTimeMillis();
                isLicenseValid = true;
                plugin.getLogger().info("[License] OK (" + plan + "), servers=" + boundServers + ", ips=" + boundIps);
                return true;
            } else {
                String r = (reason != null) ? reason : (expired ? "expired" : "invalid");
                plugin.getLogger().severe("[License] NOT VALID: reason=" + r + ", plan=" + plan);
                return false;
            }
        } catch (IOException e) {
            plugin.getLogger().warning("[License] Network error: " + e.getMessage());
            return fallbackOnGrace();
        } catch (Exception e) {
            plugin.getLogger().warning("[License] Unexpected: " + e.getMessage());
            return false;
        }
    }

    private void handlePostCheck(boolean ok, String errTag) {
        if (ok) return;
        if (lastOkAt == 0L) { // initial grace
            lastOkAt = System.currentTimeMillis();
            plugin.getLogger().warning("[License] First failure; entering initial grace (" + GRACE_SECONDS + "s).");
            isLicenseValid = false;
            return;
        }
        if (isWithinGrace()) {
            plugin.getLogger().warning("[License] Using grace window (" + (errTag != null ? errTag : "invalid") + ").");
            isLicenseValid = false;
            return;
        }
        isLicenseValid = false;
        plugin.getLogger().severe("[License] Disabling plugin due to invalid license.");
        Bukkit.getScheduler().runTask(plugin, () -> Bukkit.getPluginManager().disablePlugin(plugin));
    }

    private boolean isWithinGrace() {
        return (System.currentTimeMillis() - lastOkAt) <= (GRACE_SECONDS * 1000L);
    }

    private boolean fallbackOnGrace() {
        if (isWithinGrace()) {
            plugin.getLogger().warning("[License] Network failure; still within grace.");
            return true;
        }
        return false;
    }

    // ---------- Config & local server-id ----------
    private void loadMinimalConfig() {
        this.licenseKey = plugin.getConfig().getString("license.key", "xxxx-xxxx-xxxx-xxxx-xxxx");
        this.staticIp = plugin.getConfig().getString("license.ip", "");
    }

    private void ensureServerIdFile() {
        try {
            File f = new File(plugin.getDataFolder(), "machine.dat");
            if (!f.getParentFile().exists()) f.getParentFile().mkdirs();
            if (f.exists()) {
                this.serverId = new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim();
                if (!serverId.isEmpty()) return;
            }
            this.serverId = UUID.randomUUID().toString();
            java.nio.file.Files.write(f.toPath(), serverId.getBytes(StandardCharsets.UTF_8));
            plugin.getLogger().info("[License] Generated server-id.");
        } catch (Exception e) {
            try {
                InetSocketAddress addr = Bukkit.getServer().getIp().isEmpty()
                        ? new InetSocketAddress(Bukkit.getServer().getPort())
                        : new InetSocketAddress(Bukkit.getServer().getIp(), Bukkit.getServer().getPort());
                this.serverId = (addr.getAddress() != null ? addr.getAddress().getHostAddress() : "0.0.0.0")
                        + ":" + Bukkit.getServer().getPort();
            } catch (Exception ex) {
                this.serverId = "unknown:" + Bukkit.getServer().getPort();
            }
            plugin.getLogger().warning("[License] Using fallback server-id: " + this.serverId);
        }
    }

    // ---------- JSON helpers ----------
    private static boolean looksLikeKey(String k) {
        return k != null && k.matches(KEY_PATTERN);
    }

    private static String trimBody(String s) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", " ");
        if (s.length() > 300) s = s.substring(0, 300) + "...";
        return s;
    }

    private static boolean optBool(JsonObject o, String k, boolean def) {
        return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsBoolean() : def;
    }

    private static String optString(JsonObject o, String k, String def) {
        return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : def;
    }

    private static int optInt(JsonObject o, String k, int def) {
        try {
            return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsInt() : def;
        } catch (Exception e) {
            try {
                return (int) o.get(k).getAsLong();
            } catch (Exception ex) {
                return def;
            }
        }
    }

    private static String stripTrailingSignature(String fullJson) {
        if (fullJson == null) return "";
        return fullJson.replaceFirst(",\\s*\"signature\"\\s*:\\s*\"[^\"]*\"\\s*\\}\\s*$", "}");
    }
}
