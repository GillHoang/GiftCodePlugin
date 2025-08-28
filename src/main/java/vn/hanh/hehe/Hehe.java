package vn.hanh.hehe;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.HandlerList;
import org.bukkit.plugin.java.JavaPlugin;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.util.*;

public final class Hehe extends JavaPlugin {
    private final Map<UUID, Set<String>> usedByPlayer = new HashMap<>();
    private final Map<UUID, Long> cooldown = new HashMap<>();
    private File redeemFile;
    private YamlConfiguration redeemCfg;
    private LicenseManager licenseManager;

    @Override
    public void onEnable() {
        // Plugin startup logic
        saveDefaultConfig();

        this.licenseManager = new LicenseManager(this);

        // validate ngay
        licenseManager.validateAsync(null);

        // kiểm tra định kỳ
        licenseManager.startPeriodicCheck();

        // ví dụ chặn lệnh nếu chưa hợp lệ (hoặc trong command handlers)
        if (!licenseManager.isLicenseValid()) {
            getLogger().warning("Running in limited mode until license validated.");
        }

        Objects.requireNonNull(getCommand("code")).setExecutor(this);

        redeemFile = new File(getDataFolder(), "redeem.yml");
        if (!redeemFile.exists()) {
            try {
                getDataFolder().mkdirs();
                redeemFile.createNewFile();
            } catch (IOException io) {
                getLogger().warning("không tạo được usage.yml");
            }
        }

        redeemCfg = YamlConfiguration.loadConfiguration(redeemFile);
        loadRedeem();

        getLogger().info("Hệ thống nhập code đã sẵn sàng");
    }

    public LicenseManager getLicenseManager() {
        return licenseManager;
    }


    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command, @NotNull String label, String[] args) {
        if (!command.getName().equalsIgnoreCase("code")) return false;

        if (!(sender instanceof Player p)) {
            sender.sendMessage("Chỉ người chơi mới dùng được");
            return false;
        }

        if (!p.hasPermission("hehe.redeem")) {
            p.sendMessage("Bạn không có quyền");
            return false;
        }

        if (!(args.length == 1)) {
            p.sendMessage("Dùng: /code <mã>");
            return false;
        }

        // Kiem tra cooldown
        long now = System.currentTimeMillis();
        long last = cooldown.getOrDefault(p.getUniqueId(), 0L);
        int limit = 2000;
        if (now - last < limit) {
            p.sendMessage("Đợi một chút rồi sử dụng lại");
            return true;
        }
        cooldown.put(p.getUniqueId(), now);

        // Code
        String code = args[0].trim().toUpperCase(Locale.ROOT);

        List<String> cmds = getConfig().getStringList("giftcodes." + code);
        if (cmds.isEmpty()) {
            p.sendMessage("Mã bạn nhập không hợp lệ");
            return true;
        }

        Set<String> used = usedByPlayer.computeIfAbsent(p.getUniqueId(), k -> new HashSet<>());
        if (used.contains(code)) {
            p.sendMessage("Bạn đã dùng mã này rồi");
            return true;
        }
        used.add(code);
        redeemCfg.set(p.getUniqueId().toString(), new ArrayList<>(used));
        try {
            redeemCfg.save(redeemFile);
        } catch (IOException ignored) {

        }


        String name = p.getName();
        for (String raw : cmds) {
            String cmdLine = raw.replace("%player%", name);
            Bukkit.dispatchCommand(Bukkit.getConsoleSender(), cmdLine);
        }

        p.sendMessage("Nhập mã thành công");
        return true;
    }

    @Override
    public void onDisable() {
        // Plugin shutdown logic
        saveRedeem();

        Bukkit.getScheduler().cancelTasks(this);
        HandlerList.unregisterAll(this);

        usedByPlayer.clear();
        cooldown.clear();
    }

    private void loadRedeem() {
        usedByPlayer.clear();
        if (redeemCfg == null) return;

        for(String key : redeemCfg.getKeys(false)) {
            try {
                UUID uuid = UUID.fromString(key);
                List<String> list = redeemCfg.getStringList(key);
                usedByPlayer.put(uuid, new HashSet<>(list));
            } catch (IllegalArgumentException ignored) {

            }
        }
    }

    private void saveRedeem() {
        if (redeemCfg == null) return;

        for (Map.Entry<UUID, Set<String>> e : usedByPlayer.entrySet()) {
            redeemCfg.set(e.getKey().toString(), new ArrayList<>(e.getValue()));
        }
        try {
            redeemCfg.save(redeemFile);
        } catch (IOException ignored) {
        }
    }
}
