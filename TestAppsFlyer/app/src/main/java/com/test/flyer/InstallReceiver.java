package com.test.flyer;

import java.util.Timer;
import java.util.TimerTask;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.util.logging.Handler;
import java.util.logging.LogRecord;

/**
 * 广告显示进行安装监听进行上报
 */

public class InstallReceiver extends BroadcastReceiver {

    private static String TAG = "InstallReceiver";
    private Context mContext;

    /**
     *
     *
     * @param context
     * @param intent
     */
    @Override
    public void onReceive(Context context, Intent intent) {



    }

    private void send(String packageName, String referrer) {

    }




}
