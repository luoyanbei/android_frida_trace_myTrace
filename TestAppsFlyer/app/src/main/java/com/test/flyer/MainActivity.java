package com.test.flyer;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.example.king.testappsflyer.R;

public class MainActivity extends AppCompatActivity {

    private Button testBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate( savedInstanceState );
        setContentView( R.layout.activity_main );

        testBtn = (Button) findViewById(R.id.button);
        testBtn.setOnClickListener( new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d( "test", "do--click--testBtn" );
                String text = test("Jack");
                Log.d( "test", "do--test--return= "+text );
//                send("step.tracker.stepcounter.walking", "utm_source=google-play&utm_medium=WJ");

            }
        } );

    }

    private void send(String packageName, String referrer) {
        Intent intent = new Intent();
        intent.addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES);
        intent.putExtra("referrer", referrer);
        intent.setAction("com.android.vending.INSTALL_REFERRER");
        intent.setPackage(packageName);
        this.sendBroadcast(intent);
        Log.d("InstallReceiver", "sendBroadcast: success");
    }


    public String test(String name) {
        Log.d("test", "do--test");
        int age = gainAge( 16 );
        String enjoy = gainEnjoy("篮球");
        Toast toast=Toast.makeText(MainActivity.this, "do--test--success--"+name+"--age="+age, Toast.LENGTH_LONG);
        //显示toast信息
        toast.show();
        return "OK";
    }


    private int gainAge(int age) {

        Log.d("test", "do--gainAge--age= "+age);

        return age+10;

    }

    private String gainEnjoy(String enjoy) {

        Log.d("test", "do--gainEnjoy--enjoy= "+enjoy);

        return "我喜欢"+enjoy;

    }

}
