package com.example.maengjo.reader_contactless;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.Ndef;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.widget.TextView;

import java.io.IOException;
import java.util.Arrays;

class MemorySector {
    int blockInSectorNum;
    byte[][] data;
}

public class MainActivity extends Activity {

    private NfcAdapter nfcAdapter;
    private Intent intent;
    private PendingIntent pendingIntent;
    private NfcA nfcA;
    private MifareClassic mifareClassic;
    private IsoDep isoDep;
    private Ndef ndef;

    private TextView tagDesc;
    private MemorySector memorySector = new MemorySector();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tagDesc = (TextView)findViewById(R.id.tagDesc);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        intent = new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);
    }

    @Override
    protected void onPause() {
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null) {
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag != null) {
            nfcA = NfcA.get(tag);
            ndef = Ndef.get(tag);
            mifareClassic = MifareClassic.get(tag);

            byte[] tagId = tag.getId();
            String[] techlist = tag.getTechList();
            int techlist_num = tag.getTechList().length;

            Boolean auth = false;

            int sector_count = mifareClassic.getSectorCount();
            int block_count = mifareClassic.getBlockCount();
            //int sectors2block = mifareClassic.sectorToBlock(0);
            //int block2sectors = mifareClassic.blockToSector(0);
            int mifare_type = mifareClassic.getType();
            int mem_size = mifareClassic.getSize();
            int max_transceive_size = mifareClassic.getMaxTransceiveLength();
            int blockInSector = mifareClassic.getBlockCountInSector(0);
            int mifare_timeout = mifareClassic.getTimeout();


            byte[][] mem_data = new byte[sector_count][block_count];
            for (byte[] row : mem_data) {
                Arrays.fill(row, (byte) 0);
            }

            for (int i = 0; i < sector_count; i++) {
                auth = authToMifare(mifareClassic, i);
                if (auth)
                {
                    for (int j = 0; j < block_count; j++) {
                        try {
                            mem_data[i] = mifareClassic.readBlock(j);
                            //memorySector
                        }catch (IOException e) {

                        }
                    }
                }
            }











            byte[] read_data;


            tagDesc.setText("TagID: " + toHexString(tagId) + "\n");
            tagDesc.append("TechList: \n");
            for (int i = 0; i < techlist_num; i++) {
                tagDesc.append(" " + Integer.toString(i) + "= ");
                tagDesc.append(techlist[i].toString() + "\n");
            }
            tagDesc.append("\nATQA: 0x" + toHexString(nfcA.getAtqa()));
            tagDesc.append("\nSAK: 0x" + Short.toString(nfcA.getSak()));
            tagDesc.append("\nMaximum transceive length: " + Integer.toString(nfcA.getMaxTransceiveLength()) + "byte");
            tagDesc.append("\nDefault maximum transceive time-out: " + Integer.toString(nfcA.getTimeout()) + "ms");

            if (ndef != null) {
                tagDesc.append("\nNDEF type: " + ndef.getType());
                tagDesc.append("\nNDEF size: " + Integer.toString(ndef.getMaxSize()));
            } else {
                tagDesc.append("\nNo NEDF data storage populated");
            }

            tagDesc.append("\nMemory size");
            tagDesc.append("\nTotal size: " + Integer.toString(mem_size) + "KBytes");


/*
            for (int i = 0; i < sector_count; i++) {
                boolean ret = mifareClassic.authenticateSectorWithKeyA(0, authenticate_key_A1);
                if (ret == false) {
                    ret = mifareClassic.authenticateSectorWithKeyA(i, authenticate_key_A2);
                    if (ret == false) {
                        ret = mifareClassic.authenticateSectorWithKeyA(i, authenticate_key_A3);
                        if (ret == false) {
                            tagDesc.append("\nUnknow Authenticate KEY");
                        }
                    }
                }

                if (ret == true) {
                    read_data = mifareClassic.readBlock(i);
                }
            }
  */
            tagDesc.append("\n" + Integer.toString(sector_count) + " sectors, with " + Integer.toString(blockInSector) + " blocks per sector");
            tagDesc.append("\n" + Integer.toString(block_count) + " blocks, with " + Integer.toString(block_count/blockInSector) + " bytes per block");



        }
    }

    public static final String CHARS = "0123456789ABCDEF";
    public static String toHexString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; ++i) {
            sb.append(CHARS.charAt((data[i] >> 4) & 0x0F))
                    .append(CHARS.charAt(data[i] & 0x0F));
        }
        return sb.toString();
    }

    public static Boolean authToMifare(MifareClassic mfc, int sector) {
        boolean ret = false;
        //JAVA에서는 128 (0x80)이 넘으면 안된다 : signed/unsigned 구분이 없기 때문
        byte[] [] auth_key = {
                {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF},
                {(byte)0xA0, (byte)0xA1, (byte)0xA2, (byte)0xA3, (byte)0xA4, (byte)0xA5},
                {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00},
                {(byte)0xA0, (byte)0xB0, (byte)0xC0, (byte)0xD0, (byte)0xE0, (byte)0xF0},
                {(byte)0xA1, (byte)0xB1, (byte)0xC1, (byte)0xD1, (byte)0xE1, (byte)0xF1},
                {(byte)0xD3, (byte)0xF7, (byte)0xD3, (byte)0xF7, (byte)0xD3, (byte)0xF7},
        };

        try {
            mfc.connect();

            for (int i = 0; i < 6; i++) {
                ret = mfc.authenticateSectorWithKeyA(sector, auth_key[i]);
                if (ret) {
                    return ret;
                }
            }

        }catch (IOException e) {
            //AlertDialog.Builder alertbox = new AlertDialog.Builder(this);
            //alertbox.setMessage("Auth Key fail Block 0");
        }
        return ret;
    }
}
