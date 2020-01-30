package com.chariotsolutions.nfc.plugin;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

// using wildcard imports so we can support Cordova 3.x
import org.apache.cordova.*; // Cordova 3.x

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.nfc.tech.TagTechnology;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;


import static com.chariotsolutions.nfc.plugin.Util.byteArrayToJSON;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.text.ParseException;
import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;

import org.jmrtd.BACKey;
import org.jmrtd.BACKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.COMFile;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.DG1File;
import org.jmrtd.lds.DG2File;
import org.jmrtd.lds.FaceImageInfo;
import org.jmrtd.lds.FaceInfo;
import org.jmrtd.lds.LDS;
import org.jmrtd.lds.MRZInfo;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SODFile;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;

import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.graphics.Bitmap;
import java.util.Collection;
import android.util.Base64;
import java.util.Date;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class NfcPlugin extends CordovaPlugin implements NfcAdapter.OnNdefPushCompleteCallback {
    // Custom for Passport by TeeLeK
    private static final String REGISTER_PASSPORT_TAG = "registerPassportTag";
    //  ----- End Custom ------ 


    private static final String REGISTER_MIME_TYPE = "registerMimeType";
    private static final String REMOVE_MIME_TYPE = "removeMimeType";
    private static final String REGISTER_NDEF = "registerNdef";
    private static final String REMOVE_NDEF = "removeNdef";
    private static final String REGISTER_NDEF_FORMATABLE = "registerNdefFormatable";
    private static final String REGISTER_DEFAULT_TAG = "registerTag";
    private static final String REMOVE_DEFAULT_TAG = "removeTag";
    private static final String WRITE_TAG = "writeTag";
    private static final String MAKE_READ_ONLY = "makeReadOnly";
    private static final String ERASE_TAG = "eraseTag";
    private static final String SHARE_TAG = "shareTag";
    private static final String UNSHARE_TAG = "unshareTag";
    private static final String HANDOVER = "handover"; // Android Beam
    private static final String STOP_HANDOVER = "stopHandover";
    private static final String ENABLED = "enabled";
    private static final String INIT = "init";
    private static final String SHOW_SETTINGS = "showSettings";

    private static final String NDEF = "ndef";
    private static final String NDEF_MIME = "ndef-mime";
    private static final String NDEF_FORMATABLE = "ndef-formatable";
    private static final String TAG_DEFAULT = "tag";

    private static final String READER_MODE = "readerMode";
    private static final String DISABLE_READER_MODE = "disableReaderMode";

    // TagTechnology IsoDep, NfcA, NfcB, NfcV, NfcF, MifareClassic, MifareUltralight
    private static final String CONNECT = "connect";
    private static final String CLOSE = "close";
    private static final String TRANSCEIVE = "transceive";
    private TagTechnology tagTechnology = null;
    private Class<?> tagTechnologyClass;

    private static final String CHANNEL = "channel";

    private static final String STATUS_NFC_OK = "NFC_OK";
    private static final String STATUS_NO_NFC = "NO_NFC";
    private static final String STATUS_NFC_DISABLED = "NFC_DISABLED";
    private static final String STATUS_NDEF_PUSH_DISABLED = "NDEF_PUSH_DISABLED";

    private static final String TAG = "NfcPlugin";
    private final List<IntentFilter> intentFilters = new ArrayList<>();
    private final ArrayList<String[]> techLists = new ArrayList<>();

    private NdefMessage p2pMessage = null;
    private PendingIntent pendingIntent = null;

    private Intent savedIntent = null;

    private CallbackContext readerModeCallback;
    private CallbackContext channelCallback;
    private CallbackContext shareTagCallback;
    private CallbackContext handoverCallback;

    private PassportData passportData;
  

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {

        Log.d(TAG, "execute " + action);

        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        // showSettings can be called if NFC is disabled
        // might want to skip this if NO_NFC
        if (action.equalsIgnoreCase(SHOW_SETTINGS)) {
            showSettings(callbackContext);
            return true;
        }

        // the channel is set up when the plugin starts
        if (action.equalsIgnoreCase(CHANNEL)) {
            channelCallback = callbackContext;
            return true; // short circuit
        }

        // allow reader mode to be disabled even if nfc is disabled
        if (action.equalsIgnoreCase(DISABLE_READER_MODE)) {
            disableReaderMode(callbackContext);
            return true; // short circuit
        }

        if (!getNfcStatus().equals(STATUS_NFC_OK)) {
            callbackContext.error(getNfcStatus());
            return true; // short circuit
        }

        createPendingIntent();

        if (action.equalsIgnoreCase(READER_MODE)) {
            int flags = data.getInt(0);
            readerMode(flags, callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_MIME_TYPE)) {
            registerMimeType(data, callbackContext);

        } else if (action.equalsIgnoreCase(REMOVE_MIME_TYPE)) {
            removeMimeType(data, callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_NDEF)) {
            registerNdef(callbackContext);

        } else if (action.equalsIgnoreCase(REMOVE_NDEF)) {
            removeNdef(callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_NDEF_FORMATABLE)) {
            registerNdefFormatable(callbackContext);

        } else if (action.equals(REGISTER_DEFAULT_TAG)) {
            registerDefaultTag(callbackContext);

        } else if (action.equals(REMOVE_DEFAULT_TAG)) {
            removeDefaultTag(callbackContext);

        } else if (action.equalsIgnoreCase(WRITE_TAG)) {
            writeTag(data, callbackContext);

        } else if (action.equalsIgnoreCase(MAKE_READ_ONLY)) {
            makeReadOnly(callbackContext);

        } else if (action.equalsIgnoreCase(ERASE_TAG)) {
            eraseTag(callbackContext);

        } else if (action.equalsIgnoreCase(SHARE_TAG)) {
            shareTag(data, callbackContext);

        } else if (action.equalsIgnoreCase(UNSHARE_TAG)) {
            unshareTag(callbackContext);

        } else if (action.equalsIgnoreCase(HANDOVER)) {
            handover(data, callbackContext);

        } else if (action.equalsIgnoreCase(STOP_HANDOVER)) {
            stopHandover(callbackContext);

        } else if (action.equalsIgnoreCase(INIT)) {
            init(callbackContext);

        } else if (action.equalsIgnoreCase(ENABLED)) {
            // status is checked before every call
            // if code made it here, NFC is enabled
            callbackContext.success(STATUS_NFC_OK);

        } else if (action.equalsIgnoreCase(CONNECT)) {
            String tech = data.getString(0);
            int timeout = data.optInt(1, -1);
            connect(tech, timeout, callbackContext);

        } else if (action.equalsIgnoreCase(TRANSCEIVE)) {
            CordovaArgs args = new CordovaArgs(data); // execute is using the old signature with JSON data

            byte[] command = args.getArrayBuffer(0);
            transceive(command, callbackContext);

        } else if (action.equalsIgnoreCase(CLOSE)) {
            close(callbackContext);

        } else if (action.equals(REGISTER_PASSPORT_TAG)) { // Custom for Passport by TeeLeK

            try {
                JSONObject obj = new JSONObject(data.getString(0));

                passportData = new PassportData(
                    obj.getString("passportNumber"),
                    obj.getString("expirationDate"),
                    obj.getString("birthDate"));

                registerDefaultPassportTag(callbackContext);

            } catch (JSONException e) {
                Log.e(TAG, "JSONException : " + e.getMessage());
            }

        } else {
            // invalid action
            return false;
        }

        return true;
    }

    private String getNfcStatus() {
        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
        if (nfcAdapter == null) {
            return STATUS_NO_NFC;
        } else if (!nfcAdapter.isEnabled()) {
            return STATUS_NFC_DISABLED;
        } else {
            return STATUS_NFC_OK;
        }
    }

    private void readerMode(int flags, CallbackContext callbackContext) {
        Bundle extras = new Bundle(); // not used
        readerModeCallback = callbackContext;
        getActivity().runOnUiThread(() -> {
            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
            nfcAdapter.enableReaderMode(getActivity(), callback, flags, extras);
        });

    }

    private void disableReaderMode(CallbackContext callbackContext) {
        getActivity().runOnUiThread(() -> {
            readerModeCallback = null;
            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
            if (nfcAdapter != null) {
                nfcAdapter.disableReaderMode(getActivity());
            }
            callbackContext.success();
        });
    }

    private NfcAdapter.ReaderCallback callback = new NfcAdapter.ReaderCallback() {
        @Override
        public void onTagDiscovered(Tag tag) {

            JSONObject json;

            // If the tag supports Ndef, try and return an Ndef message
            List<String> techList = Arrays.asList(tag.getTechList());
            if (techList.contains(Ndef.class.getName())) {
                Ndef ndef = Ndef.get(tag);
                json = Util.ndefToJSON(ndef);
            } else {
                json = Util.tagToJSON(tag);
            }

            PluginResult result = new PluginResult(PluginResult.Status.OK, json);
            result.setKeepCallback(true);
            readerModeCallback.sendPluginResult(result);

        }
    };

    // Custom for Passport by TeeLeK
    private void registerDefaultPassportTag(CallbackContext callbackContext) {
        Log.e(TAG, "registerDefaultPassportTag");
        addTagFilter();
        restartNfc();
        callbackContext.success();
    }

    private void registerDefaultTag(CallbackContext callbackContext) {
        addTagFilter();
        restartNfc();
        callbackContext.success();
    }

    private void removeDefaultTag(CallbackContext callbackContext) {
        removeTagFilter();
        restartNfc();
        callbackContext.success();
    }

    private void registerNdefFormatable(CallbackContext callbackContext) {
        addTechList(new String[]{NdefFormatable.class.getName()});
        restartNfc();
        callbackContext.success();
    }

    private void registerNdef(CallbackContext callbackContext) {
        addTechList(new String[]{Ndef.class.getName()});
        restartNfc();
        callbackContext.success();
    }

    private void removeNdef(CallbackContext callbackContext) {
        removeTechList(new String[]{Ndef.class.getName()});
        restartNfc();
        callbackContext.success();
    }

    private void unshareTag(CallbackContext callbackContext) {
        p2pMessage = null;
        stopNdefPush();
        shareTagCallback = null;
        callbackContext.success();
    }

    private void init(CallbackContext callbackContext) {
        Log.d(TAG, "Enabling plugin " + getIntent());

        startNfc();
        if (!recycledIntent()) {
            parseMessage();
        }
        callbackContext.success();
    }

    private void removeMimeType(JSONArray data, CallbackContext callbackContext) throws JSONException {
        String mimeType = data.getString(0);
        removeIntentFilter(mimeType);
        restartNfc();
        callbackContext.success();
    }

    private void registerMimeType(JSONArray data, CallbackContext callbackContext) throws JSONException {
        String mimeType = "";
        try {
            mimeType = data.getString(0);
            intentFilters.add(createIntentFilter(mimeType));
            restartNfc();
            callbackContext.success();
        } catch (MalformedMimeTypeException e) {
            callbackContext.error("Invalid MIME Type " + mimeType);
        }
    }

    // Cheating and writing an empty record. We may actually be able to erase some tag types.
    private void eraseTag(CallbackContext callbackContext) {
        Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NdefRecord[] records = {
                new NdefRecord(NdefRecord.TNF_EMPTY, new byte[0], new byte[0], new byte[0])
        };
        writeNdefMessage(new NdefMessage(records), tag, callbackContext);
    }

    private void writeTag(JSONArray data, CallbackContext callbackContext) throws JSONException {
        if (getIntent() == null) {  // TODO remove this and handle LostTag
            callbackContext.error("Failed to write tag, received null intent");
        }

        Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NdefRecord[] records = Util.jsonToNdefRecords(data.getString(0));
        writeNdefMessage(new NdefMessage(records), tag, callbackContext);
    }

    private void writeNdefMessage(final NdefMessage message, final Tag tag, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                Ndef ndef = Ndef.get(tag);
                if (ndef != null) {
                    ndef.connect();

                    if (ndef.isWritable()) {
                        int size = message.toByteArray().length;
                        if (ndef.getMaxSize() < size) {
                            callbackContext.error("Tag capacity is " + ndef.getMaxSize() +
                                    " bytes, message is " + size + " bytes.");
                        } else {
                            ndef.writeNdefMessage(message);
                            callbackContext.success();
                        }
                    } else {
                        callbackContext.error("Tag is read only");
                    }
                    ndef.close();
                } else {
                    NdefFormatable formatable = NdefFormatable.get(tag);
                    if (formatable != null) {
                        formatable.connect();
                        formatable.format(message);
                        callbackContext.success();
                        formatable.close();
                    } else {
                        callbackContext.error("Tag doesn't support NDEF");
                    }
                }
            } catch (FormatException e) {
                callbackContext.error(e.getMessage());
            } catch (TagLostException e) {
                callbackContext.error(e.getMessage());
            } catch (IOException e) {
                callbackContext.error(e.getMessage());
            }
        });
    }

    private void makeReadOnly(final CallbackContext callbackContext) {

        if (getIntent() == null) { // Lost Tag
            callbackContext.error("Failed to make tag read only, received null intent");
            return;
        }

        final Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag == null) {
            callbackContext.error("Failed to make tag read only, tag is null");
            return;
        }

        cordova.getThreadPool().execute(() -> {
            boolean success = false;
            String message = "Could not make tag read only";

            Ndef ndef = Ndef.get(tag);

            try {
                if (ndef != null) {

                    ndef.connect();

                    if (!ndef.isWritable()) {
                        message = "Tag is not writable";
                    } else if (ndef.canMakeReadOnly()) {
                        success = ndef.makeReadOnly();
                    } else {
                        message = "Tag can not be made read only";
                    }

                } else {
                    message = "Tag is not NDEF";
                }

            } catch (IOException e) {
                Log.e(TAG, "Failed to make tag read only", e);
                if (e.getMessage() != null) {
                    message = e.getMessage();
                } else {
                    message = e.toString();
                }
            }

            if (success) {
                callbackContext.success();
            } else {
                callbackContext.error(message);
            }
        });
    }

    private void shareTag(JSONArray data, CallbackContext callbackContext) throws JSONException {
        NdefRecord[] records = Util.jsonToNdefRecords(data.getString(0));
        this.p2pMessage = new NdefMessage(records);

        startNdefPush(callbackContext);
    }

    // setBeamPushUris
    // Every Uri you provide must have either scheme 'file' or scheme 'content'.
    // Note that this takes priority over setNdefPush
    //
    // See http://developer.android.com/reference/android/nfc/NfcAdapter.html#setBeamPushUris(android.net.Uri[],%20android.app.Activity)
    private void handover(JSONArray data, CallbackContext callbackContext) throws JSONException {

        Uri[] uri = new Uri[data.length()];

        for (int i = 0; i < data.length(); i++) {
            uri[i] = Uri.parse(data.getString(i));
        }

        startNdefBeam(callbackContext, uri);
    }

    private void stopHandover(CallbackContext callbackContext) {
        stopNdefBeam();
        handoverCallback = null;
        callbackContext.success();
    }

    private void showSettings(CallbackContext callbackContext) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.JELLY_BEAN) {
            Intent intent = new Intent(android.provider.Settings.ACTION_NFC_SETTINGS);
            getActivity().startActivity(intent);
        } else {
            Intent intent = new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS);
            getActivity().startActivity(intent);
        }
        callbackContext.success();
    }

    private void createPendingIntent() {
        Log.e(TAG, "createPendingIntent");
        if (pendingIntent == null) {
            Log.e(TAG, "createPendingIntent : 1");
            Activity activity = getActivity();
            Log.e(TAG, "createPendingIntent : 2");
            Intent intent = new Intent(activity, activity.getClass());
            Log.e(TAG, "createPendingIntent : 3");
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            Log.e(TAG, "createPendingIntent : 4");
            pendingIntent = PendingIntent.getActivity(activity, 0, intent, 0);
            Log.e(TAG, "createPendingIntent : 5");
        }else{
            Log.e(TAG, "createPendingIntent : 6");
        }
    }

    private void addTechList(String[] list) {
        this.addTechFilter();
        this.addToTechList(list);
    }

    private void removeTechList(String[] list) {
        this.removeTechFilter();
        this.removeFromTechList(list);
    }

    private void addTechFilter() {
        intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED));
    }

    private void removeTechFilter() {
        Iterator<IntentFilter> iterator = intentFilters.iterator();
        while (iterator.hasNext()) {
            IntentFilter intentFilter = iterator.next();
            if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intentFilter.getAction(0))) {
                iterator.remove();
            }
        }
    }


    private void addTagFilter() {
        Log.e(TAG, "addTagFilter");
        intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED));
    }

    private void removeTagFilter() {
        Iterator<IntentFilter> iterator = intentFilters.iterator();
        while (iterator.hasNext()) {
            IntentFilter intentFilter = iterator.next();
            if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intentFilter.getAction(0))) {
                iterator.remove();
            }
        }
    }

    private void restartNfc() {
        Log.e(TAG, "restartNfc");
        stopNfc();
        startNfc();
    }

    private void startNfc() {
        Log.e(TAG, "startNfc");
        createPendingIntent(); // onResume can call startNfc before execute

        getActivity().runOnUiThread(() -> {
            Log.e(TAG, "startNfc : 1");
            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
            Log.e(TAG, "startNfc : 2");
            if (nfcAdapter != null && !getActivity().isFinishing()) {
                try {
                    Log.e(TAG, "startNfc : 3");
                    IntentFilter[] intentFilters = getIntentFilters();
                    Log.e(TAG, "startNfc : 4");
                    String[][] techLists = getTechLists();
                    Log.e(TAG, "startNfc : 5");
                    // don't start NFC unless some intent filters or tech lists have been added,
                    // because empty lists act as wildcards and receives ALL scan events
                    if (intentFilters.length > 0 || techLists.length > 0) {
                        Log.e(TAG, "startNfc : 6");
                        nfcAdapter.enableForegroundDispatch(getActivity(), getPendingIntent(), intentFilters, techLists);
                    }
                    Log.e(TAG, "startNfc : 7");
                    if (p2pMessage != null) {
                        Log.e(TAG, "startNfc : 8");
                        nfcAdapter.setNdefPushMessage(p2pMessage, getActivity());
                        Log.e(TAG, "startNfc : 9");
                    }
                } catch (IllegalStateException e) {
                    Log.e(TAG, "startNfc : 10");
                    // issue 110 - user exits app with home button while nfc is initializing
                    Log.w(TAG, "Illegal State Exception starting NFC. Assuming application is terminating.");
                }

            }else{
                Log.e(TAG, "startNfc : 11");
            }
        });
    }

    private void stopNfc() {
        Log.e(TAG, "stopNfc");
        getActivity().runOnUiThread(() -> {

            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
            Log.e(TAG, "stopNfc : 1");
            if (nfcAdapter != null) {
                try {
                    Log.e(TAG, "stopNfc : 2");
                    nfcAdapter.disableForegroundDispatch(getActivity());
                } catch (IllegalStateException e) {
                    Log.e(TAG, "stopNfc : 3");
                    // issue 125 - user exits app with back button while nfc
                    Log.w(TAG, "Illegal State Exception stopping NFC. Assuming application is terminating.");
                }
            }else{
                Log.e(TAG, "stopNfc : 4");
            }
        });
    }

    private void startNdefBeam(final CallbackContext callbackContext, final Uri[] uris) {
        getActivity().runOnUiThread(() -> {

            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

            if (nfcAdapter == null) {
                callbackContext.error(STATUS_NO_NFC);
            } else if (!nfcAdapter.isNdefPushEnabled()) {
                callbackContext.error(STATUS_NDEF_PUSH_DISABLED);
            } else {
                nfcAdapter.setOnNdefPushCompleteCallback(NfcPlugin.this, getActivity());
                try {
                    nfcAdapter.setBeamPushUris(uris, getActivity());

                    PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                    result.setKeepCallback(true);
                    handoverCallback = callbackContext;
                    callbackContext.sendPluginResult(result);

                } catch (IllegalArgumentException e) {
                    callbackContext.error(e.getMessage());
                }
            }
        });
    }

    private void startNdefPush(final CallbackContext callbackContext) {
        getActivity().runOnUiThread(() -> {

            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

            if (nfcAdapter == null) {
                callbackContext.error(STATUS_NO_NFC);
            } else if (!nfcAdapter.isNdefPushEnabled()) {
                callbackContext.error(STATUS_NDEF_PUSH_DISABLED);
            } else {
                nfcAdapter.setNdefPushMessage(p2pMessage, getActivity());
                nfcAdapter.setOnNdefPushCompleteCallback(NfcPlugin.this, getActivity());

                PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                result.setKeepCallback(true);
                shareTagCallback = callbackContext;
                callbackContext.sendPluginResult(result);
            }
        });
    }

    private void stopNdefPush() {
        getActivity().runOnUiThread(() -> {

            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

            if (nfcAdapter != null) {
                nfcAdapter.setNdefPushMessage(null, getActivity());
            }

        });
    }

    private void stopNdefBeam() {
        getActivity().runOnUiThread(() -> {

            NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

            if (nfcAdapter != null) {
                nfcAdapter.setBeamPushUris(null, getActivity());
            }

        });
    }

    private void addToTechList(String[] techs) {
        techLists.add(techs);
    }

    private void removeFromTechList(String[] techs) {
        Iterator<String[]> iterator = techLists.iterator();
        while (iterator.hasNext()) {
            String[] list = iterator.next();
            if (Arrays.equals(list, techs)) {
                iterator.remove();
            }
        }
    }

    private void removeIntentFilter(String mimeType) {
        Iterator<IntentFilter> iterator = intentFilters.iterator();
        while (iterator.hasNext()) {
            IntentFilter intentFilter = iterator.next();
            String mt = intentFilter.getDataType(0);
            if (mimeType.equals(mt)) {
                iterator.remove();
            }
        }
    }

    private IntentFilter createIntentFilter(String mimeType) throws MalformedMimeTypeException {
        IntentFilter intentFilter = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        intentFilter.addDataType(mimeType);
        return intentFilter;
    }

    private PendingIntent getPendingIntent() {
        return pendingIntent;
    }

    private IntentFilter[] getIntentFilters() {
        return intentFilters.toArray(new IntentFilter[intentFilters.size()]);
    }

    private String[][] getTechLists() {
        //noinspection ToArrayCallWithZeroLengthArrayArgument
        return techLists.toArray(new String[0][0]);
    }

    private void parseMessage() {
        cordova.getThreadPool().execute(() -> {
            Log.e(TAG, "parseMessage " + getIntent());
            Intent intent = getIntent();
            String action = intent.getAction();
            Log.e(TAG, "action " + action);
            if (action == null) {
                return;
            }

            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            Parcelable[] messages = intent.getParcelableArrayExtra((NfcAdapter.EXTRA_NDEF_MESSAGES));

            if (action.equals(NfcAdapter.ACTION_NDEF_DISCOVERED)) {
                Log.e(TAG, "parseMessage : 1");
                Ndef ndef = Ndef.get(tag);
                fireNdefEvent(NDEF_MIME, ndef, messages);

            } else if (action.equals(NfcAdapter.ACTION_TECH_DISCOVERED)) {
                Log.e(TAG, "parseMessage : 2");
                for (String tagTech : tag.getTechList()) {
                    Log.d(TAG, tagTech);
                    if (tagTech.equals(NdefFormatable.class.getName())) {
                        fireNdefFormatableEvent(tag);
                    } else if (tagTech.equals(Ndef.class.getName())) { //
                        Ndef ndef = Ndef.get(tag);
                        fireNdefEvent(NDEF, ndef, messages);
                    }
                }
            }

            if (action.equals(NfcAdapter.ACTION_TAG_DISCOVERED)) {
                Log.e(TAG, "parseMessage : 3");
                if(passportData != null) {
                    firePassportTagEvent(tag);
                }else{
                    fireTagEvent(tag);
                }
            }



            setIntent(new Intent());
        });
    }

    // Send the event data through a channel so the JavaScript side can fire the event
    private void sendEvent(String type, JSONObject tag) {
        Log.e(TAG, "sendEvent");
        try {
            Log.e(TAG, "sendEvent : 1");
            JSONObject event = new JSONObject();
            event.put("type", type);       // TAG_DEFAULT, NDEF, NDEF_MIME, NDEF_FORMATABLE
            event.put("tag", tag);         // JSON representing the NFC tag and NDEF messages
            Log.e(TAG, "sendEvent : 2");
            PluginResult result = new PluginResult(PluginResult.Status.OK, event);
            Log.e(TAG, "sendEvent : 3");
            result.setKeepCallback(true);
            Log.e(TAG, "sendEvent : 4");
            channelCallback.sendPluginResult(result);
            Log.e(TAG, "sendEvent : 5");
        } catch (JSONException e) {
            Log.e(TAG, "Error sending NFC event through the channel", e);
        }

    }

    private void fireNdefEvent(String type, Ndef ndef, Parcelable[] messages) {
        JSONObject json = buildNdefJSON(ndef, messages);
        sendEvent(type, json);
    }

    private void fireNdefFormatableEvent(Tag tag) {
        sendEvent(NDEF_FORMATABLE, Util.tagToJSON(tag));
    }

    private void fireTagEvent(Tag tag) {
        Log.e(TAG, "fireTagEvent");
        sendEvent(TAG_DEFAULT, Util.tagToJSON(tag));
    }

    // Custom 
    private void firePassportTagEvent(Tag tag) {

        String passportNumber = passportData.getPassportNumber();
        String expirationDate = UtilPassport.convertDate(passportData.getExpirationDate());
        String birthDate = UtilPassport.convertDate(passportData.getBirthDate());

        if (passportNumber != null && !passportNumber.isEmpty()
                && expirationDate != null && !expirationDate.isEmpty()
                && birthDate != null && !birthDate.isEmpty()) {

            Log.e(TAG, "firePassportTagEvent > passportNumber : " + passportNumber);
            Log.e(TAG, "firePassportTagEvent > expirationDate : " + expirationDate);
            Log.e(TAG, "firePassportTagEvent > birthDate : " + birthDate);

            BACKeySpec bacKey = new BACKey(passportNumber, birthDate, expirationDate);
            new ReadTask(IsoDep.get(tag), bacKey).execute();

            // JSONObject json = Util.tagToJSON(tag);


            // try{
            //     json.put("passportNumber", passportNumber);
            //     json.put("expirationDate", expirationDate);
            //     json.put("birthDate", birthDate);
            // } catch (JSONException e) {
            //     Log.e(TAG, "Failed to convert tag into json: " + tag.toString(), e);
            // }

            // sendEvent(TAG_DEFAULT, json);
        }else{
            JSONObject json = Util.tagToJSON(tag);
            
            try{
                json.put("errorMessage", "Require Passport Data");
            } catch (JSONException e) {
                Log.e(TAG, "Failed to convert tag into json: " + tag.toString(), e);
            }
            sendEvent(TAG_DEFAULT, json);
            return;
        }
    }


    private class ReadTask extends AsyncTask<Void, Void, Exception> {

        private IsoDep isoDep;
        private BACKeySpec bacKey;

        public ReadTask(IsoDep isoDep, BACKeySpec bacKey) {
            this.isoDep = isoDep;
            this.bacKey = bacKey;
        }

        private COMFile comFile;
        private SODFile sodFile;
        private DG1File dg1File;
        private DG2File dg2File;
        private String imageBase64;
        private Bitmap bitmap;

        private String trackLog = "track : 0, ";

        @Override
        protected Exception doInBackground(Void... params) {

            try {

                                CardService cardService = CardService.getInstance(isoDep);
                                cardService.open();
                
                                PassportService service = new PassportService(cardService);
                                service.open();
                                Log.e(TAG, "ReadTask > doInBackground : 1");
                                boolean paceSucceeded = false;
                                try {
                                Log.e(TAG, "ReadTask > doInBackground : 1.1.1");
                                    CardAccessFile cardAccessFile = new CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS));
                                Log.e(TAG, "ReadTask > doInBackground : 1.1.2");
                                    Collection<PACEInfo> paceInfos = cardAccessFile.getPACEInfos();
                
                                    if (paceInfos != null && paceInfos.size() > 0) {
                                        PACEInfo paceInfo = paceInfos.iterator().next();
                                        service.doPACE(bacKey, paceInfo.getObjectIdentifier(), PACEInfo.toParameterSpec(paceInfo.getParameterId()));
                                        paceSucceeded = true;
                                    } else {
                                        paceSucceeded = true;
                                    }
                                } catch (Exception e) {
                                    Log.e(TAG, "ReadTask > Exception : " + e.getMessage());
                                }
                                Log.e(TAG, "ReadTask > doInBackground : 1.1");
                                service.sendSelectApplet(paceSucceeded);
                                Log.e(TAG, "ReadTask > doInBackground : 1.2");
                                if (!paceSucceeded) {
                                    try {
                                        Log.e(TAG, "ReadTask > doInBackground : 1.3");
                                        service.getInputStream(PassportService.EF_COM).read();
                                        Log.e(TAG, "ReadTask > doInBackground : 1.4");
                                    } catch (Exception e) {
                                        Log.e(TAG, "ReadTask > doInBackground : 1.5");
                                        Log.e(TAG, "ReadTask > doInBackground : bacKey.getDocumentNumber() > " + bacKey.getDocumentNumber());
                                        Log.e(TAG, "ReadTask > doInBackground : bacKey.getDateOfBirth() > " + bacKey.getDateOfBirth());
                                        Log.e(TAG, "ReadTask > doInBackground : bacKey.getDateOfExpiry() > " + bacKey.getDateOfExpiry());
                                        service.doBAC(bacKey);
                
                                        Log.e(TAG, "ReadTask > doInBackground : 1.6");
                                    }
                                }
                
                                LDS lds = new LDS();
                
                                CardFileInputStream comIn = service.getInputStream(PassportService.EF_COM);
                                lds.add(PassportService.EF_COM, comIn, comIn.getLength());
                                comFile = lds.getCOMFile();
                                Log.e(TAG, "ReadTask > doInBackground : 2");
                                CardFileInputStream sodIn = service.getInputStream(PassportService.EF_SOD);
                                lds.add(PassportService.EF_SOD, sodIn, sodIn.getLength());
                                sodFile = lds.getSODFile();
                                Log.e(TAG, "ReadTask > doInBackground : 2.1");
                                CardFileInputStream dg1In = service.getInputStream(PassportService.EF_DG1);
                                lds.add(PassportService.EF_DG1, dg1In, dg1In.getLength());
                                dg1File = lds.getDG1File();
                                Log.e(TAG, "ReadTask > doInBackground : 2.2");
                                CardFileInputStream dg2In = service.getInputStream(PassportService.EF_DG2);
                                lds.add(PassportService.EF_DG2, dg2In, dg2In.getLength());
                                dg2File = lds.getDG2File();
                                Log.e(TAG, "ReadTask > doInBackground : 2.3");
                                List<FaceImageInfo> allFaceImageInfos = new ArrayList<>();
                                List<FaceInfo> faceInfos = dg2File.getFaceInfos();
                                for (FaceInfo faceInfo : faceInfos) {
                                    allFaceImageInfos.addAll(faceInfo.getFaceImageInfos());
                                }
                                Log.e(TAG, "ReadTask > doInBackground : 2.4");
                                if (!allFaceImageInfos.isEmpty()) {
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5");
                                    FaceImageInfo faceImageInfo = allFaceImageInfos.iterator().next();
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.1");
                                    int imageLength = faceImageInfo.getImageLength();
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.2");
                                    DataInputStream dataInputStream = new DataInputStream(faceImageInfo.getImageInputStream());
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.3");
                                    byte[] buffer = new byte[imageLength];
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.4");
                                    dataInputStream.readFully(buffer, 0, imageLength);
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.5");
                                    InputStream inputStream = new ByteArrayInputStream(buffer, 0, imageLength);
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.6");
                                    // bitmap = ImageUtil.decodeImage(
                                    //         getActivity(), faceImageInfo.getMimeType(), inputStream);
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.7");
                                    imageBase64 = Base64.encodeToString(buffer, Base64.DEFAULT);
                                    Log.e(TAG, "ReadTask > imageBase64 : " + imageBase64);
                                    Log.e(TAG, "ReadTask > doInBackground : 2.5.8");
                                }
                                Log.e(TAG, "ReadTask > doInBackground : 2.6");
                            } catch (Exception e) {
                                Log.e(TAG, "ReadTask > Exception : " + e.getMessage());
                                return e;
                            }
                            return null;
        }

        @Override
        protected void onPostExecute(Exception result) {
            // mainLayout.setVisibility(View.VISIBLE);
            // loadingLayout.setVisibility(View.GONE);
            String timeStamp = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
            if (result == null) {
                Log.e(TAG, "ReadTask > onPostExecute : result == null");

                // Intent intent;
                // if (getCallingActivity() != null) {
                //     intent = new Intent();
                // } else {
                //     intent = new Intent(MainActivity.this, ResultActivity.class);
                // }

                MRZInfo mrzInfo = dg1File.getMRZInfo();




                // intent.putExtra(ResultActivity.KEY_FIRST_NAME, mrzInfo.getSecondaryIdentifier().replace("<", ""));
                // intent.putExtra(ResultActivity.KEY_LAST_NAME, mrzInfo.getPrimaryIdentifier().replace("<", ""));
                // intent.putExtra(ResultActivity.KEY_GENDER, mrzInfo.getGender().toString());
                // intent.putExtra(ResultActivity.KEY_STATE, mrzInfo.getIssuingState());
                // intent.putExtra(ResultActivity.KEY_NATIONALITY, mrzInfo.getNationality());

                if (bitmap != null) {
                    // if (encodePhotoToBase64) {
                        // intent.putExtra(ResultActivity.KEY_PHOTO_BASE64, imageBase64);
                    // } else {
                    //     double ratio = 320.0 / bitmap.getHeight();
                    //     int targetHeight = (int) (bitmap.getHeight() * ratio);
                    //     int targetWidth = (int) (bitmap.getWidth() * ratio);

                    //     intent.putExtra(ResultActivity.KEY_PHOTO,
                    //         Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, false));
                    // }
                }

                // if (getCallingActivity() != null) {
                //     setResult(Activity.RESULT_OK, intent);
                //     finish();
                // } else {
                //     startActivity(intent);
                // }

                JSONObject json = new JSONObject();
                try {

                    json.put("id", timeStamp);
                    json.put("passportNumber", mrzInfo.getDocumentNumber());
                    json.put("expirationDate", mrzInfo.getDateOfExpiry());
                    json.put("birthDate", mrzInfo.getDateOfBirth());
                    json.put("firstName", mrzInfo.getSecondaryIdentifier().replace("<", ""));
                    json.put("lastName", mrzInfo.getPrimaryIdentifier().replace("<", ""));
                    json.put("gender", mrzInfo.getGender().toString());
                    json.put("state", mrzInfo.getIssuingState());
                    json.put("nationality", mrzInfo.getNationality());
            
                    if (imageBase64 != null) {
                        json.put("imageBase64", imageBase64);
                    }
                } catch (JSONException e) {
              
                    Log.e(TAG, "Failed to convert tag into json: " , e);
                }
                Log.e(TAG, "ReadTask > onPostExecute json : " + json);
                sendEvent(TAG_DEFAULT, json);

            } else {
                Log.e(TAG, "ReadTask > onPostExecute : result != null");
                Log.e(TAG, "ReadTask > onPostExecute : ERROR ::: " + UtilPassport.exceptionStack(result));
                // Snackbar.make(passportNumberView, exceptionStack(result), Snackbar.LENGTH_LONG).show();

                JSONObject json = new JSONObject();
                try {
                    json.put("id", timeStamp);
                    json.put("errorMessage", UtilPassport.exceptionStack(result));

                } catch (JSONException e) {
                    Log.e(TAG, "Failed to convert tag into json: " , e);
                }

                sendEvent(TAG_DEFAULT, json);
            }
        }

    }





    private JSONObject buildNdefJSON(Ndef ndef, Parcelable[] messages) {

        JSONObject json = Util.ndefToJSON(ndef);

        // ndef is null for peer-to-peer
        // ndef and messages are null for ndef format-able
        if (ndef == null && messages != null) {

            try {

                if (messages.length > 0) {
                    NdefMessage message = (NdefMessage) messages[0];
                    json.put("ndefMessage", Util.messageToJSON(message));
                    // guessing type, would prefer a more definitive way to determine type
                    json.put("type", "NDEF Push Protocol");
                }

                if (messages.length > 1) {
                    Log.wtf(TAG, "Expected one ndefMessage but found " + messages.length);
                }

            } catch (JSONException e) {
                // shouldn't happen
                Log.e(Util.TAG, "Failed to convert ndefMessage into json", e);
            }
        }
        return json;
    }

    private boolean recycledIntent() { // TODO this is a kludge, find real solution

        int flags = getIntent().getFlags();
        if ((flags & Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) == Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) {
            Log.i(TAG, "Launched from history, killing recycled intent");
            setIntent(new Intent());
            return true;
        }
        return false;
    }

    @Override
    public void onPause(boolean multitasking) {
        Log.d(TAG, "onPause " + getIntent());
        super.onPause(multitasking);
        if (multitasking) {
            // nfc can't run in background
            stopNfc();
        }
    }

    @Override
    public void onResume(boolean multitasking) {
        Log.d(TAG, "onResume " + getIntent());
        super.onResume(multitasking);
        startNfc();
    }

    @Override
    public void onNewIntent(Intent intent) {
        Log.e(TAG, "onNewIntent " + intent);
        super.onNewIntent(intent);
        setIntent(intent);
        savedIntent = intent;
        parseMessage();
    }

    private Activity getActivity() {
        return this.cordova.getActivity();
    }

    private Intent getIntent() {
        return getActivity().getIntent();
    }

    private void setIntent(Intent intent) {
        getActivity().setIntent(intent);
    }

    @Override
    public void onNdefPushComplete(NfcEvent event) {

        // handover (beam) take precedence over share tag (ndef push)
        if (handoverCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, "Beamed Message to Peer");
            result.setKeepCallback(true);
            handoverCallback.sendPluginResult(result);
        } else if (shareTagCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, "Shared Message with Peer");
            result.setKeepCallback(true);
            shareTagCallback.sendPluginResult(result);
        }

    }

    /**
     * Enable I/O operations to the tag from this TagTechnology object.
     * *
     *
     * @param tech            TagTechnology class name e.g. 'android.nfc.tech.IsoDep' or 'android.nfc.tech.NfcV'
     * @param timeout         tag timeout
     * @param callbackContext Cordova callback context
     */
    private void connect(final String tech, final int timeout, final CallbackContext callbackContext) {
        this.cordova.getThreadPool().execute(() -> {
            try {

                Tag tag = getIntent().getParcelableExtra(NfcAdapter.EXTRA_TAG);
                if (tag == null) {
                    tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                }

                if (tag == null) {
                    Log.e(TAG, "No Tag");
                    callbackContext.error("No Tag");
                    return;
                }

                // get technologies supported by this tag
                List<String> techList = Arrays.asList(tag.getTechList());
                if (techList.contains(tech)) {
                    // use reflection to call the static function Tech.get(tag)
                    tagTechnologyClass = Class.forName(tech);
                    Method method = tagTechnologyClass.getMethod("get", Tag.class);
                    tagTechnology = (TagTechnology) method.invoke(null, tag);
                }

                if (tagTechnology == null) {
                    callbackContext.error("Tag does not support " + tech);
                    return;
                }

                tagTechnology.connect();
                setTimeout(timeout);
                callbackContext.success();

            } catch (IOException ex) {
                Log.e(TAG, "Tag connection failed", ex);
                callbackContext.error("Tag connection failed");

                // Users should never get these reflection errors
            } catch (ClassNotFoundException e) {
                Log.e(TAG, e.getMessage(), e);
                callbackContext.error(e.getMessage());
            } catch (NoSuchMethodException e) {
                Log.e(TAG, e.getMessage(), e);
                callbackContext.error(e.getMessage());
            } catch (IllegalAccessException e) {
                Log.e(TAG, e.getMessage(), e);
                callbackContext.error(e.getMessage());
            } catch (InvocationTargetException e) {
                Log.e(TAG, e.getMessage(), e);
                callbackContext.error(e.getMessage());
            }
        });
    }

    // Call tagTech setTimeout with reflection or fail silently
    private void setTimeout(int timeout) {
        if (timeout < 0) {
            return;
        }
        try {
            Method setTimeout = tagTechnologyClass.getMethod("setTimeout", int.class);
            setTimeout.invoke(tagTechnology, timeout);
        } catch (NoSuchMethodException e) {
            // ignore
        } catch (IllegalAccessException e) {
            // ignore
        } catch (InvocationTargetException e) {
            // ignore
        }
    }

    /**
     * Disable I/O operations to the tag from this TagTechnology object, and release resources.
     *
     * @param callbackContext Cordova callback context
     */
    private void close(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {

                if (tagTechnology != null && tagTechnology.isConnected()) {
                    tagTechnology.close();
                    tagTechnology = null;
                    callbackContext.success();
                } else {
                    // connection already gone
                    callbackContext.success();
                }

            } catch (IOException ex) {
                Log.e(TAG, "Error closing nfc connection", ex);
                callbackContext.error("Error closing nfc connection " + ex.getLocalizedMessage());
            }
        });
    }

    /**
     * Send raw commands to the tag and receive the response.
     *
     * @param data            byte[] command to be passed to the tag
     * @param callbackContext Cordova callback context
     */
    private void transceive(final byte[] data, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                if (tagTechnology == null) {
                    Log.e(TAG, "No Tech");
                    callbackContext.error("No Tech");
                    return;
                }
                if (!tagTechnology.isConnected()) {
                    Log.e(TAG, "Not connected");
                    callbackContext.error("Not connected");
                    return;
                }

                // Use reflection so we can support many tag types
                Method transceiveMethod = tagTechnologyClass.getMethod("transceive", byte[].class);
                @SuppressWarnings("PrimitiveArrayArgumentToVarargsMethod")
                byte[] response = (byte[]) transceiveMethod.invoke(tagTechnology, data);

                callbackContext.success(response);

            } catch (NoSuchMethodException e) {
                String error = "TagTechnology " + tagTechnologyClass.getName() + " does not have a transceive function";
                Log.e(TAG, error, e);
                callbackContext.error(error);
            } catch (IllegalAccessException e) {
                Log.e(TAG, e.getMessage(), e);
                callbackContext.error(e.getMessage());
            } catch (InvocationTargetException e) {
                Log.e(TAG, e.getMessage(), e);
                Throwable cause = e.getCause();
                callbackContext.error(cause.getMessage());
            }
        });
    }

}
