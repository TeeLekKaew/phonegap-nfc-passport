package com.chariotsolutions.nfc.plugin;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.text.ParseException;

public class UtilPassport {

    public static String convertDate(String input) {
        if (input == null) {
            return null;
        }
        try {
            return new SimpleDateFormat("yyMMdd", Locale.US)
                    .format(new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(input));
        } catch (ParseException e) {
            // Log.w(MainActivity.class.getSimpleName(), e);
            return null;
        }
    }
}