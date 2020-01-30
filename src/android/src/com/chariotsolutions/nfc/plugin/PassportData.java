package com.chariotsolutions.nfc.plugin;

public class PassportData {

    private String passportNumber;
    private String expirationDate;
    private String birthDate;

    public PassportData(String passportNumber, String expirationDate, String birthDate) {
        this.passportNumber = passportNumber;
        this.expirationDate = expirationDate;
        this.birthDate = birthDate;
    }

    public String getPassportNumber() {
        return passportNumber;
    }

    public void setPassportNumber(String passportNumber) {
        this.passportNumber = passportNumber;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getBirthDate() {
        return birthDate;
    }

    public void setBirthDate(String birthDate) {
        this.birthDate = birthDate;
    }

}