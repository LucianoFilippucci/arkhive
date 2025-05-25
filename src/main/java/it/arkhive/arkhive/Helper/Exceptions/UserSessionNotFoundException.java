package it.arkhive.arkhive.Helper.Exceptions;

public class UserSessionNotFoundException extends RuntimeException {
    public UserSessionNotFoundException(String message) {
        super(message);
    }
}
