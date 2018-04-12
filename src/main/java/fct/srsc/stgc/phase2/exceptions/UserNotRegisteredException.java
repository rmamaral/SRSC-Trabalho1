package fct.srsc.stgc.phase2.exceptions;

public class UserNotRegisteredException extends RuntimeException {

    public UserNotRegisteredException() {
        super();
    }

    public UserNotRegisteredException(String message) {
        super(message);
    }
}
