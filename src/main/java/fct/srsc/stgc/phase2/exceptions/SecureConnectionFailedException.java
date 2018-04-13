package fct.srsc.stgc.phase2.exceptions;

public class SecureConnectionFailedException extends RuntimeException{

    public SecureConnectionFailedException() {
        super();
    }

    public SecureConnectionFailedException(String message) {
        super(message);
    }
}
