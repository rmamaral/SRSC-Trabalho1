package fct.srsc.stgc.phase2.exceptions;

public class DuplicatedNonceException extends RuntimeException{

    public DuplicatedNonceException() {
        super();
    }

    public DuplicatedNonceException(String message) {
        super(message);
    }
}
