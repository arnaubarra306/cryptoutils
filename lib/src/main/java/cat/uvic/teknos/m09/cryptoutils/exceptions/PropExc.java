package cat.uvic.teknos.m09.cryptoutils.exceptions;

public class PropExc extends RuntimeException{
       public PropExc(String errorCode) {
        super(errorCode);
    }

    public PropExc(String errorCode, Throwable problem) {
        super(errorCode, problem);
    }

    public PropExc(String message, Throwable problem, boolean supressionOn, boolean StackTraceWritable) {
        super(message, problem, supressionOn, StackTraceWritable);
    }

}