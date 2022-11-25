package cat.uvic.teknos.m09.cryptoutils.exceptions;

public class NotAlogtirhmExc extends RuntimeException{

    public NotAlogtirhmExc() {
    }


    public NotAlogtirhmExc(String errorCode) {
        super(errorCode);
    }


    public NotAlogtirhmExc(String errorCode, Throwable problem) {
        super(errorCode, problem);
    }

    public NotAlogtirhmExc(Throwable problem) {
        super(problem);
    }

    public NotAlogtirhmExc(String errorCode, Throwable problem, boolean supressionOn, boolean StackTraceWritable) {
        super(errorCode, problem, supressionOn, StackTraceWritable);
    }
}
