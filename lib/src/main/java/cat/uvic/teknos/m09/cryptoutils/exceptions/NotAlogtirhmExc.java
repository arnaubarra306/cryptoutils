package cat.uvic.teknos.m09.cryptoutils.exceptions;

public class NotAlogtirhmExc extends RuntimeException{

    public NotAlogtirhmExc() {
    }

    /**
     * @param errorCode Explains error
     */
    public NotAlogtirhmExc(String errorCode) {
        super(errorCode);
    }

    /**
     * @param errorCode Explains error
     * @param problem Cause of the problem
     */
    public NotAlogtirhmExc(String errorCode, Throwable problem) {
        super(errorCode, problem);
    }
    /** @param problem Cause of the problem
     */
    public NotAlogtirhmExc(Throwable problem) {
        super(problem);
    }

    /**
     * @param errorCode Explains error
     * @param problem Cause of the problem
     */
    public NotAlogtirhmExc(String errorCode, Throwable problem, boolean supressionOn, boolean StackTraceWritable) {
        super(errorCode, problem, supressionOn, StackTraceWritable);
    }
}
