package cat.uvic.teknos.m09.cryptoutils.exceptions;

public class NotKeyExc extends RuntimeException{

        public NotKeyExc() {
        }

        public NotKeyExc(String message) {
            super(message);
        }

        public NotKeyExc(String message, Throwable cause) {
            super(message, cause);
        }

        public NotKeyExc(Throwable cause) {
            super(cause);
        }

        public NotKeyExc(String advice, Throwable problem, boolean suppressionOn, boolean StackTraceOn) {
            super(advice, problem, suppressionOn, StackTraceOn);
        }
}