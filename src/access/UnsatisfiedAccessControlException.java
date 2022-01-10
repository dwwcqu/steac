package access;

/**
 * 不满足访问控制策略时报错
 */

public class UnsatisfiedAccessControlException extends Exception {

    public UnsatisfiedAccessControlException(String message){
        super(message);
    }
}
