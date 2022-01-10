package utils;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 用于对方案性能测试使用的计时器类
 */
public class Timer {
	//计时表示类型
    public enum FORMAT{
        SECOND, MILLI_SECOND, MICRO_SECOND, NANO_SECOND,
    }
    //默认最大的计时器
    private static final int DEFAULT_MAX_NUM_TIMER = 10;
    //实际使用到的计时器数量
    private final int MAX_NUM_TIMER;
    
    //记录每个计时器计时的时间
    private long[] timeRecorder;
    //判断每个计时器是否已经开始工作
    private boolean[] isTimerStart;
    //每个计时器的表示格式
    private FORMAT[] outFormat;
    
    
    //返回当前时间
    public static String nowTime() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
        return df.format(new Date());
    }
    
    //采用默认计时器数量大小的Timer构造方法
    public Timer(){
        this.MAX_NUM_TIMER = DEFAULT_MAX_NUM_TIMER;
        this.timeRecorder = new long[MAX_NUM_TIMER];
        this.isTimerStart = new boolean[MAX_NUM_TIMER];
        this.outFormat = new FORMAT[MAX_NUM_TIMER];

        //set default format as millisecond
        for (int i=0; i<outFormat.length; i++){
            outFormat[i] = FORMAT.MILLI_SECOND;
        }
    }
    
    //自定义计时器数量的构造方法
    public Timer(int max_num_timer){
        this.MAX_NUM_TIMER = max_num_timer;
        this.timeRecorder = new long[MAX_NUM_TIMER];
        this.isTimerStart = new boolean[MAX_NUM_TIMER];
        this.outFormat = new FORMAT[MAX_NUM_TIMER];

        //set default format as millisecond
        for (int i=0; i<outFormat.length; i++){
            outFormat[i] = FORMAT.MILLI_SECOND;
        }
    }
    
    //设置第num个计时器的时间格式
    public void setFormat(int num, FORMAT format){
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        this.outFormat[num] = format;
    }
    
    //开始第num个计时器的工作
    public void start(int num) {
        //Ensure the timer now stops.
        assert(!isTimerStart[num]);
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        isTimerStart[num] = true;
        timeRecorder[num] = System.nanoTime();
    }
    
    //停止第num个计时器的工作，并根据时间格式，返回第num个计时器在整个计时过程中所计的时间
    public double stop(int num) {
        //Ensure the timer now starts.
        assert(isTimerStart[num]);
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        long result = System.nanoTime() - timeRecorder[num];
        isTimerStart[num] = false;

        switch(outFormat[num]){
            case SECOND:
                return (double) result / 1000000000L;
            case MILLI_SECOND:
                return (double) result / 1000000L;
            case MICRO_SECOND:
                return (double) result / 1000L;
            case NANO_SECOND:
                return (double) result;
            default:
                return (double) result / 1000000L;
        }

    }
}

