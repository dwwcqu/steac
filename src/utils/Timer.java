package utils;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * ���ڶԷ������ܲ���ʹ�õļ�ʱ����
 */
public class Timer {
	//��ʱ��ʾ����
    public enum FORMAT{
        SECOND, MILLI_SECOND, MICRO_SECOND, NANO_SECOND,
    }
    //Ĭ�����ļ�ʱ��
    private static final int DEFAULT_MAX_NUM_TIMER = 10;
    //ʵ��ʹ�õ��ļ�ʱ������
    private final int MAX_NUM_TIMER;
    
    //��¼ÿ����ʱ����ʱ��ʱ��
    private long[] timeRecorder;
    //�ж�ÿ����ʱ���Ƿ��Ѿ���ʼ����
    private boolean[] isTimerStart;
    //ÿ����ʱ���ı�ʾ��ʽ
    private FORMAT[] outFormat;
    
    
    //���ص�ǰʱ��
    public static String nowTime() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
        return df.format(new Date());
    }
    
    //����Ĭ�ϼ�ʱ��������С��Timer���췽��
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
    
    //�Զ����ʱ�������Ĺ��췽��
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
    
    //���õ�num����ʱ����ʱ���ʽ
    public void setFormat(int num, FORMAT format){
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        this.outFormat[num] = format;
    }
    
    //��ʼ��num����ʱ���Ĺ���
    public void start(int num) {
        //Ensure the timer now stops.
        assert(!isTimerStart[num]);
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        isTimerStart[num] = true;
        timeRecorder[num] = System.nanoTime();
    }
    
    //ֹͣ��num����ʱ���Ĺ�����������ʱ���ʽ�����ص�num����ʱ����������ʱ���������Ƶ�ʱ��
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

