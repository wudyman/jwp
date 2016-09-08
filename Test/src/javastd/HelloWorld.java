package javastd;
public class HelloWorld{
	public static void main(String[] args){
		System.out.println("Hello World!");
		int i=0;
		for(i=0;i<=10;i++)
		{
			System.out.println("inner:"+i);
		}
		System.out.println("outer:"+i);
	}
}