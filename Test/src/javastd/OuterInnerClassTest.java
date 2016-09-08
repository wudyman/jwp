package javastd;
class Outer{
	public void printValue(){
		System.out.println("this is outer");
	}
	class Inner{
		public void printValue(){
			System.out.println("this is Inner");
		}
	}
}

public class OuterInnerClassTest{	
	public static void main(String[] args){
		System.out.println("OuterInnerClassTest!");
		int x=1;
		if(x==0)
		System.out.println(x);
		Outer aOuter=new Outer();
		aOuter.printValue();
		//Outer.Inner aInner=new Outer.Inner();
		Outer.Inner aInner=new Outer().new Inner();
		aInner.printValue();

	}

}