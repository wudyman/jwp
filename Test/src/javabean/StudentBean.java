package javabean;

public class StudentBean{
	private String name=null;
	private int age=0;
	
	public void setName(String name){
		this.name=name;
	}
	public String getName(){
		return this.name;
	}
	public void setAge(int age){
		this.age=age;
	}
	public int getAge(){
		return this.age;
	}
	//public static void main(String[] args)
	//{
		//System.out.println("StudentBean");
	//}
}