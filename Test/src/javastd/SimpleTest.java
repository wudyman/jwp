package javastd;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Date;

import javax.swing.JOptionPane;
import javax.swing.Timer;

import javastd.package1.*;
class Person
{
	private String name;
	private int age;
	public Person(String name,int age)
	{
		this.name=name;
		this.age=age;
	}
	public void setName(String name)
	{
		this.name=name;
	}
	public String getName()
	{
		return name;
	}
}
class BlackPerson extends Person
{
	public BlackPerson(String name,int age)
	{
		super(name,age);
	}
}

class TimerPrinter implements ActionListener
{
	public void actionPerformed(ActionEvent event)
	{
		Date now=new Date();
		System.out.println("time is :"+now);
	}
}


public class SimpleTest
{
	public static void main(String[] args)
	{
		StringBuilder stringBuilder=new StringBuilder();
		stringBuilder.append("xxx");
		System.out.println(stringBuilder.toString());
		
		//Scanner in=new Scanner(System.in);
		//System.out.println("Please input your name:");
		//String name=in.nextLine();
		//System.out.println("your name is:"+name);
		
		PrintWriter aOut;
		try {
			aOut = new PrintWriter("myfile.txt");
			aOut.print("print test 2");
			aOut.flush();
			aOut.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		int y=new Integer(10);
		String[] aStringArray=new String[10];
		Person[] aPersonArray=new Person[10];
		aStringArray[1]="111";
		aPersonArray[1]=new Person("jack",20);
		System.out.println(aStringArray[1].toString());
		System.out.println(aPersonArray[1].toString());
		System.out.println(aPersonArray[1].hashCode());
		System.out.println(aPersonArray[1].getName());
		System.out.println(y);
		
		int[] aArray={0,1,2,3,4,5,6,7,8,9,10};
		
		for(int i:aArray)
			System.out.print(i);
		
		System.out.println("aArray:"+Arrays.toString(aArray));
		
		BlackPerson aBlackPerson=new BlackPerson("bolt",28);
		System.out.println(aBlackPerson.getName());
		
		Employee aStuff1=new Employee("andy",18000);
		Manager aManager1=new Manager("lucy",20000,10000);
		
		Employee stuff=null;
		stuff=aManager1;
		System.out.println(stuff.getName());
		System.out.println(stuff.getSalary());
		
		stuff=aStuff1;
		System.out.println(stuff.getName());
		System.out.println(stuff.getSalary());
		
		if(stuff instanceof Manager)
		{
		Manager manager=(Manager) stuff;
		System.out.println(manager.getName());
		System.out.println(manager.getAllSalary());
		}
		
		ActionListener listener=new TimerPrinter();
		Timer t=new Timer(10000,listener);
		t.start();
		JOptionPane.showMessageDialog(null, "quit program?");
	}
}