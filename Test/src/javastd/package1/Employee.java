package javastd.package1;

public class Employee
{
	private String name;
	private double salary;
	public Employee(String name,double salary)
	{
		this.name=name;
		this.salary=salary;
	}
	public void setName(String name)
	{
		this.name=name;
	}
	public String getName()
	{
		return this.name;
	}
	public void setSalary(double salary)
	{
		this.salary=salary;
	}
	public double getSalary()
	{
		return this.salary;
	}
}

