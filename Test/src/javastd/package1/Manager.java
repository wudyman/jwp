package javastd.package1;
public class Manager extends Employee
{
	private double bonus;
	public Manager(String name,double salary,double bonus)
	{
		super(name,salary);
		this.bonus=bonus;
	}
	public void setBonus(double bonus)
	{
		this.bonus=bonus;
	}
	public double getBonus()
	{
		return this.bonus;
	}
	public double getAllSalary()
	{
		return bonus+super.getSalary();
	}
	
}