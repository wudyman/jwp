package javastd;

import java.util.ArrayList;
class Pair<T>
{
	T t;
	public Pair(T t)
	{
		this.t=t;
	}
	public T get()
	{
		return t;
	}
}

class PairA<T extends A>
{
	T t;
	public PairA(T t)
	{
		this.t=t;
	}
	public T get()
	{
		return t;
	}
}
class A
{
	private String name1;
	public A()
	{
		name1="A";
	}
	public String getName()
	{
		return name1;
	}
}

class B extends A
{
	private String name2;
	public B()
	{
		super();
		name2="B";
	}
	public String getName()
	{
		return name2;
	}
}

class C
{
	private String name1;
	public C()
	{
		name1="C";
	}
	public String getName()
	{
		return name1;
	}
}

public class GeneralTest
{
	public static void main(String[] args)
	{
		System.out.println("main");
        Pair<A> aA=new Pair(new A());
        System.out.println(aA.get().getName());
        
        aA=new Pair(new B());
        System.out.println(aA.get().getName());
        
        Pair<C> aC=new Pair(new C());
        System.out.println(aC.get().getName());
        
        PairA<B> aAA=new PairA(new B());
        System.out.println(aAA.get().getName());
		
        Pair<?> aAll=new Pair(new A());
        System.out.println(((A) aAll.get()).getName());
        
        aAll=new Pair(new C());
        System.out.println(((C) aAll.get()).getName());
	}
}